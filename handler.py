import base64
import json
import logging
import mimetypes
import os
import time
import urllib.parse
import urllib.request
import uuid

import boto3
import runpod
import websocket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

server_address = os.getenv('SERVER_ADDRESS', '127.0.0.1')
client_id = str(uuid.uuid4())
WRAPPED_KEY_PREFIX = 'v1:'


def decode_encryption_key():
    key_b64 = os.getenv('WAN22_FIELD_ENC_KEY_B64') or os.getenv('FIELD_ENC_KEY_B64')
    if not key_b64:
        raise Exception('FIELD_ENC_KEY_B64 is required for WAN22 secure transport')

    try:
        key = base64.b64decode(key_b64)
    except Exception as error:
        raise Exception(f'Invalid encryption key encoding: {error}')

    if len(key) != 32:
        raise Exception(f'Invalid encryption key length: expected 32 bytes, got {len(key)}')

    return key


def serialize_binding(binding):
    return json.dumps(binding, separators=(',', ':'), sort_keys=True).encode('utf-8')


def unwrap_dek(master_key, wrapped_key):
    if not isinstance(wrapped_key, str) or not wrapped_key.startswith(WRAPPED_KEY_PREFIX):
        raise Exception('Wrapped key prefix is invalid')

    try:
        payload = base64.b64decode(wrapped_key[len(WRAPPED_KEY_PREFIX):])
    except Exception as error:
        raise Exception(f'Wrapped key must be valid base64: {error}')

    if len(payload) <= 28:
        raise Exception('Wrapped key payload is too short')

    nonce = payload[:12]
    ciphertext = payload[12:-16]
    tag = payload[-16:]

    try:
        return AESGCM(master_key).decrypt(nonce, ciphertext + tag, b'engui:wrapped-key:v1')
    except Exception as error:
        raise Exception(f'Failed to unwrap DEK: {error}')


def decrypt_structured_envelope(envelope):
    key = decode_encryption_key()
    binding = envelope.get('binding')
    wrapped_key = envelope.get('wrapped_key')
    nonce_b64 = envelope.get('nonce')
    ciphertext_b64 = envelope.get('ciphertext')

    if not binding or not wrapped_key or not nonce_b64 or not ciphertext_b64:
        raise Exception('Structured secure payload is missing required fields')

    dek = unwrap_dek(key, wrapped_key)

    try:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception as error:
        raise Exception(f'Failed to decode structured secure payload: {error}')

    try:
        plaintext = AESGCM(dek).decrypt(nonce, ciphertext, serialize_binding(binding))
        return json.loads(plaintext.decode('utf-8'))
    except Exception as error:
        raise Exception(f'Failed to decrypt structured secure payload: {error}')


def decrypt_secure_input(job_input):
    secure = job_input.get('_secure')
    if not secure:
        return job_input

    if not secure.get('wrapped_key') or not secure.get('binding'):
        raise Exception('WAN22 secure contract requires structured _secure envelope')

    payload = decrypt_structured_envelope(secure)
    for key_name, value in payload.items():
        job_input[key_name] = value

    job_input['__secure_binding'] = secure.get('binding')
    job_input.pop('_secure', None)
    return job_input


def encrypt_result_to_transport(plaintext_bytes, job_id, model_id, attempt_id, output_path, kind='video', mime='video/mp4'):
    master_key = decode_encryption_key()
    dek = os.urandom(32)
    binding = {
        'job_id': job_id,
        'model_id': model_id,
        'attempt_id': attempt_id,
        'direction': 'endpoint_to_engui',
        'role': 'result',
        'kind': kind,
    }

    nonce = os.urandom(12)
    ciphertext_with_tag = AESGCM(dek).encrypt(nonce, plaintext_bytes, serialize_binding(binding))

    wrap_nonce = os.urandom(12)
    wrapped_key_payload = AESGCM(master_key).encrypt(wrap_nonce, dek, b'engui:wrapped-key:v1')
    wrapped_key = WRAPPED_KEY_PREFIX + base64.b64encode(wrap_nonce + wrapped_key_payload).decode('utf-8')

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as output_file:
        output_file.write(ciphertext_with_tag)

    return {
        'status': 'completed',
        'result_media': {
            'kind': kind,
            'mime': mime,
            'storage_path': output_path,
            'envelope': {
                'v': 1,
                'wrapped_key': wrapped_key,
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'binding': binding,
            },
        },
    }


def normalize_transport_failure(code, message):
    return {
        'status': 'failed',
        'error': {
            'code': code,
            'message': message,
        },
    }


def resolve_secure_storage_path(path_value):
    if not path_value or not isinstance(path_value, str):
        return path_value

    normalized = path_value.rstrip('/')
    candidates = [normalized]
    prefixes = [
        ('/runpod-volume/secure-jobs/', '/secure-jobs/'),
        ('/secure-jobs/', '/runpod-volume/secure-jobs/'),
        ('/runpod-volume/wan22-inputs/', '/wan22-inputs/'),
        ('/wan22-inputs/', '/runpod-volume/wan22-inputs/'),
    ]

    for source_prefix, target_prefix in prefixes:
        if normalized.startswith(source_prefix):
            candidates.append(normalized.replace(source_prefix, target_prefix, 1))
            break

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[-1]


def secure_storage_path_to_s3_key(path_value):
    if not path_value or not isinstance(path_value, str):
        raise Exception('Secure storage path is missing')

    normalized = path_value.lstrip('/')
    if normalized.startswith('runpod-volume/'):
        normalized = normalized[len('runpod-volume/'):]
    return normalized


def download_secure_media_input_from_s3(storage_path):
    endpoint_url = os.getenv('S3_ENDPOINT_URL')
    access_key_id = os.getenv('S3_ACCESS_KEY_ID')
    secret_access_key = os.getenv('S3_SECRET_ACCESS_KEY')
    bucket_name = os.getenv('S3_BUCKET_NAME')
    region_name = (os.getenv('S3_REGION') or 'us-east-1').lower()

    if not endpoint_url or not access_key_id or not secret_access_key or not bucket_name:
        raise Exception('Secure media input is not mounted locally and S3 configuration is missing')

    object_key = secure_storage_path_to_s3_key(storage_path)
    client = boto3.client(
        's3',
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=region_name,
    )

    try:
        response = client.get_object(Bucket=bucket_name, Key=object_key)
        return response['Body'].read()
    except Exception as error:
        raise Exception(f'Failed to download secure media input from S3 ({object_key}): {error}')


def get_transport_request(job_input):
    transport_request = job_input.get('transport_request') or {}
    output_dir = transport_request.get('output_dir')
    output_file_name = transport_request.get('output_file_name')

    if not isinstance(output_dir, str) or not output_dir.strip():
        raise Exception('WAN22 secure contract requires transport_request.output_dir')
    if not isinstance(output_file_name, str) or not output_file_name.strip():
        raise Exception('WAN22 secure contract requires transport_request.output_file_name')

    output_dir = output_dir.rstrip('/')
    if not output_dir.startswith(('/runpod-volume/', '/secure-jobs/')):
        raise Exception('transport_request.output_dir must be under /runpod-volume/ or /secure-jobs/')

    return {
        'output_dir': resolve_secure_storage_path(output_dir),
        'output_file_name': output_file_name.strip(),
    }


def decrypt_media_input_to_file(descriptor, output_file_path):
    key = decode_encryption_key()
    storage_path = descriptor.get('storage_path')
    envelope = descriptor.get('envelope') or {}
    binding = envelope.get('binding')
    wrapped_key = envelope.get('wrapped_key')
    nonce_b64 = envelope.get('nonce')

    if not storage_path or not binding or not wrapped_key or not nonce_b64:
        raise Exception('Secure media input descriptor is incomplete')

    resolved_storage_path = resolve_secure_storage_path(storage_path)

    if os.path.exists(resolved_storage_path):
        with open(resolved_storage_path, 'rb') as input_file:
            ciphertext_with_tag = input_file.read()
    else:
        logger.info(f'Secure media input not mounted locally, downloading from S3: {storage_path}')
        ciphertext_with_tag = download_secure_media_input_from_s3(storage_path)

    dek = unwrap_dek(key, wrapped_key)
    try:
        nonce = base64.b64decode(nonce_b64)
    except Exception as error:
        raise Exception(f'Failed to decode secure media nonce: {error}')

    try:
        plaintext = AESGCM(dek).decrypt(nonce, ciphertext_with_tag, serialize_binding(binding))
    except Exception as error:
        raise Exception(f'Failed to decrypt secure media input: {error}')

    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    with open(output_file_path, 'wb') as output_file:
        output_file.write(plaintext)

    return output_file_path


def get_secure_media_input(job_input, roles):
    media_inputs = job_input.get('media_inputs') or []
    for descriptor in media_inputs:
        if descriptor.get('role') in roles:
            return descriptor
    return None


def queue_prompt(prompt):
    url = f'http://{server_address}:8188/prompt'
    logger.info(f'Queueing prompt to: {url}')
    payload = {'prompt': prompt, 'client_id': client_id}
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data)
    return json.loads(urllib.request.urlopen(req).read())


def get_history(prompt_id):
    url = f'http://{server_address}:8188/history/{prompt_id}'
    logger.info(f'Getting history from: {url}')
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read())


def get_video_output_paths(ws, prompt):
    prompt_id = queue_prompt(prompt)['prompt_id']
    while True:
        out = ws.recv()
        if not isinstance(out, str):
            continue

        message = json.loads(out)
        if message.get('type') == 'executing':
            data = message.get('data') or {}
            if data.get('node') is None and data.get('prompt_id') == prompt_id:
                break

    history = get_history(prompt_id)[prompt_id]
    output_paths = []
    for node_output in history.get('outputs', {}).values():
        if 'gifs' in node_output:
            for video in node_output['gifs']:
                fullpath = video.get('fullpath')
                if fullpath:
                    output_paths.append(fullpath)

    return output_paths


def load_workflow(workflow_path):
    with open(workflow_path, 'r') as file:
        return json.load(file)


def detect_video_mime(path_value):
    mime, _ = mimetypes.guess_type(path_value)
    return mime or 'video/mp4'


def handler(job):
    job_input = job.get('input', {})
    logger.info(f'Received job input keys: {sorted(job_input.keys())}')

    try:
        job_input = decrypt_secure_input(job_input)
        transport_request = get_transport_request(job_input)
        secure_source_image = get_secure_media_input(job_input, ['source_image'])
        if not secure_source_image:
            raise Exception('WAN22 secure contract requires media_inputs with role source_image')

        task_id = f'task_{uuid.uuid4()}'
        input_ext = mimetypes.guess_extension(secure_source_image.get('mime') or 'image/png') or '.png'
        image_path = os.path.abspath(os.path.join(task_id, f'input_image{input_ext}'))
        decrypt_media_input_to_file(secure_source_image, image_path)

        lora_pairs = job_input.get('lora_pairs', [])
        lora_count = len(lora_pairs)
        if lora_count == 0:
            workflow_file = '/wan22_nolora.json'
        elif lora_count == 1:
            workflow_file = '/wan22_1lora.json'
        elif lora_count == 2:
            workflow_file = '/wan22_2lora.json'
        else:
            if lora_count > 3:
                logger.warning(f'LoRA pair count {lora_count} exceeds max 3. Truncating.')
                lora_pairs = lora_pairs[:3]
            workflow_file = '/wan22_3lora.json'
            lora_count = min(lora_count, 3)

        prompt = load_workflow(workflow_file)
        prompt['260']['inputs']['image'] = image_path
        prompt['846']['inputs']['value'] = job_input.get('length', 81)
        prompt['246']['inputs']['value'] = job_input['prompt']
        prompt['835']['inputs']['noise_seed'] = job_input['seed']
        prompt['830']['inputs']['cfg'] = job_input['cfg']
        prompt['849']['inputs']['value'] = job_input['width']
        prompt['848']['inputs']['value'] = job_input['height']

        steps = job_input.get('steps', 10)
        if '834' in prompt:
            prompt['834']['inputs']['steps'] = steps
            logger.info(f'Steps set to: {steps}')

        if lora_count > 0:
            lora_node_mapping = {
                1: {'high': ['282'], 'low': ['286']},
                2: {'high': ['282', '339'], 'low': ['286', '337']},
                3: {'high': ['282', '339', '340'], 'low': ['286', '337', '338']},
            }
            current_mapping = lora_node_mapping[lora_count]
            for index, lora_pair in enumerate(lora_pairs):
                lora_high = lora_pair.get('high')
                lora_low = lora_pair.get('low')
                lora_high_weight = lora_pair.get('high_weight', 1.0)
                lora_low_weight = lora_pair.get('low_weight', 1.0)

                if index < len(current_mapping['high']):
                    high_node_id = current_mapping['high'][index]
                    if high_node_id in prompt and lora_high:
                        prompt[high_node_id]['inputs']['lora_name'] = lora_high
                        prompt[high_node_id]['inputs']['strength_model'] = lora_high_weight

                if index < len(current_mapping['low']):
                    low_node_id = current_mapping['low'][index]
                    if low_node_id in prompt and lora_low:
                        prompt[low_node_id]['inputs']['lora_name'] = lora_low
                        prompt[low_node_id]['inputs']['strength_model'] = lora_low_weight

        ws_url = f'ws://{server_address}:8188/ws?clientId={client_id}'
        http_url = f'http://{server_address}:8188/'

        max_http_attempts = 180
        for http_attempt in range(max_http_attempts):
            try:
                response = urllib.request.urlopen(http_url, timeout=5)
                logger.info(f'HTTP connection succeeded (attempt {http_attempt + 1})')
                response.close()
                break
            except Exception as error:
                logger.warning(f'HTTP connection failed (attempt {http_attempt + 1}/{max_http_attempts}): {error}')
                if http_attempt == max_http_attempts - 1:
                    raise Exception('ComfyUI server is not reachable')
                time.sleep(1)

        ws = websocket.WebSocket()
        max_attempts = int(180 / 5)
        for attempt in range(max_attempts):
            try:
                ws.connect(ws_url)
                logger.info(f'WebSocket connection succeeded (attempt {attempt + 1})')
                break
            except Exception as error:
                logger.warning(f'WebSocket connection failed (attempt {attempt + 1}/{max_attempts}): {error}')
                if attempt == max_attempts - 1:
                    raise Exception('WebSocket connection timed out (3 minutes)')
                time.sleep(5)

        try:
            video_paths = get_video_output_paths(ws, prompt)
        finally:
            ws.close()

        if not video_paths:
            raise Exception('No generated video was found in ComfyUI history')

        result_path = video_paths[0]
        with open(result_path, 'rb') as file:
            result_bytes = file.read()

        secure_binding = job_input.get('__secure_binding', {}) or {}
        media_binding = (secure_source_image or {}).get('envelope', {}).get('binding', {}) or {}
        job_id = secure_binding.get('job_id') or media_binding.get('job_id') or job_input.get('job_id') or 'unknown-job'
        attempt_id = secure_binding.get('attempt_id') or media_binding.get('attempt_id') or job_input.get('attempt_id') or 'unknown-attempt'
        model_id = secure_binding.get('model_id') or media_binding.get('model_id') or job_input.get('model_id') or 'wan22'
        output_path = os.path.join(transport_request['output_dir'], transport_request['output_file_name'])
        mime = detect_video_mime(result_path)

        return {
            'transport_result': encrypt_result_to_transport(
                result_bytes,
                job_id,
                model_id,
                attempt_id,
                output_path,
                'video',
                mime,
            )
        }
    except Exception as error:
        logger.exception('WAN22 secure transport handler failed')
        return {
            'transport_result': normalize_transport_failure('WAN22_SECURE_TRANSPORT_FAILED', str(error))
        }


runpod.serverless.start({'handler': handler})

import base64
import json
import logging
import mimetypes
import os
import shutil
import time
import urllib.error
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
UNSAFE_OPTIMIZATION_CLASSES = {
    'EasyCache',
    'PathchSageAttentionKJ',
    'TorchCompileModel',
    'TorchCompileModelWanVideoV2',
}
MAX_LORA_PAIRS = int(os.getenv('WAN22_MAX_LORA_PAIRS', '0'))
HIGH_MODEL_LOADER_NODE_ID = '230'
LOW_MODEL_LOADER_NODE_ID = '235'
T2V_HIGH_MODEL_LOADER_NODE_ID = '37'
T2V_LOW_MODEL_LOADER_NODE_ID = '56'
T2V_HIGH_BASE_LORA_NODE_ID = '67'
T2V_LOW_BASE_LORA_NODE_ID = '68'
T2V_HIGH_SHIFT_NODE_ID = '54'
T2V_LOW_SHIFT_NODE_ID = '55'
HTTP_ERROR_BODY_LIMIT = int(os.getenv('WAN22_HTTP_ERROR_BODY_LIMIT', '4000'))
COMFYUI_INPUT_DIR = os.getenv('COMFYUI_INPUT_DIR', '/ComfyUI/input')
COMFYUI_OUTPUT_DIR = os.getenv('COMFYUI_OUTPUT_DIR', '/ComfyUI/output')
COMFYUI_TEMP_DIR = os.getenv('COMFYUI_TEMP_DIR', '/ComfyUI/temp')
COMFYUI_RUNTIME_DIRS = [
    COMFYUI_INPUT_DIR,
    COMFYUI_OUTPUT_DIR,
    COMFYUI_TEMP_DIR,
]
T2V_MODE_VALUES = {'t2v', 'text_to_video', 'wan22-t2v'}
CONTINUATION_FRAME_BATCH_NODE_ID = '901001'
CONTINUATION_FRAME_SAVE_NODE_ID = '901002'
CONTINUATION_FRAME_SOURCE_NODE_ID = '323'
CONTINUATION_FRAME_ROLE = 'continuation_frame'
CONTINUATION_FRAME_OFFSET_FROM_END = int(os.getenv('WAN22_CONTINUATION_FRAME_OFFSET_FROM_END', '3'))


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


def encrypt_result_to_transport(plaintext_bytes, job_id, model_id, attempt_id, output_path, kind='video', mime='video/mp4', role='result'):
    master_key = decode_encryption_key()
    dek = os.urandom(32)
    binding = {
        'job_id': job_id,
        'model_id': model_id,
        'attempt_id': attempt_id,
        'direction': 'endpoint_to_engui',
        'role': role,
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


def get_comfy_input_image_target(task_id, input_ext):
    image_file_name = f'{task_id}_input_image{input_ext}'
    image_path = os.path.join(COMFYUI_INPUT_DIR, image_file_name)
    return image_path, image_file_name


def get_secure_media_input(job_input, roles):
    media_inputs = job_input.get('media_inputs') or []
    for descriptor in media_inputs:
        if descriptor.get('role') in roles:
            return descriptor
    return None


def should_return_continuation_frame(job_input):
    return job_input.get('return_continuation_frame') is True


def get_requested_length(job_input):
    try:
        return max(1, int(job_input.get('length', 81)))
    except (TypeError, ValueError):
        return 81


def continuation_frame_batch_index(job_input):
    return max(0, get_requested_length(job_input) - CONTINUATION_FRAME_OFFSET_FROM_END)


def add_continuation_frame_output(prompt, job_input, task_id):
    if CONTINUATION_FRAME_SOURCE_NODE_ID not in prompt:
        raise Exception(f'Continuation frame source node {CONTINUATION_FRAME_SOURCE_NODE_ID} is missing from workflow')

    prompt[CONTINUATION_FRAME_BATCH_NODE_ID] = {
        'inputs': {
            'image': [CONTINUATION_FRAME_SOURCE_NODE_ID, 0],
            'batch_index': continuation_frame_batch_index(job_input),
            'length': 1,
        },
        'class_type': 'ImageFromBatch',
        '_meta': {
            'title': 'Engui Sequence Continuation Frame',
        },
    }
    prompt[CONTINUATION_FRAME_SAVE_NODE_ID] = {
        'inputs': {
            'filename_prefix': f'{task_id}/engui_sequence_continuation',
            'images': [CONTINUATION_FRAME_BATCH_NODE_ID, 0],
        },
        'class_type': 'SaveImage',
        '_meta': {
            'title': 'Save Engui Sequence Continuation PNG',
        },
    }
    logger.info(
        'Continuation frame output enabled at batch index %s',
        prompt[CONTINUATION_FRAME_BATCH_NODE_ID]['inputs']['batch_index'],
    )

    return prompt


def queue_prompt(prompt):
    url = f'http://{server_address}:8188/prompt'
    logger.info(f'Queueing prompt to: {url}')
    payload = {'prompt': prompt, 'client_id': client_id}
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data)
    try:
        return json.loads(urllib.request.urlopen(req).read())
    except urllib.error.HTTPError as error:
        body = ''
        try:
            body = error.read().decode('utf-8', errors='replace')
        except Exception as read_error:
            body = f'<failed to read response body: {read_error}>'

        if len(body) > HTTP_ERROR_BODY_LIMIT:
            body = f'{body[:HTTP_ERROR_BODY_LIMIT]}...<truncated>'

        raise Exception(f'ComfyUI /prompt returned HTTP {error.code} {error.reason}: {body}') from error


def get_history(prompt_id):
    url = f'http://{server_address}:8188/history/{prompt_id}'
    logger.info(f'Getting history from: {url}')
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read())


def resolve_comfy_output_path(item):
    fullpath = item.get('fullpath')
    if fullpath:
        return fullpath

    filename = item.get('filename')
    if not filename:
        return None

    subfolder = item.get('subfolder') or ''
    output_type = item.get('type') or 'output'
    base_dir = COMFYUI_TEMP_DIR if output_type == 'temp' else COMFYUI_OUTPUT_DIR
    return os.path.join(base_dir, subfolder, filename)


def get_comfy_output_paths(ws, prompt):
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
    video_paths = []
    image_paths_by_node = {}
    for node_id, node_output in history.get('outputs', {}).items():
        if 'gifs' in node_output:
            for video in node_output['gifs']:
                fullpath = resolve_comfy_output_path(video)
                if fullpath:
                    video_paths.append(fullpath)
        if 'images' in node_output:
            node_images = []
            for image in node_output['images']:
                fullpath = resolve_comfy_output_path(image)
                if fullpath:
                    node_images.append(fullpath)
            if node_images:
                image_paths_by_node.setdefault(node_id, []).extend(node_images)

    return {
        'video_paths': video_paths,
        'image_paths_by_node': image_paths_by_node,
    }

def get_video_output_paths(ws, prompt):
    return get_comfy_output_paths(ws, prompt)['video_paths']


def continuation_frame_output_path(comfy_outputs):
    paths = comfy_outputs.get('image_paths_by_node', {}).get(CONTINUATION_FRAME_SAVE_NODE_ID) or []
    if not paths:
        return None
    return paths[0]


def transport_artifact_output_path(transport_request, role):
    output_dir = transport_request['output_dir']
    output_file_name = transport_request['output_file_name']
    stem, extension = os.path.splitext(output_file_name)
    if not extension:
        extension = '.bin'
    return os.path.join(output_dir, f'{stem}__{role}{extension}')


def load_workflow(workflow_path):
    with open(workflow_path, 'r') as file:
        return json.load(file)


def unsafe_optimizations_enabled():
    return os.getenv('WAN22_ENABLE_UNSAFE_OPTIMIZATIONS') == '1'


def replace_node_references(value, node_id, replacement):
    if isinstance(value, list):
        if len(value) == 2 and value[0] == node_id and isinstance(value[1], int):
            return list(replacement)
        return [replace_node_references(item, node_id, replacement) for item in value]

    if isinstance(value, dict):
        return {
            key: replace_node_references(item, node_id, replacement)
            for key, item in value.items()
        }

    return value


def strip_unsafe_optimization_nodes(prompt):
    removed = []
    changed = True

    while changed:
        changed = False
        for node_id, node in list(prompt.items()):
            if node.get('class_type') not in UNSAFE_OPTIMIZATION_CLASSES:
                continue

            replacement = node.get('inputs', {}).get('model')
            if not (
                isinstance(replacement, list)
                and len(replacement) == 2
                and isinstance(replacement[0], str)
                and isinstance(replacement[1], int)
            ):
                raise Exception(f'Unsafe optimization node {node_id} has no model input to bypass')

            for target_id, target_node in prompt.items():
                if target_id == node_id:
                    continue
                target_node['inputs'] = replace_node_references(
                    target_node.get('inputs', {}),
                    node_id,
                    replacement,
                )

            removed.append(f"{node_id}:{node.get('class_type')}")
            del prompt[node_id]
            changed = True
            break

    if removed:
        logger.info(f'Removed unsafe optimization nodes: {", ".join(removed)}')

    return prompt


def replace_node_references_in_nodes(prompt, node_ids, node_id, replacement):
    for target_id in node_ids:
        target_node = prompt.get(target_id)
        if not target_node:
            continue
        target_node['inputs'] = replace_node_references(
            target_node.get('inputs', {}),
            node_id,
            replacement,
        )


def normalize_lora_pairs(job_input):
    raw_lora_pairs = job_input.get('lora_pairs', [])
    if raw_lora_pairs is None:
        return []
    if not isinstance(raw_lora_pairs, list):
        raise Exception('lora_pairs must be a list.')

    if MAX_LORA_PAIRS > 0 and len(raw_lora_pairs) > MAX_LORA_PAIRS:
        logger.warning(f'LoRA pair count {len(raw_lora_pairs)} exceeds max {MAX_LORA_PAIRS}. Truncating.')
        raw_lora_pairs = raw_lora_pairs[:MAX_LORA_PAIRS]

    normalized = []
    for index, pair in enumerate(raw_lora_pairs):
        if not isinstance(pair, dict):
            raise Exception(f'LoRA pair {index + 1} must be an object.')

        lora_high = str(pair.get('high') or '').strip()
        lora_low = str(pair.get('low') or '').strip()
        if not lora_high and not lora_low:
            continue

        try:
            high_weight = float(pair.get('high_weight', 1.0))
            low_weight = float(pair.get('low_weight', 1.0))
        except (TypeError, ValueError):
            raise Exception(f'LoRA pair {index + 1} weights must be numeric.')

        normalized.append({
            'high': lora_high or None,
            'low': lora_low or None,
            'high_weight': high_weight,
            'low_weight': low_weight,
        })

    return normalized


def apply_lora_chain_to_model_loader(prompt, lora_entries, model_loader_node_id, base_node_id, label):
    if not lora_entries:
        return prompt

    if model_loader_node_id not in prompt:
        raise Exception(f'Workflow is missing {label} model loader node {model_loader_node_id}.')

    existing_node_ids = set(prompt.keys())
    previous_model_binding = [model_loader_node_id, 0]

    for index, (lora_name, strength) in enumerate(lora_entries):
        node_id = str(base_node_id + index)
        if node_id in prompt:
            raise Exception(f'Dynamic LoRA node id collision: {node_id}')

        prompt[node_id] = {
            'inputs': {
                'lora_name': lora_name,
                'strength_model': strength,
                'model': previous_model_binding,
            },
            'class_type': 'LoraLoaderModelOnly',
            '_meta': {
                'title': f'Dynamic {label} LoRA {index + 1}',
            },
        }
        previous_model_binding = [node_id, 0]

    replace_node_references_in_nodes(
        prompt,
        existing_node_ids,
        model_loader_node_id,
        previous_model_binding,
    )
    return prompt


def apply_dynamic_lora_pairs_to_workflow(prompt, lora_pairs):
    high_loras = [
        (pair['high'], pair['high_weight'])
        for pair in lora_pairs
        if pair.get('high')
    ]
    low_loras = [
        (pair['low'], pair['low_weight'])
        for pair in lora_pairs
        if pair.get('low')
    ]

    apply_lora_chain_to_model_loader(
        prompt,
        high_loras,
        HIGH_MODEL_LOADER_NODE_ID,
        3500,
        'high',
    )
    apply_lora_chain_to_model_loader(
        prompt,
        low_loras,
        LOW_MODEL_LOADER_NODE_ID,
        3600,
        'low',
    )

    logger.info(f'Dynamic LoRA pairs configured: high={len(high_loras)}, low={len(low_loras)}')
    return prompt


def apply_dynamic_lora_pairs_to_t2v_workflow(prompt, lora_pairs):
    high_loras = [
        (pair['high'], pair['high_weight'])
        for pair in lora_pairs
        if pair.get('high')
    ]
    low_loras = [
        (pair['low'], pair['low_weight'])
        for pair in lora_pairs
        if pair.get('low')
    ]

    apply_lora_chain_to_model_loader(
        prompt,
        high_loras,
        T2V_HIGH_BASE_LORA_NODE_ID,
        3700,
        'T2V high',
    )
    apply_lora_chain_to_model_loader(
        prompt,
        low_loras,
        T2V_LOW_BASE_LORA_NODE_ID,
        3800,
        'T2V low',
    )

    logger.info(f'Dynamic T2V LoRA pairs configured: high={len(high_loras)}, low={len(low_loras)}')
    return prompt


def detect_video_mime(path_value):
    mime, _ = mimetypes.guess_type(path_value)
    return mime or 'video/mp4'


def is_t2v_request(job_input):
    mode = str(job_input.get('mode') or job_input.get('task') or '').strip().lower()
    return mode in T2V_MODE_VALUES


def get_negative_prompt(job_input):
    return (
        job_input.get('negativePrompt')
        or job_input.get('negative_prompt')
        or ''
    )


def get_optional_float(job_input, *keys):
    for key in keys:
        value = job_input.get(key)
        if value is None or value == '':
            continue
        return float(value)
    return None


def configure_t2v_workflow(prompt, job_input):
    steps = max(2, int(job_input.get('steps', 4)))
    split_step = max(1, min(steps - 1, round(steps * 0.5)))
    cfg = float(job_input.get('cfg', 1.0))
    seed = int(job_input['seed'])

    prompt['6']['inputs']['text'] = job_input['prompt']
    prompt['7']['inputs']['text'] = get_negative_prompt(job_input)
    prompt['57']['inputs']['noise_seed'] = seed
    prompt['57']['inputs']['steps'] = steps
    prompt['57']['inputs']['cfg'] = cfg
    prompt['57']['inputs']['end_at_step'] = split_step
    prompt['58']['inputs']['noise_seed'] = seed
    prompt['58']['inputs']['steps'] = steps
    prompt['58']['inputs']['cfg'] = cfg
    prompt['58']['inputs']['start_at_step'] = split_step
    prompt['58']['inputs']['end_at_step'] = steps
    prompt['59']['inputs']['width'] = int(job_input['width'])
    prompt['59']['inputs']['height'] = int(job_input['height'])
    prompt['59']['inputs']['length'] = int(job_input.get('length', 81))

    logger.info(f'T2V workflow configured: steps={steps}, split={split_step}, cfg={cfg}')
    return prompt


def cleanup_directory_contents(directory_path):
    if not directory_path:
        return

    target = os.path.abspath(directory_path)
    if target == os.path.abspath(os.sep):
        logger.warning(f'Skipping cleanup for unsafe directory: {directory_path}')
        return
    if not os.path.isdir(target):
        return

    for name in os.listdir(target):
        path = os.path.join(target, name)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
        except FileNotFoundError:
            pass
        except Exception as cleanup_error:
            logger.warning(f'Cleanup warning for {path}: {cleanup_error}')


def cleanup_runtime_artifacts(task_id):
    if task_id:
        task_path = os.path.abspath(task_id)
        if os.path.exists(task_path):
            try:
                if os.path.isdir(task_path):
                    shutil.rmtree(task_path, ignore_errors=True)
                else:
                    os.remove(task_path)
            except Exception as cleanup_error:
                logger.warning(f'Cleanup warning for {task_path}: {cleanup_error}')

    for directory_path in COMFYUI_RUNTIME_DIRS:
        cleanup_directory_contents(directory_path)


def handler(job):
    job_input = job.get('input', {})
    logger.info(f'Received job input keys: {sorted(job_input.keys())}')
    task_id = f'task_{uuid.uuid4()}'

    try:
        job_input = decrypt_secure_input(job_input)
        transport_request = get_transport_request(job_input)
        secure_source_image = None

        if is_t2v_request(job_input):
            prompt = load_workflow('/wan22_t2v.json')
            prompt = configure_t2v_workflow(prompt, job_input)
            lora_pairs = normalize_lora_pairs(job_input)
            if lora_pairs:
                prompt = apply_dynamic_lora_pairs_to_t2v_workflow(prompt, lora_pairs)
        else:
            secure_source_image = get_secure_media_input(job_input, ['source_image'])
            if not secure_source_image:
                raise Exception('WAN22 secure contract requires media_inputs with role source_image')

            input_ext = mimetypes.guess_extension(secure_source_image.get('mime') or 'image/png') or '.png'
            image_path, image_file_name = get_comfy_input_image_target(task_id, input_ext)
            decrypt_media_input_to_file(secure_source_image, image_path)

            lora_pairs = normalize_lora_pairs(job_input)
            workflow_file = '/wan22_nolora.json'

            prompt = load_workflow(workflow_file)
            if not unsafe_optimizations_enabled():
                prompt = strip_unsafe_optimization_nodes(prompt)

            prompt['260']['inputs']['image'] = image_file_name
            prompt['846']['inputs']['value'] = job_input.get('length', 81)
            prompt['246']['inputs']['value'] = job_input['prompt']
            prompt['835']['inputs']['noise_seed'] = job_input['seed']
            prompt['830']['inputs']['cfg'] = job_input['cfg']
            prompt['849']['inputs']['value'] = job_input['width']
            prompt['848']['inputs']['value'] = job_input['height']

            steps = int(job_input.get('steps', 4))
            if '834' in prompt:
                prompt['834']['inputs']['steps'] = steps
                logger.info(f'Steps set to: {steps}')
            if '829' in prompt:
                split_step = max(1, min(steps - 1, round(steps * 0.6))) if steps > 1 else 1
                prompt['829']['inputs']['step'] = split_step
                logger.info(f'Sigma split step set to: {split_step}')

            if lora_pairs:
                prompt = apply_dynamic_lora_pairs_to_workflow(prompt, lora_pairs)

            if should_return_continuation_frame(job_input):
                prompt = add_continuation_frame_output(prompt, job_input, task_id)

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
            comfy_outputs = get_comfy_output_paths(ws, prompt)
        finally:
            ws.close()

        video_paths = comfy_outputs['video_paths']
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

        transport_result = encrypt_result_to_transport(
            result_bytes,
            job_id,
            model_id,
            attempt_id,
            output_path,
            'video',
            mime,
        )

        if should_return_continuation_frame(job_input) and not is_t2v_request(job_input):
            continuation_path = continuation_frame_output_path(comfy_outputs)
            if not continuation_path or not os.path.exists(continuation_path):
                raise Exception('Continuation frame was requested but no generated PNG was found in ComfyUI history')

            with open(continuation_path, 'rb') as file:
                continuation_bytes = file.read()

            continuation_output_path = transport_artifact_output_path(transport_request, CONTINUATION_FRAME_ROLE)
            transport_result.setdefault('artifacts', {})[CONTINUATION_FRAME_ROLE] = encrypt_result_to_transport(
                continuation_bytes,
                job_id,
                model_id,
                attempt_id,
                continuation_output_path,
                'image',
                'image/png',
                CONTINUATION_FRAME_ROLE,
            )['result_media']

        return {
            'transport_result': transport_result,
        }
    except Exception as error:
        logger.exception('WAN22 secure transport handler failed')
        return {
            'transport_result': normalize_transport_failure('WAN22_SECURE_TRANSPORT_FAILED', str(error))
        }
    finally:
        cleanup_runtime_artifacts(task_id)


runpod.serverless.start({'handler': handler})

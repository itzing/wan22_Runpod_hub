# Wan22 for RunPod Serverless
[한국어 README 보기](README_kr.md)

This project is a template designed to easily deploy and use [Wan22](https://github.com/Comfy-Org/Wan_2.2_ComfyUI_Repackaged) in the RunPod Serverless environment.

[![Runpod](https://api.runpod.io/badge/wlsdml1114/wan22_Runpod_hub_alt)](https://console.runpod.io/hub/wlsdml1114/wan22_Runpod_hub_alt)

Wan22 is an advanced AI model that generates high-quality videos from images with natural motion and realistic animations.

## DaSiWa Branch Notes

The `dasiwa-i2v-lightspeed-v11` branch swaps the default WAN 2.2 I2V high/low diffusion models for the DaSiWa distilled v11 pair mirrored in the public `itzing/mpm-test` Hugging Face repository:

- `DasiwaWAN22I2V14BLightspeed_snatchkissHighV11.safetensors`
- `DasiwaWAN22I2V14BLightspeed_snatchkissLowV11.safetensors`

The original DaSiWa Hugging Face repository is gated. The DaSiWa files are mirrored in `itzing/mpm-test` and packaged once into the public Docker Hub model-provider image `itzing/wan22-dasiwa-models:v1`:

- digest: `sha256:041d51e250480067d3ffec164f516b1f0bcf4facfdfeb2f79120f4f3df667e94`

The endpoint Dockerfile copies the DaSiWa diffusion models from that provider image, so RunPod endpoint builds do not need `HF_TOKEN` and do not download the 29 GB checkpoint pair from Hugging Face during every deployment:

```bash
docker build -t wan22-dasiwa .
```

To rebuild the model-provider image itself:

```bash
docker build -f dasiwa-model-provider.Dockerfile -t itzing/wan22-dasiwa-models:v1 .
docker push itzing/wan22-dasiwa-models:v1
```

This branch uses a single clean workflow and builds `lora_pairs` dynamically at runtime. Each input pair can provide a `high` LoRA, a `low` LoRA, or both; the handler creates separate high/low `LoraLoaderModelOnly` chains before queueing the prompt.

Recommended DaSiWa starting point: `steps=4`, `cfg=1`, no LightX2V/CausVid speed LoRA stacked on top.

## Wan 2.2 T2V SmoothMix Branch Notes

The `wan22-t2v-lightning-v1` branch provides a separate text-to-video endpoint path. It keeps text-to-video isolated from the DaSiWa image-to-video endpoint so the RunPod endpoint can be deployed, tested, and rolled back independently.

The branch is prepared for the SmoothMix Wan 2.2 T2V high/low diffusion pair:

- `SmoothMix_T2V_High_v4.safetensors`
- `SmoothMix_T2V_Low_v4.safetensors`

Those files should be packaged once into the Docker Hub model-provider image `itzing/wan22-smoothmix-t2v-models:v1`:

- digest: pending until the SmoothMix model files are available and the provider image is pushed

The endpoint Dockerfile copies the diffusion models and optional LoRAs from that provider image so RunPod endpoint builds do not download large immutable model files during every deployment. The base workflow does not bake in the old LightX2V Lightning LoRA pair; dynamic LoRAs are chained at runtime from `lora_pairs`.

To rebuild the T2V model-provider image:

```bash
mkdir -p models/diffusion_models models/loras
# Place SmoothMix_T2V_High_v4.safetensors and SmoothMix_T2V_Low_v4.safetensors in models/diffusion_models.
docker build -f t2v-model-provider.Dockerfile -t itzing/wan22-smoothmix-t2v-models:v1 .
docker push itzing/wan22-smoothmix-t2v-models:v1
```

T2V requests should set `mode` to `t2v` and do not need `media_inputs` or a `source_image`. Recommended first-run values are `steps=6`, `cfg=1`, `sigma_shift=8`, `length=81`, `fps=32`, with dimensions such as `832x480`.

## ✨ Key Features

*   **Image-to-Video Generation**: Converts static images into dynamic videos with natural motion.
*   **High-Quality Output**: Produces high-resolution videos with realistic animations.
*   **Customizable Parameters**: Control video generation with various parameters like seed, width, height, and prompts.
*   **ComfyUI Integration**: Built on top of ComfyUI for flexible workflow management.

## 🚀 RunPod Serverless Template

This template includes all the necessary components to run Wan22 as a RunPod Serverless Worker.

*   **Dockerfile**: Configures the environment and installs all dependencies required for model execution.
*   **handler.py**: Implements the handler function that processes requests for RunPod Serverless.
*   **entrypoint.sh**: Performs initialization tasks when the worker starts.
*   **wan22.json**: Workflow configuration for image-to-video generation.

### Input

The `input` object must contain the following fields. `image_path` supports **URL, file path, or Base64 encoded string**.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `prompt` | `string` | **Yes** | `N/A` | Description text for the video to be generated. |
| `image_path` | `string` | **Yes** | `N/A` | Path, URL, or Base64 string of the input image to convert to video. |
| `seed` | `integer` | **Yes** | `N/A` | Random seed for video generation (affects the randomness of the output). |
| `width` | `integer` | **Yes** | `N/A` | Width of the output video in pixels. |
| `height` | `integer` | **Yes** | `N/A` | Height of the output video in pixels. |

**Request Example:**

```json
{
  "input": {
    "prompt": "A person walking in a natural way.",
    "image_path": "https://path/to/your/image.jpg",
    "seed": 12345,
    "width": 512,
    "height": 512
  }
}
```

### Output

#### Success

If the job is successful, it returns a JSON object with the generated video Base64 encoded.

| Parameter | Type | Description |
| --- | --- | --- |
| `video` | `string` | Base64 encoded video file data. |

**Success Response Example:**

```json
{
  "video": "data:video/mp4;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
}
```

#### Error

If the job fails, it returns a JSON object containing an error message.

| Parameter | Type | Description |
| --- | --- | --- |
| `error` | `string` | Description of the error that occurred. |

**Error Response Example:**

```json
{
  "error": "비디오를 찾을 수 없습니다."
}
```

## 🛠️ Usage and API Reference

1.  Create a Serverless Endpoint on RunPod based on this repository.
2.  Once the build is complete and the endpoint is active, submit jobs via HTTP POST requests according to the API Reference below.

### 📁 Using Network Volumes

Instead of directly transmitting Base64 encoded files, you can use RunPod's Network Volumes to handle large files. This is especially useful when dealing with large image files.

1.  **Create and Connect Network Volume**: Create a Network Volume (e.g., S3-based volume) from the RunPod dashboard and connect it to your Serverless Endpoint settings.
2.  **Upload Files**: Upload the image files you want to use to the created Network Volume.
3.  **Specify Paths**: When making an API request, specify the file paths within the Network Volume for `image_path`. For example, if the volume is mounted at `/my_volume` and you use `image.jpg`, the path would be `"/my_volume/image.jpg"`.

## 🔧 Workflow Configuration

This template includes a workflow configuration:

*   **wan22.json**: Image-to-video generation workflow

The workflow is based on ComfyUI and includes all necessary nodes for Wan22 processing, including:
- CLIP text encoding for prompts
- VAE loading and processing
- WanImageToVideo node for video generation
- Image concatenation and processing nodes

## 🙏 Original Project

This project is based on the following original repository. All rights to the model and core logic belong to the original authors.

*   **Wan22:** [https://github.com/Wan-Video/Wan2.2](https://github.com/Wan-Video/Wan2.2)
*   **ComfyUI:** [https://github.com/comfyanonymous/ComfyUI](https://github.com/comfyanonymous/ComfyUI)
*   **ComfyUI-WanVideoWrapper** [https://github.com/kijai/ComfyUI-WanVideoWrapper](https://github.com/kijai/ComfyUI-WanVideoWrapper)

## 📄 License

The original Wan22 project follows its respective license. This template also adheres to that license.

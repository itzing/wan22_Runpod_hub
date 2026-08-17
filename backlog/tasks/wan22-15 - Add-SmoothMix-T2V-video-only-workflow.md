# wan22-15 - Add SmoothMix T2V video-only workflow

Status: Done
Labels: [wan22, t2v, smoothmix, lora, secure-transport]

## Goal

Prepare the WAN22 T2V endpoint branch to generate video with the SmoothMix T2V high/low model pair:

- `SmoothMix_T2V_High_v4.safetensors`
- `SmoothMix_T2V_Low_v4.safetensors`

Audio generation is out of scope.

## Scope

- Keep the existing secure structured prompt input and encrypted result transport.
- Use a video-only T2V workflow.
- Preserve text-only T2V inputs: prompt, negative prompt, seed, width, height, length, steps, cfg, and fps.
- Add T2V sigma shift support so Engui can send `sigma_shift`.
- Keep dynamic high/low LoRA support, chaining every received LoRA pair in order.
- Do not launch a live RunPod generation job.

## Notes

The SmoothMix model files are not available in this repo yet. The provider image must later include both files under `/models/diffusion_models`.

## Result

- `wan22_t2v.json` now targets the SmoothMix high/low T2V model pair.
- The base T2V workflow no longer bakes in the old Lightning LoRA pair.
- Dynamic LoRA pairs are chained directly after the SmoothMix high/low model loaders.
- T2V accepts `sigma_shift` and `fps` overrides while preserving secure structured input and encrypted result transport.
- The endpoint Dockerfile expects the pending `itzing/wan22-smoothmix-t2v-models:v1` provider image and installs the NAG sampler dependency required by the SmoothMix workflow core.

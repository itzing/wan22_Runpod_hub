---
id: wan22-02
title: Add DaSiWa I2V branch with dynamic LoRA pairs
status: done
created: 2026-07-03T14:07:32Z
completed: 2026-07-03T14:15:00Z
labels: [wan22, runpod, dasiwa, lora, workflow]
---

## Summary

Create an isolated branch that swaps the WAN 2.2 I2V base high/low diffusion models to the DaSiWa distilled FP8 checkpoint pair and replaces static LoRA-pair workflow variants with runtime-generated high/low LoRA chains.

## Acceptance Criteria

- The branch obtains the DaSiWa v11 high/low checkpoint pair from a Docker Hub model-provider image, avoiding per-endpoint Hugging Face downloads during RunPod builds.
- The workflow references the DaSiWa high/low filenames instead of the original `wan2.2_i2v_*_fp8_scaled.safetensors` files.
- The handler builds dynamic `LoraLoaderModelOnly` chains for high and low model paths based on `lora_pairs`.
- Static 1/2/3-LoRA node-id mappings are no longer used.
- Placeholder LoRA names such as `lora2.safetensors` cannot leak into queued prompts.
- Validation covers JSON parsing, Python syntax, and placeholder/old-model string checks.

## Notes

- Do not launch live RunPod jobs without explicit approval.
- The original DaSiWa Hugging Face repository is gated; the model-provider image is built from the public `itzing/mpm-test` mirror so endpoint image builds do not need `HF_TOKEN`.
- Provider image: `itzing/wan22-dasiwa-models:v1`
- Provider digest: `sha256:041d51e250480067d3ffec164f516b1f0bcf4facfdfeb2f79120f4f3df667e94`

## Implementation Notes

- `dasiwa-model-provider.Dockerfile` builds the DaSiWa v11 high/low checkpoint provider image from public `itzing/mpm-test` files.
- `Dockerfile` now copies DaSiWa diffusion models from `itzing/wan22-dasiwa-models:v1` instead of downloading them during the endpoint build.
- Workflow JSONs were switched to DaSiWa model filenames and cleaned of baked speed-LoRA nodes.
- `handler.py` now uses one clean workflow and creates dynamic high/low LoRA chains from `lora_pairs`.
- Validation passed: Python compile, workflow JSON parsing, dynamic graph smoke test, and old placeholder/model string checks.

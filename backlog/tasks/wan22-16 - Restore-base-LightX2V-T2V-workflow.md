# WAN22-16 - Restore base LightX2V T2V workflow

## Status

In progress

## Context

SmoothMix T2V quality is not acceptable. Restore Wan 2.2 T2V to the clean base high/low FP8 diffusion models with baked LightX2V 4-step high/low LoRA, while preserving dynamic user LoRA pairs on top.

## Scope

- Package a new T2V model provider image with base high/low diffusion models, LightX2V high/low LoRA, UMT5 XXL FP8 text encoder, and WAN VAE.
- Update the endpoint Dockerfile to use the new provider image.
- Replace the SmoothMix/NAG workflow with the official core ComfyUI Wan 2.2 T2V graph shape plus baked LightX2V LoRA.
- Preserve dynamic T2V LoRA pair insertion.
- Keep sigma shift fixed in the workflow and remove request-level sigma/FPS overrides for T2V.
- Remove old local T2V provider image and SmoothMix leftovers after the new provider work starts.

## Validation

- Workflow JSON parses.
- Structural validation covers model filenames, baked LightX2V nodes, dynamic LoRA insertion anchors, and absence of NAG.
- `handler.py` compiles.
- Docker provider image contains the expected model files.

---
id: wan22-04
title: Store secure source images in ComfyUI input
status: done
created: 2026-07-04T09:22:00Z
completed: 2026-07-04T09:25:00Z
labels: [wan22, runpod, comfyui, secure-transport]
---

## Summary

Fix WAN22 secure source image handling so decrypted inputs are placed in ComfyUI's input directory and `LoadImage` receives a filename instead of an absolute path.

## Acceptance Criteria

- Secure source images are written under `/ComfyUI/input` by default.
- Workflow node `260` receives only the ComfyUI input filename.
- The ComfyUI input directory can be overridden for tests with `COMFYUI_INPUT_DIR`.
- Validation covers Python syntax, workflow JSON parsing, dynamic LoRA graph rewriting, and the LoadImage filename/path contract.

## Notes

- Do not launch live RunPod jobs without explicit approval.
- Rollback: revert the implementation commit and redeploy the previous endpoint image/branch.

## Implementation Notes

- Added `COMFYUI_INPUT_DIR`, defaulting to `/ComfyUI/input`.
- Added `get_comfy_input_image_target()` to produce the decrypted image path plus the filename expected by ComfyUI `LoadImage`.
- The handler now writes the secure source image into ComfyUI's input directory and assigns only the filename to node `260`.
- Validation passed: Python compile, all workflow JSON parse, LoadImage target smoke, and dynamic DR34ML4Y LoRA graph smoke with a non-absolute LoadImage filename.

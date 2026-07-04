---
id: wan22-05
title: Clean ComfyUI runtime dirs after WAN22 runs
status: done
created: 2026-07-04T09:34:00Z
completed: 2026-07-04T09:34:00Z
labels: [wan22, runpod, comfyui, cleanup]
---

## Summary

Clean WAN22 endpoint-local runtime artifacts after each handler invocation, matching the ZImage endpoint cleanup behavior for ComfyUI runtime directories.

## Acceptance Criteria

- Cleanup runs after successful and failed handler executions.
- The per-task local directory is removed when present.
- ComfyUI runtime directories are cleared after the run: input, output, and temp.
- Validation covers Python syntax, workflow JSON parsing, dynamic LoRA graph rewriting, LoadImage filename handling, and cleanup behavior.

## Notes

- Do not launch live RunPod jobs without explicit approval.
- Rollback: revert the implementation commit and redeploy the previous endpoint image/branch.

## Implementation Notes

- Added best-effort cleanup helpers in `handler.py`.
- Cleanup clears the contents of `COMFYUI_INPUT_DIR`, `/ComfyUI/output`, and `/ComfyUI/temp`.
- Cleanup runs from the handler `finally` block.

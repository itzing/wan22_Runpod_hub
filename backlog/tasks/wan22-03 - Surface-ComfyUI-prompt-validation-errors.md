---
id: wan22-03
title: Surface ComfyUI prompt validation errors
status: done
created: 2026-07-04T08:47:00Z
completed: 2026-07-04T08:51:00Z
labels: [wan22, runpod, comfyui, diagnostics]
---

## Summary

Expose the response body from ComfyUI `/prompt` HTTP failures so RunPod transport errors include the concrete workflow validation reason instead of only `HTTP Error 400: Bad Request`.

## Acceptance Criteria

- `handler.py` preserves the ComfyUI HTTP status and response body when `/prompt` rejects a workflow.
- Error messages remain bounded so large responses do not flood RunPod or Engui status payloads.
- Validation covers Python syntax, workflow JSON parsing, dynamic LoRA graph rewriting, and the new HTTPError body handling path.

## Notes

- Do not launch live RunPod jobs without explicit approval.
- Rollback: revert the diagnostic commit and redeploy the previous endpoint image/branch.

## Implementation Notes

- `handler.py` now catches `urllib.error.HTTPError` from ComfyUI `/prompt`, reads the response body, bounds it with `WAN22_HTTP_ERROR_BODY_LIMIT`, and includes it in the endpoint failure message.
- Validation passed: Python compile, all workflow JSON parse, dynamic LoRA graph rewrite for the DR34ML4Y high/low pair, and an HTTPError-body unit smoke.

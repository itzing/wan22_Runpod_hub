# WAN22-17 - Stage dynamic LoRAs in local runtime cache

## Status

Done

## Summary

Stage dynamic WAN22 LoRA pair files into a local ComfyUI LoRA cache before mutating workflows.

## Scope

- Resolve `lora_pairs[].high` and `lora_pairs[].low` from `/runpod-volume/loras` or `/ComfyUI/models/loras`.
- Copy first-use LoRAs to `/ComfyUI/models/loras/_runtime_cache/lora_<hash>.safetensors`.
- Pass only `_runtime_cache/lora_<hash>.safetensors` into ComfyUI workflow nodes.
- Log cache hit/miss, size, copy seconds, and throughput without original LoRA names.
- Preserve the existing WAN22 request contract.

## Validation

- `python3 -m py_compile handler.py`
- `git diff --check`

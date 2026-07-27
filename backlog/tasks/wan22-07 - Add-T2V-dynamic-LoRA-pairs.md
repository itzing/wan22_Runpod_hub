---
id: wan22-07
title: Add T2V dynamic LoRA pairs
status: Done
labels: [wan22, runpod, t2v, lora, comfyui]
---

## Problem

Wan 2.2 T2V has a baked LightX2V Lightning high/low LoRA pair in `wan22_t2v.json`, but the endpoint ignores user-supplied `lora_pairs`. Engui cannot safely expose a T2V LoRA picker until the endpoint can chain additional high/low LoRAs at runtime.

## Acceptance Criteria

- [x] T2V requests accept the existing `lora_pairs` array contract.
- [x] Additional T2V high/low LoRAs are chained after the baked Lightning nodes.
- [x] Existing I2V dynamic LoRA behavior remains unchanged.
- [x] Static validation covers Python syntax and T2V graph rewriting.

## Notes

The T2V workflow keeps the baked Lightning LoRA nodes (`67` high, `68` low) and appends user LoRAs after them before the high/low model sampling nodes. This preserves the speed baseline while allowing optional style or character LoRAs.

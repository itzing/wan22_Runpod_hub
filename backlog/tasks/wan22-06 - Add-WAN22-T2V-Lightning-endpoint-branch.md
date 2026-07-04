---
id: wan22-06
title: Add WAN22 T2V Lightning endpoint branch
status: pending
created: 2026-07-04T20:11:00Z
labels: [wan22, runpod, t2v, lightning, comfyui]
---

## Summary

Add a separate Wan 2.2 text-to-video endpoint path using LightX2V T2V A14B 4-step Lightning weights, while keeping the existing I2V endpoint behavior isolated.

## Acceptance Criteria

- A `wan22-t2v-lightning-v1` branch exists in this repository.
- A T2V ComfyUI workflow is added and does not require image input.
- The handler supports T2V requests without `media_inputs` or `source_image`.
- Secure structured prompt transport and encrypted result transport remain supported.
- Large immutable T2V model files are prepared through a provider image instead of being downloaded during every endpoint build.
- Validation covers Python syntax, workflow JSON parsing, T2V workflow source checks, and T2V prompt construction without media inputs.
- No live RunPod generation job is launched without explicit approval.

## Notes

- First model candidate: `lightx2v/Wan2.2-Lightning/Wan2.2-T2V-A14B-4steps-lora-rank64-Seko-V1.1`.
- Rollback: revert the endpoint branch commits or switch the RunPod endpoint back to the previous image/branch.

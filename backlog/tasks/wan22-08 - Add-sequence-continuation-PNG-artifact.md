---
id: wan22-08
title: Add sequence continuation PNG artifact
status: done
labels: [secure-transport, video-sequences, wan22, i2v]
---

## Goal

Return a lossless PNG continuation frame from WAN22 I2V endpoint runs only when Engui Video Sequence jobs explicitly request it.

## Acceptance Criteria

- [x] Existing secure `transport_result.result_media` remains the generated MP4.
- [x] The endpoint accepts a sequence-only request flag and does not emit the PNG artifact for ordinary Create I2V jobs.
- [x] When requested, the endpoint saves a PNG continuation frame from the generated image batch before MP4 compression.
- [x] The PNG is encrypted with the secure transport result path and returned as a `continuation_frame` artifact.
- [x] Existing T2V behavior is not changed.
- [x] Local validation covers Python syntax and workflow JSON parsing.

## Result

Implemented in commit `a27ac99`. The handler dynamically adds `ImageFromBatch` and `SaveImage` only when `return_continuation_frame` is true for WAN22 I2V jobs. The returned secure result keeps the MP4 in `result_media` and adds `artifacts.continuation_frame` for the encrypted PNG.

## Rollback

Revert the endpoint commit and redeploy the previous RunPod image/template.

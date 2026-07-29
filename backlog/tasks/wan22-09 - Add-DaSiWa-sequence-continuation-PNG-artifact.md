---
id: wan22-09
title: Add DaSiWa sequence continuation PNG artifact
status: done
labels: [secure-transport, video-sequences, wan22, dasiwa, i2v]
---

## Goal

Return a lossless PNG continuation frame from DaSiWa I2V endpoint runs only when Engui Video Sequence jobs explicitly request it.

## Acceptance Criteria

- [x] Existing secure `transport_result.result_media` remains the generated MP4.
- [x] The endpoint accepts `return_continuation_frame` and does not emit the PNG artifact unless requested.
- [x] When requested, the endpoint saves a PNG continuation frame from the generated image batch before MP4 compression.
- [x] The PNG is encrypted with the secure transport result path and returned as a `continuation_frame` artifact.
- [x] Local validation covers Python syntax, workflow JSON parsing, and structural workflow injection.

## Rollback

Revert the endpoint commit and redeploy the previous RunPod image/template.

## Result

Implemented on branch `dasiwa-i2v-lightspeed-v11`. The handler dynamically adds `ImageFromBatch` and `SaveImage` from DaSiWa VAEDecode node `323` only when `return_continuation_frame` is true, keeps the MP4 as `transport_result.result_media`, and returns the encrypted PNG under `transport_result.artifacts.continuation_frame`.

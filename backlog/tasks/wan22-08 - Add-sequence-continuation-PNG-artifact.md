---
id: wan22-08
title: Add sequence continuation PNG artifact
status: in_progress
labels: [secure-transport, video-sequences, wan22, i2v]
---

## Goal

Return a lossless PNG continuation frame from WAN22 I2V endpoint runs only when Engui Video Sequence jobs explicitly request it.

## Acceptance Criteria

- [ ] Existing secure `transport_result.result_media` remains the generated MP4.
- [ ] The endpoint accepts a sequence-only request flag and does not emit the PNG artifact for ordinary Create I2V jobs.
- [ ] When requested, the endpoint saves a PNG continuation frame from the generated image batch before MP4 compression.
- [ ] The PNG is encrypted with the secure transport result path and returned as a `continuation_frame` artifact.
- [ ] Existing T2V behavior is not changed.
- [ ] Local validation covers Python syntax and workflow JSON parsing.

## Rollback

Revert the endpoint commit and redeploy the previous RunPod image/template.

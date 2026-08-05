---
id: wan22-13
title: Add DaSiWa looped output
status: Done
labels: [wan22, dasiwa, i2v, workflow]
---

## Goal

Allow Engui to request loop-friendly DaSiWa I2V output by sending `looped: true`. The endpoint should use the source image as both the first and last frame conditioning input and omit the final decoded frame from MP4 assembly to avoid a duplicate hold frame at the loop boundary.

## Acceptance Criteria

- [x] The handler accepts optional `looped`.
- [x] When `looped` is true, the source image is connected as both `start_image` and `end_image`.
- [x] When `looped` is true, `VHS_VideoCombine` receives a decoded image batch without the final frame.
- [x] Non-looped requests keep the current workflow shape.
- [x] Structural validation covers looped and non-looped rewrites.

## Rollback

Revert the endpoint commit and redeploy the previous RunPod image/template.

## Result

The handler now treats `looped: true` as same-source first/last frame conditioning and inserts an `ImageFromBatch` node before MP4 assembly to omit the final decoded frame from the rendered output.

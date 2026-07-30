---
id: wan22-12
title: Add DaSiWa output FPS input
status: Done
labels: [wan22, dasiwa, i2v, workflow]
---

## Goal

Allow Engui to choose whether DaSiWa I2V assembles generated frames into MP4 output at 16fps or 32fps.

## Acceptance Criteria

- [x] The handler accepts `fps` or `output_fps`.
- [x] Only 16 and 32 are allowed; invalid values fall back to 16.
- [x] The selected value is applied to `VHS_VideoCombine.frame_rate`.
- [x] Generated frame count is not changed by the endpoint.
- [x] Structural tests verify both 16fps and 32fps rewrites.

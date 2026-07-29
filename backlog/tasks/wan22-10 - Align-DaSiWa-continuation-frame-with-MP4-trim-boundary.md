---
id: wan22-10
title: Align DaSiWa continuation frame with MP4 trim boundary
status: done
labels: [secure-transport, video-sequences, wan22, dasiwa, i2v]
---

## Goal

Make DaSiWa sequence continuation PNGs match the real MP4 boundary used by Engui final rendering.

## Acceptance Criteria

- [x] The endpoint selects a continuation frame aligned with DaSiWa's emitted MP4 frame count, not only the requested latent length.
- [x] The PNG remains a lossless `SaveImage` artifact from the decoded image batch.
- [x] Local validation covers Python syntax and structural continuation node injection.

## Rollback

Revert the endpoint commit and redeploy the previous RunPod image/template.

## Result

Changed the DaSiWa continuation offset default from 3 to 7 frames from requested length. For `length=81`, this selects decoded batch index 74 instead of 78, matching the observed 77-frame MP4 output after Engui trims the final 3 visible frames before concatenation.

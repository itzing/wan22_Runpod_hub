---
id: wan22-14
title: Perturb looped end frame
status: done
created: 2026-08-05
completed: 2026-08-05
---

## Summary

Reduce WAN 2.2 looped first/last-frame artifacts by avoiding bit-identical start and end conditioning images.

## Acceptance Criteria

- [x] Looped requests create a near-identical end image file from the source image.
- [x] The workflow loads and scales the end image through a separate node path.
- [x] `WanFirstLastFrameToVideo.end_image` points at the separate end image node.
- [x] Non-looped requests keep the current workflow shape.
- [x] Local validation covers Python syntax and structural looped/non-looped rewrites.

## Notes

The endpoint now makes a PNG copy of the source image for looped jobs using a 1px crop plus resize. This keeps the frame visually aligned while avoiding a bit-identical `start_image`/`end_image` pair, which can trigger boundary over-conditioning artifacts in WAN 2.2 FLF2V loops.

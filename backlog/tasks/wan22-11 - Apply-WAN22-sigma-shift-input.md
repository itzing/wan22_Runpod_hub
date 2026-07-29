# wan22-11 - Apply WAN22 sigma shift input

status: done
labels: [wan22, dasiwa, i2v, workflow]

## Context

Engui will send an optional `sigma_shift` value for Wan 2.2 I2V jobs. The endpoint should apply it to both high/low `ModelSamplingSD3` nodes while preserving the existing default when the field is absent.

## Acceptance Criteria

- [x] Endpoint accepts optional `sigma_shift`.
- [x] Values are clamped to the supported range `3` through `8`.
- [x] Both workflow shift nodes are patched before prompt submission.
- [x] Existing default remains `5` when no `sigma_shift` is provided.

## Result

The handler now applies `sigma_shift` to workflow nodes `362` and `363`, clamps input to `3..8`, and falls back to `5` when the field is missing or invalid.

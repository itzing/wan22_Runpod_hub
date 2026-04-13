---
id: WAN22-01
title: Migrate endpoint to secure-only file transport
status: In Progress
assignee: []
created_date: '2026-04-13 16:22'
updated_date: '2026-04-13 16:22'
labels:
  - wan22
  - secure-transport
  - runpod
  - storage
dependencies: []
priority: high
---

## Description

Convert the WAN22 RunPod endpoint from plaintext/base64 input-output handling to the secure encrypted file transport contract used by Engui secure jobs.

## Scope

- require encrypted media input from `media_inputs`
- decrypt the input image to a local temp file before workflow execution
- require `transport_request.output_dir` and `transport_request.output_file_name`
- encrypt the generated video into the requested output file
- return `transport_result` only
- derive result binding from secure binding or secure input binding, never from RunPod execution id as the primary source

## Acceptance Criteria

- legacy plaintext `image_path` input is not used
- endpoint fails clearly when secure input or transport request is missing
- secure input decrypt path works from the mounted secure file
- result is written as encrypted file to the Engui-requested output path
- returned `transport_result.envelope.binding` matches the Engui job and attempt ids
- `python3 -m py_compile handler.py` passes

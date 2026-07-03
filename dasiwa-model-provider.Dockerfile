FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget

RUN mkdir -p /models/diffusion_models && \
    wget --progress=dot:giga \
      "https://huggingface.co/itzing/mpm-test/resolve/main/DasiwaWAN22I2V14BLightspeed_snatchkissHighV11.safetensors?download=true" \
      -O /models/diffusion_models/DasiwaWAN22I2V14BLightspeed_snatchkissHighV11.safetensors

RUN mkdir -p /models/diffusion_models && \
    wget --progress=dot:giga \
      "https://huggingface.co/itzing/mpm-test/resolve/main/DasiwaWAN22I2V14BLightspeed_snatchkissLowV11.safetensors?download=true" \
      -O /models/diffusion_models/DasiwaWAN22I2V14BLightspeed_snatchkissLowV11.safetensors

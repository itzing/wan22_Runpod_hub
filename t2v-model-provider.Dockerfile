FROM alpine:3.20

RUN mkdir -p /models/diffusion_models /models/loras

COPY models/diffusion_models/SmoothMix_T2V_High_v4.safetensors /models/diffusion_models/SmoothMix_T2V_High_v4.safetensors
COPY models/diffusion_models/SmoothMix_T2V_Low_v4.safetensors /models/diffusion_models/SmoothMix_T2V_Low_v4.safetensors
COPY models/loras/ /models/loras/

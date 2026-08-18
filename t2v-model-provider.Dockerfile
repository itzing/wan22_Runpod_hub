FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget

RUN mkdir -p /models/diffusion_models /models/loras /models/text_encoders /models/vae

RUN wget --progress=dot:giga \
      "https://huggingface.co/Comfy-Org/Wan_2.2_ComfyUI_Repackaged/resolve/main/split_files/diffusion_models/wan2.2_t2v_high_noise_14B_fp8_scaled.safetensors?download=true" \
      -O /models/diffusion_models/wan2.2_t2v_high_noise_14B_fp8_scaled.safetensors

RUN wget --progress=dot:giga \
      "https://huggingface.co/Comfy-Org/Wan_2.2_ComfyUI_Repackaged/resolve/main/split_files/diffusion_models/wan2.2_t2v_low_noise_14B_fp8_scaled.safetensors?download=true" \
      -O /models/diffusion_models/wan2.2_t2v_low_noise_14B_fp8_scaled.safetensors

RUN wget --progress=dot:giga \
      "https://huggingface.co/lightx2v/Wan2.2-Lightning/resolve/main/Wan2.2-T2V-A14B-4steps-lora-rank64-Seko-V1.1/high_noise_model.safetensors?download=true" \
      -O /models/loras/Wan2.2-T2V-A14B-4steps-lora-rank64-Seko-V1.1-High.safetensors

RUN wget --progress=dot:giga \
      "https://huggingface.co/lightx2v/Wan2.2-Lightning/resolve/main/Wan2.2-T2V-A14B-4steps-lora-rank64-Seko-V1.1/low_noise_model.safetensors?download=true" \
      -O /models/loras/Wan2.2-T2V-A14B-4steps-lora-rank64-Seko-V1.1-Low.safetensors

RUN wget --progress=dot:giga \
      "https://huggingface.co/Comfy-Org/Wan_2.1_ComfyUI_repackaged/resolve/main/split_files/text_encoders/umt5_xxl_fp8_e4m3fn_scaled.safetensors?download=true" \
      -O /models/text_encoders/umt5_xxl_fp8_e4m3fn_scaled.safetensors

RUN wget --progress=dot:giga \
      "https://huggingface.co/Comfy-Org/Wan_2.1_ComfyUI_repackaged/resolve/main/split_files/vae/wan_2.1_vae.safetensors?download=true" \
      -O /models/vae/wan_2.1_vae.safetensors

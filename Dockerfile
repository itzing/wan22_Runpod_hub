# Use specific version of nvidia cuda image
FROM wlsdml1114/my-comfy-models:v1 AS model_provider
FROM wlsdml1114/multitalk-base:1.4 as runtime

RUN pip install -U "huggingface_hub[hf_transfer]"
RUN pip install runpod websocket-client

ARG HF_TOKEN
ENV HF_HUB_ENABLE_HF_TRANSFER=1

WORKDIR /

RUN git clone https://github.com/comfyanonymous/ComfyUI.git && \
    cd /ComfyUI && \
    pip install -r requirements.txt

RUN cd /ComfyUI/custom_nodes && \
    git clone https://github.com/Comfy-Org/ComfyUI-Manager.git && \
    cd ComfyUI-Manager && \
    pip install -r requirements.txt

RUN cd /ComfyUI/custom_nodes && \
    git clone https://github.com/city96/ComfyUI-GGUF && \
    cd ComfyUI-GGUF && \
    pip install -r requirements.txt

RUN cd /ComfyUI/custom_nodes && \
    git clone https://github.com/kijai/ComfyUI-KJNodes && \
    cd ComfyUI-KJNodes && \
    pip install -r requirements.txt

RUN cd /ComfyUI/custom_nodes && \
    git clone https://github.com/Kosinkadink/ComfyUI-VideoHelperSuite && \
    cd ComfyUI-VideoHelperSuite && \
    pip install -r requirements.txt
    
RUN cd /ComfyUI/custom_nodes && \
    git clone https://github.com/kael558/ComfyUI-GGUF-FantasyTalking && \
    cd ComfyUI-GGUF-FantasyTalking && \
    pip install -r requirements.txt
    
RUN cd /ComfyUI/custom_nodes && \
    git clone https://github.com/orssorbit/ComfyUI-wanBlockswap

RUN cd /ComfyUI/custom_nodes && \
    git clone https://github.com/kijai/ComfyUI-WanVideoWrapper && \
    cd ComfyUI-WanVideoWrapper && \
    pip install -r requirements.txt

COPY --from=model_provider /models/vae /ComfyUI/models/vae
COPY --from=model_provider /models/text_encoders /ComfyUI/models/text_encoders

RUN mkdir -p /ComfyUI/models/diffusion_models /tmp/dasiwa && \
    hf download darksidewalker/DaSiWa-WAN2.2-I2V \
      Distilled/FP8/v11/DasiwaWAN22I2V14BLightspeed_snatchkissHighV11-fp8-e4m3fn-mixed.safetensors \
      Distilled/FP8/v11/DasiwaWAN22I2V14BLightspeed_snatchkissLowV11-fp8-e4m3fn-mixed.safetensors \
      --local-dir /tmp/dasiwa \
      --token "$HF_TOKEN" && \
    cp /tmp/dasiwa/Distilled/FP8/v11/*.safetensors /ComfyUI/models/diffusion_models/ && \
    rm -rf /tmp/dasiwa

COPY . .
COPY extra_model_paths.yaml /ComfyUI/extra_model_paths.yaml
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]

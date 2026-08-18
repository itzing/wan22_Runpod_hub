import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / "wan22_t2v.json"

EXPECTED_MODELS = {
    "37": "wan2.2_t2v_high_noise_14B_fp8_scaled.safetensors",
    "56": "wan2.2_t2v_low_noise_14B_fp8_scaled.safetensors",
}

EXPECTED_BASE_LORAS = {
    "67": "Wan2.2-T2V-A14B-4steps-lora-rank64-Seko-V1.1-High.safetensors",
    "68": "Wan2.2-T2V-A14B-4steps-lora-rank64-Seko-V1.1-Low.safetensors",
}

FORBIDDEN_CLASSES = {
    "LoadImage",
    "VHS_LoadVideo",
    "WanImageToVideo",
    "WanFirstLastFrameToVideo",
    "MMAudioSampler",
    "MMAudioModelLoader",
    "MMAudioFeatureUtilsLoader",
    "RIFE VFI",
    "RIFEInterpolation",
    "KSamplerWithNAG (Advanced)",
}


def assert_condition(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    workflow = json.loads(WORKFLOW_PATH.read_text())

    for node_id, model_name in EXPECTED_MODELS.items():
        node = workflow.get(node_id)
        assert_condition(node is not None, f"Missing model loader node {node_id}")
        assert_condition(node["class_type"] == "UNETLoader", f"Node {node_id} must be a UNETLoader")
        assert_condition(
            node["inputs"]["unet_name"] == model_name,
            f"Node {node_id} should load {model_name}",
        )

    class_types = {node["class_type"] for node in workflow.values()}
    forbidden_present = sorted(class_types.intersection(FORBIDDEN_CLASSES))
    assert_condition(
        not forbidden_present,
        f"Video-only T2V workflow contains forbidden classes: {forbidden_present}",
    )

    for node_id, lora_name in EXPECTED_BASE_LORAS.items():
        node = workflow.get(node_id)
        assert_condition(node is not None, f"Missing base LightX2V LoRA node {node_id}")
        assert_condition(node["class_type"] == "LoraLoaderModelOnly", f"Node {node_id} must be a LoRA loader")
        assert_condition(node["inputs"]["lora_name"] == lora_name, f"Node {node_id} should load {lora_name}")

    assert_condition(workflow["54"]["inputs"]["model"] == ["67", 0], "High shift must read base high LightX2V LoRA")
    assert_condition(workflow["55"]["inputs"]["model"] == ["68", 0], "Low shift must read base low LightX2V LoRA")
    assert_condition(workflow["54"]["inputs"]["shift"] == 8.0, "High sigma shift default should be 8")
    assert_condition(workflow["55"]["inputs"]["shift"] == 8.0, "Low sigma shift default should be 8")
    assert_condition(workflow["58"]["class_type"] == "KSamplerAdvanced", "Low pass should use core sampler")
    assert_condition(workflow["57"]["inputs"]["steps"] == 4, "High pass should default to 4 steps")
    assert_condition(workflow["58"]["inputs"]["steps"] == 4, "Low pass should default to 4 steps")
    assert_condition(workflow["60"]["inputs"]["frame_rate"] == 16, "Default output FPS should be 16")

    print("LightX2V T2V workflow validation passed")


if __name__ == "__main__":
    main()

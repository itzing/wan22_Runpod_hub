import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / "wan22_t2v.json"

EXPECTED_MODELS = {
    "37": "SmoothMix_T2V_High_v4.safetensors",
    "56": "SmoothMix_T2V_Low_v4.safetensors",
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

    lora_names = [
        node.get("inputs", {}).get("lora_name", "")
        for node in workflow.values()
        if node["class_type"] == "LoraLoaderModelOnly"
    ]
    baked_lightning = [
        name
        for name in lora_names
        if "Wan2.2-T2V-A14B-4steps-lora-rank64-Seko-V1.1" in name
    ]
    assert_condition(
        not baked_lightning,
        "SmoothMix T2V workflow must not bake in the old Lightning LoRA pair",
    )

    assert_condition(workflow["54"]["inputs"]["model"] == ["37", 0], "High shift must read high model loader")
    assert_condition(workflow["55"]["inputs"]["model"] == ["56", 0], "Low shift must read low model loader")
    assert_condition(workflow["54"]["inputs"]["shift"] == 8.0, "High sigma shift default should be 8")
    assert_condition(workflow["55"]["inputs"]["shift"] == 8.0, "Low sigma shift default should be 8")
    assert_condition(workflow["58"]["class_type"] == "KSamplerWithNAG (Advanced)", "Low pass should use NAG sampler")
    assert_condition(workflow["60"]["inputs"]["frame_rate"] == 32, "Default output FPS should be 32")

    print("SmoothMix T2V workflow validation passed")


if __name__ == "__main__":
    main()

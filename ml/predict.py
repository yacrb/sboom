import hashlib
import json
from functools import lru_cache
from pathlib import Path

import numpy as np
import onnxruntime as ort

from ml.features import extract

HERE = Path(__file__).parent


@lru_cache(maxsize=1)
def benchmark():
    return json.loads((HERE / "benchmark.json").read_text())


@lru_cache(maxsize=1)
def session():
    graph = (HERE / "model.onnx").read_bytes()
    if hashlib.sha256(graph).hexdigest() != benchmark()["sha256"]:
        raise ValueError("model_integrity")
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    return ort.InferenceSession(graph, options, providers=["CPUExecutionProvider"])


def predict(name, version):
    features = extract(name, version)
    if features is None:
        return None
    model = session()
    x = np.array([[features[key] for key in benchmark()["features"]]], dtype=np.float32)
    # Compare the observed score with one changed input at a time.
    keys = benchmark()["features"]
    variants = np.repeat(x, len(keys) + 1, axis=0)
    for index, key in enumerate(keys):
        variants[index + 1, index] = benchmark()["medians"][key]
    label, values = model.run(None, {model.get_inputs()[0].name: variants})
    score = float(values[0, 1])
    deltas = sorted(
        ((key, score - float(v)) for key, v in zip(keys, values[1:, 1])), key=lambda item: -item[1]
    )
    return dict(
        review=bool(label[0]),
        score=score,
        features=features,
        signals=[dict(feature=k, difference=d) for k, d in deltas[:3] if d > 0.001],
    )

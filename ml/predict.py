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
    label, values = model.run(None, {model.get_inputs()[0].name: x})
    return dict(review=bool(label[0]), score=float(values[0, 1]), features=features)

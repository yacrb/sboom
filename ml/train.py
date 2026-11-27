"""Chronological validation, followed by one evaluation on the latest observations."""
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from skl2onnx import to_onnx

from ml.dataset import DATA
from ml.features import extract

HERE = Path(__file__).parent
FEATURES = list(extract("example", "1.0.0"))


def split(frame, fraction):
    day = frame.iloc[int(len(frame) * fraction)].observed
    return frame[frame.observed < day], frame[frame.observed >= day]


def scores(model, x):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(x)[:, 1]
    return model.decision_function(x)


def evaluate(y, predicted, score, probability):
    return dict(accuracy=accuracy_score(y, predicted), precision=precision_score(y, predicted, zero_division=0),
                recall=recall_score(y, predicted), f1=f1_score(y, predicted),
                roc_auc=roc_auc_score(y, score), average_precision=average_precision_score(y, score),
                brier=brier_score_loss(y, score) if probability else None,
                confusion=confusion_matrix(y, predicted, labels=[0, 1]).tolist())


def train(frame):
    frame = frame.drop_duplicates(["name", "version"]).sort_values(["observed", "name"])
    if frame.group.duplicated().any() or frame[FEATURES + ["label"]].isna().any().any():
        raise ValueError("Family overlap or missing classifier input")
    early, test = split(frame, .8)
    models = {
        "Prior baseline": DummyClassifier(strategy="prior"),
        "Logistic regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=42)),
        "K-nearest neighbors": make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=9)),
        "Decision tree": DecisionTreeClassifier(max_depth=5, min_samples_leaf=5, random_state=42),
        "Random forest": RandomForestClassifier(n_estimators=80, max_depth=7, min_samples_leaf=3, random_state=42),
        "Support vector machine": make_pipeline(StandardScaler(), SVC(C=1, kernel="rbf")),
    }
    validation = {}
    for name, classifier in models.items():
        folds = []
        for lower, upper in [(.4, .6), (.6, .8), (.8, 1.)]:
            past, future = split(early, lower)
            if upper < 1:
                future = future[future.observed < early.iloc[int(len(early)*upper)].observed]
            fitted = clone(classifier).fit(past[FEATURES], past.label)
            folds.append(average_precision_score(future.label, scores(fitted, future[FEATURES])))
        validation[name] = float(np.mean(folds))
    winner = max((n for n in models if n != "Prior baseline"), key=validation.get)
    results = {}
    for name, model in models.items():
        model.fit(early[FEATURES], early.label)
        score = scores(model, test[FEATURES])
        results[name] = dict(cv_ap=validation[name], **evaluate(test.label, model.predict(test[FEATURES]),
                             score, hasattr(model, "predict_proba")))
    model = models[winner]
    importance = permutation_importance(model, test[FEATURES], test.label, scoring="average_precision",
                                        n_repeats=5, random_state=42)
    # Export numerical operators. The application never unpickles model files.
    options = {id(model.steps[-1][1] if hasattr(model, "steps") else model): {"zipmap": False}}
    graph = to_onnx(model, early[FEATURES].iloc[:1].to_numpy(dtype=np.float32), options=options,
                    target_opset=17).SerializeToString()
    (HERE / "model.onnx").write_bytes(graph)
    report = dict(winner=winner, features=FEATURES, probability=hasattr(model, "predict_proba"),
                  sha256=hashlib.sha256(graph).hexdigest(), training=len(early), testing=len(test),
                  positive=int(frame.label.sum()), negative=int((frame.label == 0).sum()),
                  cutoff=test.observed.min(), results=results,
                  importance=dict(zip(FEATURES, importance.importances_mean)),
                  dataset_sha256=hashlib.sha256(frame.to_csv(index=False,float_format="%.10f").encode()).hexdigest())
    (HERE / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    return report, model, test


if __name__ == "__main__":
    report, _, _ = train(pd.read_csv(DATA / "releases.csv", keep_default_na=False))
    print(pd.DataFrame(report["results"]).drop(index="confusion").T.round(3))
    print(report["winner"], report["training"], report["testing"])

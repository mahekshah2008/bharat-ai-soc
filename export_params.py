import json
import joblib

pipeline = joblib.load("sms_classifier.joblib")
vec = pipeline.named_steps["tfidfvectorizer"]
clf = pipeline.named_steps["multinomialnb"]

params = {
    "classes": [int(c) for c in clf.classes_],
    "class_log_prior": clf.class_log_prior_.tolist(),
    "feature_log_prob": clf.feature_log_prob_.tolist(),
    "vocabulary": {str(k): int(v) for k, v in vec.vocabulary_.items()},
    "idf": vec.idf_.tolist(),
    "ngram_range": list(vec.ngram_range),
    "stop_words": list(vec.get_stop_words()) if vec.get_stop_words() else []
}

with open("model_params.json", "w", encoding="utf-8") as f:
    json.dump(params, f)

print("model_params.json exported with full TF-IDF parameters!")
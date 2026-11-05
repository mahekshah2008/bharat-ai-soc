import os
import re
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

print("[1/4] Downloading and loading standard SMS Spam Collection dataset...")
url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
df = pd.read_csv(url, sep='\t', header=None, names=['label', 'message'])

# Map 'ham' (safe) to 0, and 'spam' (threat/scam) to 1
df['label_num'] = df['label'].map({'ham': 0, 'spam': 1})
print(f"Total samples loaded: {len(df)} (Safe: {sum(df['label_num'] == 0)}, Scam: {sum(df['label_num'] == 1)})")

# Add a few India-specific scam samples (Electricity bill, Challan, KYC) to strengthen local edge detection
local_scams = [
    ("URGENT: Your electricity connection will be disconnected tonight. Update bill immediately: http://bit.ly/power-pay", 1),
    ("Dear customer, your SBI bank account is blocked. Update PAN KYC now at http://sbi-kyc-verify.in", 1),
    ("Immediate action required: Unpaid e-challan pending against your vehicle. Pay fine: http://echallan-vahan.in", 1),
    ("Congratulations! You won a cash prize of 50,000. Claim your reward: http://win-lottery.xyz", 1),
    ("Your SIM card will be deactivated in 24 hours. Submit Aadhaar verification: http://telecom-kyc.net", 1)
]
df_extra = pd.DataFrame(local_scams, columns=['message', 'label_num'])
df_all = pd.concat([df[['message', 'label_num']], df_extra], ignore_index=True)

# Split into 80% Training and 20% Evaluation
X_train, X_test, y_train, y_test = train_test_split(
    df_all['message'], df_all['label_num'], test_size=0.2, random_state=42, stratify=df_all['label_num']
)

print("[2/4] Training TF-IDF + Multinomial Naive Bayes pipeline...")
model = make_pipeline(
    TfidfVectorizer(ngram_range=(1, 2), stop_words='english', max_features=5000),
    MultinomialNB()
)
model.fit(X_train, y_train)

print("[3/4] Evaluating model performance...")
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"Evaluation Accuracy: {acc * 100:.2f}%\n")
print(classification_report(y_test, y_pred, target_names=['Safe (Ham)', 'Scam (Spam)']))

print("[4/4] Saving updated model to disk...")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "sms_classifier.joblib")
joblib.dump(model, model_path)
print(f"[SUCCESS] High-accuracy production model saved to: {model_path}")
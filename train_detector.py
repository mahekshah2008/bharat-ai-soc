import re
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

# 1. Training samples
data_samples = [
    # Safe / Ham messages (Label: 0)
    ("Hey, are you free for lunch tomorrow?", 0),
    ("Can you please send me the class notes from today?", 0),
    ("Mummy said dinner is ready, come down soon.", 0),
    ("Your package has been delivered to your front door.", 0),
    ("Let's meet at the library around 4 PM.", 0),
    ("Please find attached the assignment pdf for review.", 0),
    ("Happy birthday! Wishing you a wonderful year ahead.", 0),
    ("The professor postponed tomorrow morning's lecture.", 0),
    
    # Scam / Threat messages (Label: 1)
    ("URGENT: Your electricity connection will be cut off tonight. Pay immediately at http://bit.ly/power-pay", 1),
    ("Dear customer, your bank account is suspended. Update KYC now at http://secure-bank-login.com", 1),
    ("Congratulations! You won a cash prize of 50,000. Claim your reward: http://win-lottery.xyz", 1),
    ("Immediate action required: Unpaid traffic challan pending. Settle penalty here: http://echallan-verify.in", 1),
    ("Your SIM card will be deactivated in 24 hours. Submit verification details: http://telecom-kyc.net", 1),
    ("Alert: Unauthorized transaction detected on your debit card. Block it now: http://card-protect.cc", 1),
    ("Part-time job offer! Earn 5000 daily from home. Register instantly: http://easy-income-jobs.site", 1)
]

texts, labels = zip(*data_samples)

# 2. Train the pipeline
model = make_pipeline(TfidfVectorizer(), MultinomialNB())
model.fit(texts, labels)

# 3. Save the trained pipeline to disk
model_filename = "sms_classifier.joblib"
joblib.dump(model, model_filename)
print(f"[SUCCESS] Model trained and saved as '{model_filename}'")
# PhishingGuard

PhishGuard analyzes pasted email text with a TF-IDF and Logistic Regression model,
then reports rule-based explanations for suspicious patterns and URLs.

## Train the email model

1. Download the CSV from the
   [Kaggle Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset).
2. Place the CSV in the project (for example, `data\Phishing_Email.csv`).
3. Install dependencies and train the model:

   ```powershell
   python -m pip install -r requirements.txt
   python model.py --train data\Phishing_Email.csv
   ```

The trained classifier is saved as `phishing_model.joblib` and loaded on demand;
the app does not retrain it. The model artifact is local and should not be loaded
from untrusted sources.

## Run the app

```powershell
streamlit run app.py
```
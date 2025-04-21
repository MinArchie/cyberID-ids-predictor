"""Flask app for analyzing network log files and displaying intrusion detection results."""

import os
import pandas as pd
import joblib
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from sklearn.preprocessing import MinMaxScaler
import torch
from torch import nn

app = Flask(__name__)
app.secret_key = "your_secure_secret_key_here"
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

df = pd.DataFrame()
og_df = pd.read_csv("data/final_train.csv")
model_ml = joblib.load("model/svm_rbf_kdd_model.pkl")


class IntrusionNet(nn.Module):
    """Neural network for intrusion detection."""

    def __init__(self, input_dim):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.model(x)


@app.route('/')
def index():
    """Render the homepage."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle file upload and redirect to results page."""
    if 'logfile' not in request.files:
        return redirect(url_for('index'))

    file = request.files['logfile']
    model_choice = request.form.get('model_choice')

    if file.filename == '':
        return redirect(url_for('index'))

    if file and model_choice:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        session['uploaded_file'] = file.filename
        session['model_choice'] = model_choice
        return redirect(url_for('results'))

    return redirect(url_for('index'))


@app.route('/results')
def results():
    """Display prediction results for uploaded file."""
    filename = session.get('uploaded_file')
    model_choice = session.get('model_choice')

    if not filename or not model_choice:
        return redirect(url_for('index'))

    file_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        if model_choice == 'ml':
            return handle_ml_model(file_path, filename)
        if model_choice == 'dl':
            return handle_dl_model(file_path, filename)

        return redirect(url_for('index'))
    except ValueError as val_err:
        return f"Value Error: {val_err}", 500
    except FileNotFoundError as fnf_err:
        return f"File not found: {fnf_err}", 404
    except Exception as exc:
        return f"Unexpected error: {exc}", 500


def handle_ml_model(file_path, filename):
    """Handle prediction using ML model."""
    global df
    df = pd.DataFrame()
    user_df = pd.read_csv(file_path)

    features_to_use = og_df.drop(columns=['binary_attack', 'level'], errors='ignore').columns.tolist()
    user_df_filtered = user_df[features_to_use].copy()
    predictions = model_ml.predict(user_df_filtered)

    all_results = []
    for idx, row in user_df.iterrows():
        row_data = row.to_dict()
        label = 'abnormal' if predictions[idx] == 'abnormal' else 'normal'
        row_data['binary_attack'] = label

        if label == 'abnormal':
            row_data['explanation'] = explain_abnormal_log(row)

        all_results.append(row_data)

    df = pd.DataFrame(all_results)
    return render_template('results.html', filename=filename, results=all_results)


def handle_dl_model(file_path, filename):
    """Handle prediction using DL model."""
    global df
    df = pd.DataFrame()
    user_df = pd.read_csv(file_path)

    features_to_use = og_df.drop(columns=['binary_attack', 'level'], errors='ignore').columns.tolist()
    user_df_filtered = user_df[features_to_use].copy()

    preprocessor = joblib.load("model/dl_preprocessor.pkl")
    x_log_processed = preprocessor.transform(user_df_filtered)
    x_log_tensor = torch.tensor(
        x_log_processed.toarray() if hasattr(x_log_processed, "toarray") else x_log_processed,
        dtype=torch.float32
    )

    model = IntrusionNet(input_dim=x_log_tensor.shape[1])
    model.load_state_dict(torch.load("model/intrusion_net.pth"))
    model.eval()

    with torch.no_grad():
        predictions = model(x_log_tensor).squeeze()
        predicted_labels = (predictions >= 0.5).int().numpy()
        mapped_labels = ["abnormal" if p == 1 else "normal" for p in predicted_labels]

    user_df['binary_attack'] = mapped_labels

    all_results = []
    for idx, row in user_df.iterrows():
        row_data = row.to_dict()
        if row_data['binary_attack'] == 'abnormal':
            row_data['explanation'] = explain_abnormal_log(row)
        all_results.append(row_data)

    df = pd.DataFrame(all_results)
    return render_template('results.html', filename=filename, results=all_results)


@app.route('/api/dashboard-data')
def dashboard_data():
    """Return statistics for dashboard charts."""
    return jsonify({
        'attack_type_stats': attack_type(),
        'failed_login_stats': failed_counts(),
        'duration_stats': duration_stats(),
        'service_stats': service_distribution(),
        'protocol_stats': protocol_usage()
    })


# ============================
# Helper functions
# ============================

def failed_counts():
    """Calculate percentage of failed login attempts for each attack class."""
    counts = df.groupby('binary_attack')['num_failed_logins'].count()
    percent = (counts / counts.sum()) * 100
    return {"labels": percent.index.tolist(), "data": percent.values.tolist()}


def duration_stats():
    """Return normalized duration statistics by attack type."""
    scaler = MinMaxScaler()
    df_copy = df.copy()
    df_copy['duration_scaled'] = scaler.fit_transform(df[['duration']])
    duration = df_copy.groupby('binary_attack')['duration_scaled'].mean()
    return {"labels": duration.index.tolist(), "data": duration.values.tolist()}


def attack_type():
    """Return percentage of each attack type."""
    abnormal = df['binary_attack'].value_counts()
    abnormal_percent = ((abnormal / abnormal.sum()) * 100)
    return {"labels": abnormal_percent.index.tolist(), "data": abnormal_percent.values.tolist()}


def service_distribution():
    """Return top 10 services and their distribution by attack type."""
    top_services = og_df['service'].value_counts().nlargest(10).index.tolist()
    filtered_df = og_df[og_df['service'].isin(top_services)]
    grouped = filtered_df.groupby(['service', 'binary_attack']).size().unstack(fill_value=0)
    grouped = grouped.reindex(columns=['normal', 'abnormal'], fill_value=0)
    grouped = grouped.loc[grouped.sum(axis=1).sort_values(ascending=False).index]
    return {
        "labels": grouped.index.tolist(),
        "normal": grouped['normal'].tolist(),
        "abnormal": grouped['abnormal'].tolist()
    }


def protocol_usage():
    """Return protocol usage statistics split by attack type."""
    grouped = df.groupby(['protocol_type', 'binary_attack']).size().unstack(fill_value=0)
    return {
        'labels': grouped.index.tolist(),
        'datasets': [
            {
                'label': 'Normal',
                'data': grouped['normal'].tolist(),
                'backgroundColor': 'rgba(106, 153, 78, 0.7)'
            },
            {
                'label': 'Abnormal',
                'data': grouped['abnormal'].tolist(),
                'backgroundColor': 'rgba(114, 0, 38, 0.7)'
            }
        ]
    }


def numerical_feature_analysis(input_row, normal_df):
    """Analyze numerical features for anomalies."""
    explanation = {}
    for col in ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count', 'num_failed_logins']:
        mean = normal_df[col].mean()
        std = normal_df[col].std()
        val = input_row[col]
        z = (val - mean) / (std if std != 0 else 1)
        if abs(z) > 2:
            explanation[col] = f"Value {val} is {z:.2f} std deviations from normal (mean: {mean:.2f})"
    return explanation


def rare_categorical_analysis(input_row, normal_df, abnormal_df):
    """Analyze rare values in categorical features."""
    explanation = {}
    for col in ['protocol_type', 'service', 'flag']:
        val = input_row[col]
        normal_freq = normal_df[col].value_counts(normalize=True).get(val, 0)
        abnormal_freq = abnormal_df[col].value_counts(normalize=True).get(val, 0)

        if normal_freq < 0.01 and abnormal_freq > 0.05:
            explanation[col] = (
                f"Value '{val}' is rare in normal logs ({normal_freq*100:.2f}%) "
                f"but common in abnormal ({abnormal_freq*100:.2f}%)"
            )
    return explanation


def threshold_flags(input_row):
    """Flag specific fields crossing thresholds."""
    explanation = {}
    if input_row['num_failed_logins'] > 2:
        explanation['num_failed_logins'] = "Failed login count exceeds threshold"
    if input_row['duration'] > 5000:
        explanation['duration'] = "Duration unusually long"
    if 'rerror_rate' in input_row and input_row['rerror_rate'] > 0.5:
        explanation['rerror_rate'] = "High remote error rate"
    return explanation


def explain_abnormal_log(input_row):
    """Combine all abnormal explanation analyses for a log entry."""
    normal_df = og_df[og_df['binary_attack'] == 'normal']
    abnormal_df = og_df[og_df['binary_attack'] == 'abnormal']

    explanations = {}
    explanations.update(numerical_feature_analysis(input_row, normal_df))
    explanations.update(rare_categorical_analysis(input_row, normal_df, abnormal_df))
    explanations.update(threshold_flags(input_row))

    return explanations


if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
import pandas as pd
import joblib
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

df = pd.read_csv("final_train.csv")
model = joblib("model/scaler.pkl")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/dashboard-data')
def dashboard_data():
    return jsonify({
        'attack_type_stats': attack_type(),
        'failed_login_stats': failed_counts(),
        'duration_stats': duration_stats(),
        'service_stats': service_distribution()
    })

@app.route('/api/analyze-log', methods=['POST'])
def analyze_log():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    try:
        user_df = pd.read_csv(file)
    except Exception as e:
        return jsonify({'error': f'Invalid CSV file: {str(e)}'}), 400

    results = []
    for _, row in user_df.iterrows():
        row_data = row.to_dict()
        prediction = model.predict([row])[0]
        row_data['prediction'] = prediction

        if prediction == 'abnormal':
            row_data['explanation'] = explain_abnormal_log(row)

        results.append(row_data)

    return jsonify(results)


# ============================
# helper functions
# ============================
def failed_counts():
    failed_counts = df.groupby('binary_attack')['num_failed_logins'].count()
    failed_percent = (failed_counts / failed_counts.sum()) * 100
    return {
        "labels": failed_percent.index.tolist(),
        "data": failed_percent.values.tolist()
    }

def duration_stats():
    scaler = MinMaxScaler()
    df_no_outliers = df.copy()
    df_no_outliers['duration_scaled'] = scaler.fit_transform(df[['duration']])
    duration = df_no_outliers.groupby('binary_attack')['duration_scaled'].mean()
    return {
        "labels": duration.index.tolist(),
        "data": duration.values.tolist()
    }

def attack_type():
    abnormal = df['binary_attack'].value_counts()
    abnormal_percent = ((abnormal / abnormal.sum()) * 100)
    return {
        "labels": abnormal_percent.index.tolist(),
        "data": abnormal_percent.values.tolist()
    }

def service_distribution():
    service = df['service'].value_counts().nlargest(10)
    return {
        "labels": service.index.tolist(),
        "values": service.values.tolist()
    }

def src_dest_bytes():
    df_filtered = df[(df['src_bytes'] > 0) & (df['dst_bytes'] > 0)]
    data = {
        'label': 'Source vs Destination Bytes',
        'data': [{'x': row['src_bytes'], 'y': row['dst_bytes'], 'binary_attack': row['binary_attack']} for _, row in df_filtered.iterrows()],
        'backgroundColor': 'rgba(54, 162, 235, 0.6)',
        'borderColor': 'rgba(54, 162, 235, 1)',
        'borderWidth': 1
    }
    return data

def numerical_feature_analysis(input_row, normal_df):
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
    explanation = {}
    for col in ['protocol_type', 'service', 'flag']:
        val = input_row[col]
        normal_freq = normal_df[col].value_counts(normalize=True).get(val, 0)
        abnormal_freq = abnormal_df[col].value_counts(normalize=True).get(val, 0)

        if normal_freq < 0.01 and abnormal_freq > 0.05:
            explanation[col] = f"Value '{val}' is rare in normal logs ({normal_freq*100:.2f}%) but common in abnormal ({abnormal_freq*100:.2f}%)"
    return explanation

def threshold_flags(input_row):
    explanation = {}
    if input_row['num_failed_logins'] > 3:
        explanation['num_failed_logins'] = "Failed login count exceeds threshold"
    if input_row['duration'] > 5000:
        explanation['duration'] = "Duration unusually long"
    if 'rerror_rate' in input_row and input_row['rerror_rate'] > 0.5:
        explanation['rerror_rate'] = "High remote error rate"
    return explanation

def explain_abnormal_log(input_row):
    normal_df = df[df['binary_attack'] == 'normal']
    abnormal_df = df[df['binary_attack'] == 'abnormal']

    explanations = {}
    explanations.update(numerical_feature_analysis(input_row, normal_df))
    explanations.update(rare_categorical_analysis(input_row, normal_df, abnormal_df))
    explanations.update(threshold_flags(input_row))

    return explanations


if __name__ == '__main__':
    app.run(debug=True)
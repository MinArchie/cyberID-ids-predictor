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


if __name__ == '__main__':
    app.run(debug=True)
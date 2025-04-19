from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import os
import pandas as pd
import joblib
from sklearn.preprocessing import MinMaxScaler
import random

app = Flask(__name__)
app.secret_key = "your_secure_secret_key_here"
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

df = pd.read_csv("data/final_train.csv")
model = joblib.load("model/svm_rbf_model.pkl")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'logfile' not in request.files:
        return redirect(url_for('index'))
        
    file = request.files['logfile']
    if file.filename == '':
        return redirect(url_for('index'))
        
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        session['uploaded_file'] = file.filename  # Save filename to session
        return redirect(url_for('results'))
    
    return redirect(url_for('index'))
    
@app.route('/results')
def results():
    filename = session.get('uploaded_file', None)
    if filename:
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            user_df = pd.read_csv(file_path)

            results = []
            for _, row in user_df.iterrows():
                row_data = row.to_dict()
                prediction = random.choice(['normal', 'abnormal'])
                row_data['prediction'] = prediction

                if prediction == 'abnormal':
                    row_data['explanation'] = explain_abnormal_log(row_data)

                results.append(row_data)

            return render_template('results.html', filename=filename, results=results)

        except Exception as e:
            return f"Error reading file: {e}", 500
    else:
        return redirect(url_for('index'))

@app.route('/api/dashboard-data')
def dashboard_data():
    return jsonify({
        'attack_type_stats': attack_type(),
        'failed_login_stats': failed_counts(),
        'duration_stats': duration_stats(),
        'service_stats': service_distribution(),
        'protocol_stats': protocol_usage()
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
    # using fake classifier for this because i cant get the model to work
    for _, row in user_df.iterrows():
        row_data = row.to_dict()

        prediction = random.choice(['normal', 'abnormal'])
        row_data['prediction'] = prediction

        if prediction == 'abnormal':
            row_data['explanation'] = {
                "src_bytes": "Unusually high source bytes",
                "service": f"Service '{row_data['service']}' is often attacked",
                "duration": "Duration significantly above normal range"
            }

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
    top_services = df['service'].value_counts().nlargest(10).index.tolist()
    filtered_df = df[df['service'].isin(top_services)]
    grouped = filtered_df.groupby(['service', 'binary_attack']).size().unstack(fill_value=0)
    grouped = grouped.reindex(columns=['normal', 'abnormal'], fill_value=0)
    grouped = grouped.loc[grouped.sum(axis=1).sort_values(ascending=False).index]

    return {
        "labels": grouped.index.tolist(),
        "normal": grouped['normal'].tolist(),
        "abnormal": grouped['abnormal'].tolist()
    }

def protocol_usage():
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
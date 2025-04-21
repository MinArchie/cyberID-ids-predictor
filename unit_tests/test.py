import unittest
import os
import io
import json
import pandas as pd
from app import app, failed_counts, duration_stats, attack_type, service_distribution, protocol_usage

class FlaskAppTestCase(unittest.TestCase):

    def setUp(self):
        """Create a test client and other setup variables."""
        app.testing = True
        self.client = app.test_client()

    def test_homepage(self):
        """Test the index page renders successfully."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'html', response.data.lower())  # Simple content check

    def test_analyze_redirects_without_file(self):
        """Test the /analyze endpoint with no file."""
        response = self.client.post('/analyze', data={})
        self.assertEqual(response.status_code, 302)

    def test_analyze_log_api_with_no_file(self):
        """Test the API /api/analyze-log without a file."""
        response = self.client.post('/api/analyze-log', data={})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'No file uploaded', response.data)

    def test_analyze_log_api_with_empty_filename(self):
        """Test /api/analyze-log with an empty file name."""
        data = {'file': (io.BytesIO(b''), '')}
        response = self.client.post('/api/analyze-log', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'Empty filename', response.data)

    def test_analyze_log_api_valid_csv(self):
        """Test /api/analyze-log with valid CSV content."""
        sample_data = "duration,protocol_type,service,flag,src_bytes,dst_bytes,num_failed_logins\n" \
                      "10,tcp,http,SF,100,200,0"
        data = {'file': (io.BytesIO(sample_data.encode()), 'test.csv')}
        response = self.client.post('/api/analyze-log', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data)
        self.assertIsInstance(json_data, list)
        self.assertIn('prediction', json_data[0])

    def test_dashboard_api(self):
        """Test the dashboard data endpoint returns JSON with required keys."""
        response = self.client.get('/api/dashboard-data')
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertIn('attack_type_stats', json_data)
        self.assertIn('failed_login_stats', json_data)

    # =======================
    # Helper function tests
    # =======================

    def test_failed_counts_returns_labels_and_data(self):
        result = failed_counts()
        self.assertIn('labels', result)
        self.assertIn('data', result)
        self.assertEqual(len(result['labels']), len(result['data']))

    def test_duration_stats_structure(self):
        result = duration_stats()
        self.assertIn('labels', result)
        self.assertIn('data', result)

    def test_attack_type_structure(self):
        result = attack_type()
        self.assertIn('labels', result)
        self.assertIn('data', result)

    def test_service_distribution_structure(self):
        result = service_distribution()
        self.assertIn('labels', result)
        self.assertIn('normal', result)
        self.assertIn('abnormal', result)

    def test_protocol_usage_structure(self):
        result = protocol_usage()
        self.assertIn('labels', result)
        self.assertIn('datasets', result)
        self.assertEqual(len(result['datasets']), 2)


if __name__ == '__main__':
    unittest.main()

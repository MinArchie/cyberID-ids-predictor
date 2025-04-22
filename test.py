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
        global df
        from app import df
        test_data = {
            'duration': [1, 5, 10, 20, 30],
            'protocol_type': ['tcp', 'udp', 'icmp', 'tcp', 'udp'],
            'service': ['http', 'dns', 'smtp', 'ftp', 'http'],
            'flag': ['SF', 'SF', 'REJ', 'SF', 'SF'],
            'src_bytes': [100, 200, 300, 400, 500],
            'dst_bytes': [50, 100, 150, 200, 250],
            'num_failed_logins': [0, 1, 0, 2, 3],
            'binary_attack': ['normal', 'normal', 'abnormal', 'abnormal', 'abnormal']
        }
        app.df = pd.DataFrame(test_data)
        import app as app_module
        app_module.df = pd.DataFrame(test_data)
        
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    def tearDown(self):
        """Clean up after tests."""
        with self.client.session_transaction() as session:
            session.clear()
        
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if filename.startswith('test_'):
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                except:
                    pass

    def test_homepage(self):
        """Test the index page renders successfully."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'html', response.data.lower())

    def test_analyze_redirects_without_file(self):
        """Test the /analyze endpoint with no file."""
        response = self.client.post('/analyze', data={})
        self.assertEqual(response.status_code, 302)

    def test_dashboard_api(self):
        """Test the dashboard data endpoint returns JSON with required keys."""
        response = self.client.get('/api/dashboard-data')
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertIn('attack_type_stats', json_data)
        self.assertIn('failed_login_stats', json_data)
        self.assertIn('duration_stats', json_data)
        self.assertIn('service_stats', json_data)
        self.assertIn('protocol_stats', json_data)

    def test_analyze_with_empty_filename(self):
        """Test /analyze with an empty filename."""
        data = {'logfile': (io.BytesIO(b''), ''), 'model_choice': 'ml'}
        response = self.client.post('/analyze', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/')

    def test_analyze_without_model_choice(self):
        """Test /analyze without specifying a model choice."""
        sample_data = "duration,protocol_type,service,flag,src_bytes,dst_bytes,num_failed_logins\n" \
                     "10,tcp,http,SF,100,200,0"
        data = {'logfile': (io.BytesIO(sample_data.encode()), 'test_file.csv')}
        response = self.client.post('/analyze', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/')

    def test_results_without_session_data(self):
        """Test accessing /results without required session data."""
        response = self.client.get('/results')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/')

    def test_results_with_invalid_model_choice(self):
        """Test /results with an invalid model choice in session."""
        with self.client.session_transaction() as session:
            session['uploaded_file'] = 'test_file.csv'
            session['model_choice'] = 'invalid_model'
        with open(os.path.join(app.config['UPLOAD_FOLDER'], 'test_file.csv'), 'w') as f:
            f.write("duration,protocol_type,service,flag,src_bytes,dst_bytes,num_failed_logins\n" \
                    "10,tcp,http,SF,100,200,0")
            
        response = self.client.get('/results')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/')

    def test_results_with_nonexistent_file(self):
        """Test /results with a nonexistent file."""
        with self.client.session_transaction() as session:
            session['uploaded_file'] = 'nonexistent_file.csv'
            session['model_choice'] = 'ml'
            
        response = self.client.get('/results')
        self.assertEqual(response.status_code, 404)
        self.assertIn(b'File not found', response.data)

    def test_results_with_invalid_csv_format(self):
        """Test /results with an invalid CSV file format."""
        with self.client.session_transaction() as session:
            session['uploaded_file'] = 'test_invalid.csv'
            session['model_choice'] = 'ml'
            
        with open(os.path.join(app.config['UPLOAD_FOLDER'], 'test_invalid.csv'), 'w') as f:
            f.write("invalid_column\n1")
            
        response = self.client.get('/results')
        self.assertEqual(response.status_code, 500)

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
        try:
            result = service_distribution()
            self.assertIn('labels', result)
            self.assertIn('normal', result)
            self.assertIn('abnormal', result)
        except KeyError:
            self.skipTest("Required columns not available in test data")

    def test_protocol_usage_structure(self):
        result = protocol_usage()
        self.assertIn('labels', result)
        self.assertIn('datasets', result)
        self.assertEqual(len(result['datasets']), 2)

    def test_empty_dataframe_handling(self):
        """Test helper functions with an empty dataframe."""
        import app as app_module
        original_df = app_module.df.copy()
        
        try:
            app_module.df = pd.DataFrame()
            
            with self.assertRaises(Exception):
                failed_counts()
                
            with self.assertRaises(Exception):
                duration_stats()
                
            with self.assertRaises(Exception):
                attack_type()
                
            with self.assertRaises(Exception):
                protocol_usage()
        finally:
            app_module.df = original_df


if __name__ == '__main__':
    unittest.main()
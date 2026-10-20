import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ['GHOSTNET_ML_API_KEY'] = 'test-service-key'
TEMP = tempfile.TemporaryDirectory(prefix='ghostnet-test-', dir=ROOT.parent)
os.environ['GHOSTNET_SCAN_ROOTS'] = TEMP.name
os.environ['IDS_MODEL_PATH'] = str(Path(TEMP.name) / 'anomaly.joblib')
import app

class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.client=app.app.test_client()
        self.headers={'X-API-Key':'test-service-key'}
        self.core=app.yara_core_mod
    def test_authentication_required(self):
        self.assertEqual(401,self.client.post('/api/yara/scan-file',json={}).status_code)
        self.assertEqual(200,self.client.get('/api/health').status_code)
    def test_legacy_entrypoints_share_authenticated_service(self):
        import runpy
        first=runpy.run_path(str(ROOT/'Malware Detection Model'/'app.py'))['app']
        second=runpy.run_path(str(ROOT/'Yara Detection Model'/'yara_api.py'))['app']
        self.assertIs(first,second)
        self.assertEqual(401,first.test_client().post('/api/yara/scan-file',json={}).status_code)
    def test_native_conditions_not_any_string(self):
        rules=self.core.parse_rules('rule both { strings: $a="alpha" $b="beta" condition: all of them }')
        self.assertEqual({},self.core.match_rules(rules,b'alpha'))
        self.assertIn('both',self.core.match_rules(rules,b'alpha beta'))
    def test_native_filesize_and_offset(self):
        rules=self.core.parse_rules('rule header { strings: $a={4D 5A} condition: $a at 0 and filesize < 10 }')
        self.assertFalse(self.core.match_rules(rules,b'xMZ'))
        self.assertTrue(self.core.match_rules(rules,b'MZ123'))
    def test_invalid_rules_fail(self):
        with self.assertRaises(Exception):self.core.parse_rules('rule broken { condition: imaginary }')
    def test_scan_refuses_truncation(self):
        path=Path(TEMP.name)/'large.bin';path.write_bytes(b'0123456789')
        rules=self.core.parse_rules('rule test { condition: true }')
        with self.assertRaises(ValueError):self.core.scan_file(rules,path,max_bytes=5)
    def test_paths_restricted(self):
        with self.assertRaises(ValueError):app.allowed_file(__file__)
    def test_static_file_cannot_use_telemetry_model(self):
        path=Path(TEMP.name)/'sample.bin';path.write_bytes(b'example')
        self.assertEqual(400,self.client.post('/api/malware/scan-file',headers=self.headers,json={'filePath':str(path)}).status_code)
    def test_baseline_persisted_and_schema_checked(self):
        import pandas as pd
        service=app.AnomalyService()
        records=pd.DataFrame([{'packet_size':100+i,'source_port':1000+i,'destination_port':443,'protocol':'TCP'} for i in range(30)])
        service.train(records)
        restored=app.AnomalyService();self.assertTrue(restored.is_ready());self.assertEqual(30,restored.state()['baselineRows'])
        self.assertEqual(1,len(restored.detect(records.head(1))))
        with self.assertRaises(ValueError):restored.detect(pd.DataFrame([{'packet_size':123}]))
        invalid=records.head(1).copy();invalid['packet_size']='bad'
        with self.assertRaises(ValueError):restored.detect(invalid)
        invalid=records.head(1).copy();invalid['packet_size']=float('inf')
        with self.assertRaises(ValueError):restored.detect(invalid)

if __name__=='__main__':unittest.main()

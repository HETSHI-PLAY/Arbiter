"""Database trust contracts: synthetic config/driver, never .env or network."""
import importlib.util
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from fastapi import HTTPException
from fastapi.testclient import TestClient
from tests.test_ui_api import load_isolated_api, SyntheticDB

ROOT = Path(__file__).resolve().parents[1]


def load_database():
    config = types.ModuleType('app.config')
    config.DATABASE_URL = 'postgresql://synthetic:local-secret@local.invalid/test'
    config.REMOTE_DATABASE_URL = 'postgresql://synthetic:remote-secret@remote.invalid/test'
    config.ACTIVE_DB_PROFILE = 'local'
    driver = types.ModuleType('psycopg')
    driver.connect = MagicMock(side_effect=AssertionError('Network forbidden'))
    rows = types.ModuleType('psycopg.rows')
    rows.dict_row = object()
    spec = importlib.util.spec_from_file_location('isolated_database_trust', ROOT / 'app/database.py')
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'app.config': config, 'psycopg': driver, 'psycopg.rows': rows}):
        spec.loader.exec_module(module)
    return module


class DatabaseTrustTests(unittest.TestCase):
    def setUp(self):
        self.db = load_database()
        self.api = load_isolated_api()
        self.api.db_module = self.db
        self.client = TestClient(self.api.app)
        self.addCleanup(self.client.close)

    def test_profile_probe_uses_requested_profile_without_switching(self):
        connection = MagicMock()
        connection.__enter__.return_value.execute.return_value.fetchone.return_value = {'v': 'PostgreSQL synthetic'}
        self.db.psycopg.connect.side_effect = None
        self.db.psycopg.connect.return_value = connection
        response = self.client.post('/api/database/test', json={'profile': 'remote'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['ok'])
        self.assertEqual(self.db.psycopg.connect.call_args.args[0], self.db._db_profiles['remote']['url'])
        self.assertEqual(self.db.get_active_profile_id(), 'local')

    def test_masked_uri_replacement_is_rejected_without_mutation(self):
        original = self.db._db_profiles['remote']['url']
        for value in ('postgresql://user:***@synthetic.invalid/db', 'postgresql://user:%2A%2A%2A@synthetic.invalid/db'):
            response = self.client.post('/api/database/config', json={'profile': 'remote', 'url': value})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(self.db._db_profiles['remote']['url'], original)

    def test_unknown_profile_probe_rejected_without_connection(self):
        response = self.client.post('/api/database/test', json={'profile': 'missing'})
        self.assertEqual(response.status_code, 400)
        self.db.psycopg.connect.assert_not_called()

    def test_purge_alerts_requires_valid_preview_token(self):
        # Execution (dry_run=False) without preview token must be rejected
        response = self.client.post('/api/database/purge-alerts', json={'tenant': 'Alpha', 'dry_run': False})
        self.assertEqual(response.status_code, 400)
        self.assertIn('preview_token', response.json().get('detail', ''))

    def test_purge_alerts_dry_run_generates_preview_token(self):
        # Dry-run generates server preview_token
        fake_conn = MagicMock(spec=['__enter__', '__exit__', 'execute'])
        fake_conn.__enter__.return_value.execute.return_value.fetchone.return_value = {'n': 5}
        with patch.object(self.api, 'get_db') as mock_get_db:
            mock_get_db.return_value = fake_conn
            response = self.client.post('/api/database/purge-alerts', json={'tenant': 'Alpha', 'dry_run': True})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertTrue(data.get('dry_run'))
            self.assertIn('preview_token', data)
            self.assertTrue(len(data['preview_token']) >= 16)

    def test_purge_alerts_rejects_malformed_older_than_days(self):
        response = self.client.post('/api/database/purge-alerts', json={'older_than_days': 'invalid_days', 'dry_run': True})
        self.assertEqual(response.status_code, 400)

    def test_purge_alerts_rejects_negative_older_than_days(self):
        response = self.client.post('/api/database/purge-alerts', json={'older_than_days': -10, 'dry_run': True})
        self.assertEqual(response.status_code, 400)

    def test_purge_alerts_rejects_invalid_iso_time(self):
        response = self.client.post('/api/database/purge-alerts', json={'time_from': 'not-an-iso-time', 'dry_run': True})
        self.assertEqual(response.status_code, 400)

    def test_purge_alerts_rejects_inverted_time_range(self):
        response = self.client.post('/api/database/purge-alerts', json={
            'time_from': '2026-02-01T00:00:00Z',
            'time_to': '2026-01-01T00:00:00Z',
            'dry_run': True
        })
        self.assertEqual(response.status_code, 400)

    def test_purge_alerts_rejects_non_boolean_dry_run(self):
        response = self.client.post('/api/database/purge-alerts', json={'tenant': 'Alpha', 'dry_run': 'not_a_bool'})
        self.assertEqual(response.status_code, 400)

    def test_purge_incidents_rejects_invalid_status_filter(self):
        response = self.client.post('/api/database/purge-incidents', json={'status': 'invalid_filter', 'dry_run': True})
        self.assertEqual(response.status_code, 400)

    def test_purge_alerts_execution_with_token_and_single_use(self):
        fake_conn = MagicMock(spec=['__enter__', '__exit__', 'execute'])
        fake_conn.__enter__.return_value.execute.return_value.fetchone.return_value = {'n': 3}
        cur_mock = MagicMock()
        cur_mock.rowcount = 3
        fake_conn.__enter__.return_value.execute.return_value = cur_mock

        with patch.object(self.api, 'get_db') as mock_get_db:
            mock_get_db.return_value = fake_conn
            # 1. Preview
            prev = self.client.post('/api/database/purge-alerts', json={'tenant': 'Alpha', 'dry_run': True})
            self.assertEqual(prev.status_code, 200)
            token = prev.json()['preview_token']

            # 2. Execute with token
            exec_res = self.client.post('/api/database/purge-alerts', json={
                'tenant': 'Alpha',
                'dry_run': False,
                'preview_token': token
            })
            self.assertEqual(exec_res.status_code, 200)
            self.assertEqual(exec_res.json()['deleted'], 3)

            # 3. Re-execution with same token must fail (single-use)
            re_exec = self.client.post('/api/database/purge-alerts', json={
                'tenant': 'Alpha',
                'dry_run': False,
                'preview_token': token
            })
            self.assertEqual(re_exec.status_code, 400)
            self.assertIn('single-use', re_exec.json().get('detail', ''))

    def test_purge_alerts_execution_rejects_expired_token(self):
        fake_conn = MagicMock(spec=['__enter__', '__exit__', 'execute'])
        fake_conn.__enter__.return_value.execute.return_value.fetchone.return_value = {'n': 2}
        with patch.object(self.api, 'get_db') as mock_get_db:
            mock_get_db.return_value = fake_conn
            prev = self.client.post('/api/database/purge-alerts', json={'tenant': 'Alpha', 'dry_run': True})
            token = prev.json()['preview_token']
            # Force expiration
            self.db._preview_registry[token]['expires_at'] = time.time() - 10
            exec_res = self.client.post('/api/database/purge-alerts', json={
                'tenant': 'Alpha',
                'dry_run': False,
                'preview_token': token
            })
            self.assertEqual(exec_res.status_code, 400)
            self.assertIn('kedaluwarsa', exec_res.json().get('detail', ''))

    def test_purge_alerts_execution_rejects_criteria_mismatch(self):
        fake_conn = MagicMock(spec=['__enter__', '__exit__', 'execute'])
        fake_conn.__enter__.return_value.execute.return_value.fetchone.return_value = {'n': 2}
        with patch.object(self.api, 'get_db') as mock_get_db:
            mock_get_db.return_value = fake_conn
            prev = self.client.post('/api/database/purge-alerts', json={'tenant': 'Alpha', 'dry_run': True})
            token = prev.json()['preview_token']
            # Attempt to execute with tenant=Beta using token for tenant=Alpha
            exec_res = self.client.post('/api/database/purge-alerts', json={
                'tenant': 'Beta',
                'dry_run': False,
                'preview_token': token
            })
            self.assertEqual(exec_res.status_code, 400)
            self.assertIn('tidak cocok', exec_res.json().get('detail', ''))

    def test_purge_alerts_execution_rejects_profile_switch(self):
        fake_conn = MagicMock(spec=['__enter__', '__exit__', 'execute'])
        fake_conn.__enter__.return_value.execute.return_value.fetchone.return_value = {'n': 2}
        with patch.object(self.api, 'get_db') as mock_get_db:
            mock_get_db.return_value = fake_conn
            prev = self.client.post('/api/database/purge-alerts', json={'tenant': 'Alpha', 'dry_run': True})
            token = prev.json()['preview_token']
            # Switch profile before execution
            self.db._db_profiles['remote']['mode'] = 'read_write'
            try:
                self.db.set_active_profile('remote')
                exec_res = self.client.post('/api/database/purge-alerts', json={
                    'tenant': 'Alpha',
                    'dry_run': False,
                    'preview_token': token
                })
                self.assertEqual(exec_res.status_code, 409)
                self.assertIn('berubah', exec_res.json().get('detail', ''))
            finally:
                self.db._db_profiles['remote']['mode'] = 'read_only'
                self.db.set_active_profile('local')

    def test_concurrent_token_consumption_is_strictly_atomic(self):
        import concurrent.futures
        fake_conn = MagicMock(spec=['__enter__', '__exit__', 'execute'])
        fake_conn.__enter__.return_value.execute.return_value.fetchone.return_value = {'n': 2}
        cur_mock = MagicMock()
        cur_mock.rowcount = 2
        fake_conn.__enter__.return_value.execute.return_value = cur_mock

        with patch.object(self.api, 'get_db') as mock_get_db:
            mock_get_db.return_value = fake_conn
            prev = self.client.post('/api/database/purge-alerts', json={'tenant': 'Alpha', 'dry_run': True})
            token = prev.json()['preview_token']

            results = []
            def try_consume():
                return self.client.post('/api/database/purge-alerts', json={
                    'tenant': 'Alpha',
                    'dry_run': False,
                    'preview_token': token
                })

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                f1 = executor.submit(try_consume)
                f2 = executor.submit(try_consume)
                results = [f1.result(), f2.result()]

            status_codes = sorted([r.status_code for r in results])
            # Exactly one request must succeed (200) and one must be rejected (400)
            self.assertEqual(status_codes, [200, 400])

    def test_preview_registry_capacity_is_bounded(self):
        # Generating tokens beyond MAX_PREVIEW_REGISTRY_SIZE must evict oldest tokens
        max_size = self.db.MAX_PREVIEW_REGISTRY_SIZE
        tokens = []
        for i in range(max_size + 20):
            tok = self.db.create_preview_token('alerts', 'local', {'tenant': f't-{i}'}, 1)
            tokens.append(tok)

        self.assertLessEqual(len(self.db._preview_registry), max_size)
        # Oldest tokens must have been evicted
        self.assertNotIn(tokens[0], self.db._preview_registry)
        self.assertNotIn(tokens[1], self.db._preview_registry)
        # Newest tokens must still be present
        self.assertIn(tokens[-1], self.db._preview_registry)

    def test_purge_alerts_rejects_toctou_connection_profile_drift(self):
        # If connection was tagged for 'remote' but active profile became 'local'
        fake_conn = MagicMock()
        fake_conn._arbiter_profile_id = 'remote'
        fake_conn.__enter__.return_value.execute.return_value.fetchone.return_value = {'n': 2}
        with patch.object(self.api, 'get_db') as mock_get_db:
            mock_get_db.return_value = fake_conn
            # _active_profile is 'local'
            self.assertEqual(self.db.get_active_profile_id(), 'local')
            with self.assertRaises(HTTPException) as ctx:
                self.db.purge_alerts(fake_conn, tenant='Alpha', dry_run=True)
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertIn('beralih', ctx.exception.detail)

"""Bundled PWA assets must not be resolved beside the executable."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app as panel


STATIC = Path(panel.__file__).resolve().parent / 'static'


class PwaResourcePathTests(unittest.TestCase):
    def test_service_worker_from_source(self):
        response = TestClient(panel.app).get('/sw.js?v=123')
        self.assert_worker(response)

    def test_service_worker_when_executable_is_outside_bundle(self):
        # PyInstaller puts __file__ in its extracted bundle, while
        # application_path points at the directory containing the executable.
        with tempfile.TemporaryDirectory() as executable_dir:
            with patch.object(panel, 'application_path', executable_dir):
                response = TestClient(panel.app).get('/sw.js?v=123')
        self.assert_worker(response)

    def assert_worker(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, (STATIC / 'sw.js').read_bytes())
        self.assertTrue(response.headers['content-type'].startswith('text/javascript'))
        self.assertEqual(response.headers['cache-control'], 'no-cache')
        self.assertEqual(response.headers['service-worker-allowed'], '/')

    def test_static_version_when_executable_is_outside_bundle(self):
        expected = str(int(max(
            os.path.getmtime(Path(root) / name)
            for root, _, files in os.walk(STATIC)
            for name in files
        )))
        self.assertNotEqual(expected, '0')
        with tempfile.TemporaryDirectory() as executable_dir:
            with patch.object(panel, 'application_path', executable_dir):
                self.assertEqual(panel.static_version(), expected)


if __name__ == '__main__':
    unittest.main()

"""The test session must never operate on the checkout's data.json."""

import os
import unittest

import app


class DataIsolationTests(unittest.TestCase):
    def test_data_file_points_at_the_session_temp_dir(self):
        self.assertEqual(
            os.path.basename(app.DATA_FILE), 'data.json')
        self.assertIn('awp-test-data-', app.DATA_FILE)

    def test_data_file_is_not_the_checkout_file(self):
        checkout = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'data.json')
        self.assertNotEqual(os.path.abspath(app.DATA_FILE),
                            os.path.abspath(checkout))


if __name__ == '__main__':
    unittest.main()

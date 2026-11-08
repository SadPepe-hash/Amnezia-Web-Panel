import re
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / 'templates' / 'my_connections.html'


class TestMyConnectionsPageInit(unittest.TestCase):
    def test_page_loads_connections_on_dom_ready(self):
        source = TEMPLATE.read_text(encoding='utf-8')
        match = re.search(
            r"document\.addEventListener\(\s*['\"]DOMContentLoaded['\"]\s*,\s*\(\)\s*=>\s*\{(.*?)\}\s*\)",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(
            match,
            'DOMContentLoaded initializer is missing from my_connections.html',
        )
        body = match.group(1)
        self.assertIn('loadSelfServiceOptions()', body)
        self.assertIn('loadConnections()', body)


if __name__ == '__main__':
    unittest.main()

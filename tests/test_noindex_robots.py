"""Regression guards for crawl-blocking and the sanitized login page.

The panel is an admin tool often exposed on a public domain; it must not
advertise itself to search engines or showcase its feature set in the
publicly viewable login page source.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NoindexAndLoginSanitizationTests(unittest.TestCase):
    def test_x_robots_tag_middleware_present(self):
        app_src = (ROOT / 'app.py').read_text(encoding='utf-8')
        self.assertIn("response.headers['X-Robots-Tag'] = 'noindex, nofollow'",
                      app_src)

    def test_robots_txt_route_disallows_everything(self):
        app_src = (ROOT / 'app.py').read_text(encoding='utf-8')
        self.assertIn('@app.get("/robots.txt"', app_src)
        self.assertIn('Disallow: /', app_src)

    def test_meta_robots_in_page_heads(self):
        for name in ('templates/base.html', 'templates/login.html'):
            head = (ROOT / name).read_text(encoding='utf-8')
            self.assertIn('<meta name="robots" content="noindex, nofollow">',
                          head, msg=f'{name} must keep crawlers out')

    def test_login_page_does_not_dump_full_i18n_dictionary(self):
        login = (ROOT / 'templates' / 'login.html').read_text(encoding='utf-8')
        self.assertIn('login_translations_json', login)
        self.assertNotIn('{{ translations_json', login,
                         'full UI dictionary must not leak into the public '
                         'login page (feature showcase in view-source)')
        self.assertNotIn('all_translations_json', login)

    def test_render_provides_minimal_login_dictionary(self):
        app_src = (ROOT / 'app.py').read_text(encoding='utf-8')
        self.assertIn('login_translations_json', app_src)
        for key in ("'login'", "'logging_in'", "'login_error'"):
            self.assertIn(key, app_src)


if __name__ == '__main__':
    unittest.main()

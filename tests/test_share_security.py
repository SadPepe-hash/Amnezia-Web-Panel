"""Exercise real share functions with synthetic state; never import/start app."""
import ast
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from starlette.responses import HTMLResponse, JSONResponse


class ShareSecurityTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parents[1].joinpath('app.py').read_text(encoding='utf-8-sig')
        tree = ast.parse(source)
        names = {'api_user_share_setup', 'share_page', 'api_share_auth',
                 'api_share_connections', 'api_share_config', '_share_session_authorized'}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        for node in nodes:
            node.decorator_list = []
        self.user = {'id': 'u1', 'username': 'synthetic', 'share_token': 'stable-url',
                     'share_enabled': True, 'share_password_hash': 'hash:old'}
        self.data = {'users': [self.user], 'servers': [], 'user_connections': []}
        self.saved = []
        self.ssh = Mock(side_effect=AssertionError('SSH must not be reached'))
        self.ns = {'Request': object, 'ShareSetupRequest': object, 'ShareAuthRequest': object,
                   'JSONResponse': JSONResponse, 'HTMLResponse': HTMLResponse,
                   'load_data': lambda: self.data,
                   'save_data': lambda data: self.saved.append(copy.deepcopy(data)),
                   '_check_admin': lambda request: True,
                   'hash_password': lambda password: 'hash:' + password,
                   'verify_password': lambda password, hashed: hashed == 'hash:' + password,
                   '_t': lambda text, lang: text, 'tpl': lambda *args, **kwargs: kwargs,
                   'get_ssh': self.ssh}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<isolated-share-functions>', 'exec'), self.ns)
        self.request = SimpleNamespace(session={}, cookies={})

    def call(self, name, **kwargs):
        return self.ns[name](token='stable-url', request=self.request, **kwargs)

    def login(self, password='old'):
        return self.call('api_share_auth', req=SimpleNamespace(password=password))

    def setup_share(self, enabled=True, password=None):
        result = self.ns['api_user_share_setup']('u1', SimpleNamespace(enabled=enabled, password=password), self.request)
        self.assertEqual(result['share_token'], 'stable-url')
        self.assertEqual(self.user['share_token'], 'stable-url')

    def assert_locked(self):
        self.assertTrue(self.call('share_page')['need_password'])
        self.assertEqual(self.call('api_share_connections').status_code, 401)
        self.assertEqual(self.call('api_share_config', connection_id='missing').status_code, 401)
        self.ssh.assert_not_called()

    def assert_authorized(self):
        self.assertFalse(self.call('share_page')['need_password'])
        self.assertEqual(self.call('api_share_connections')['username'], 'synthetic')
        # Passing auth reaches connection lookup, but never a real server.
        self.assertEqual(self.call('api_share_config', connection_id='missing').status_code, 404)
        self.ssh.assert_not_called()

    def test_password_change_revokes_replayed_session_on_all_routes(self):
        self.assertEqual(self.login(), {'status': 'success'})
        self.assert_authorized()
        old_session = copy.deepcopy(self.request.session)
        self.setup_share(password='new')
        self.assertIn('share_auth_revision', self.saved[-1]['users'][0])
        self.request.session = old_session
        self.assert_locked()
        self.assertEqual(self.login('old').status_code, 401)
        self.assert_locked()
        self.assertEqual(self.login('new'), {'status': 'success'})
        self.assert_authorized()

    def test_disable_and_reenable_does_not_resurrect_session(self):
        self.login()
        old_session = copy.deepcopy(self.request.session)
        self.setup_share(enabled=False)
        self.assertEqual(self.call('share_page').status_code, 404)
        self.assertEqual(self.login().status_code, 404)
        self.assertEqual(self.call('api_share_connections').status_code, 403)
        self.assertEqual(self.call('api_share_config', connection_id='missing').status_code, 403)
        self.setup_share(enabled=True)
        self.request.session = old_session
        self.assert_locked()
        self.login()
        self.assert_authorized()

    def test_legacy_boolean_session_is_rejected_even_at_revision_one(self):
        for revision in (None, 0, 1):
            with self.subTest(revision=revision):
                if revision is not None:
                    self.user['share_auth_revision'] = revision
                self.request.session = {'share_auth_stable-url': True}
                self.assert_locked()
                self.login()
                self.assert_authorized()

    def test_new_login_uses_revision_not_password_hash(self):
        self.login()
        value = self.request.session['share_auth_stable-url']
        self.assertIs(type(value), int)
        self.assertEqual(value, self.user.get('share_auth_revision', 0))
        self.assertNotIn(self.user['share_password_hash'], repr(self.request.session))
        self.assert_authorized()

    def test_unchanged_settings_preserve_authorization(self):
        self.login()
        self.setup_share()
        self.assert_authorized()

    def test_clear_and_reprotect_revokes_previous_session(self):
        self.login()
        old_session = copy.deepcopy(self.request.session)
        self.setup_share(password='')
        self.request.session = {}
        self.assert_authorized()  # Explicitly passwordless sharing stays public.
        self.setup_share(password='new')
        self.request.session = old_session
        self.assert_locked()

    def test_missing_and_wrong_typed_sessions_fail_closed(self):
        for value in (None, False, True, '0', {}, []):
            with self.subTest(value=value):
                self.request.session = {'share_auth_stable-url': value}
                self.assert_locked()


if __name__ == '__main__':
    unittest.main()

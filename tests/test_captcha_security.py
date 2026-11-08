"""Exercise real auth handlers without importing app or touching panel data.

The process-local challenge store intentionally supports a single worker only;
multiple workers need a shared store with atomic consume (not cookie answers).
"""
import ast
import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from typing import Optional


ROOT = Path(__file__).resolve().parents[1]
ANSWER = 'AbC72'
PNG = b'\x89PNG\r\n\x1a\nsynthetic-image'


def load_handlers():
    """Compile only the actual auth handlers, model and challenge import."""
    tree = ast.parse((ROOT / 'app.py').read_text(encoding='utf-8'))
    names = {'api_captcha', 'api_login', 'LoginRequest'}
    selected = [node for node in tree.body
                if getattr(node, 'name', '') in names
                or (isinstance(node, ast.ImportFrom)
                    and node.module == 'captcha_challenges')]
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key='synthetic-test-key')
    data = {'settings': {'captcha': {'enabled': True}},
            'users': [{'id': 'test-user', 'username': 'alice', 'password_hash': 'hashed',
                       'role': 'admin', 'enabled': True}]}
    image = SimpleNamespace(save=lambda out, **kwargs: out.write(PNG))
    generator = Mock(return_value=SimpleNamespace(gen_captcha_image=Mock(
        return_value=SimpleNamespace(characters=ANSWER, image=image))))
    ns = dict(app=app, Request=Request, BaseModel=BaseModel, Optional=Optional,
              JSONResponse=JSONResponse, StreamingResponse=StreamingResponse,
              io=io, CaptchaGenerator=generator, load_data=lambda: data,
              verify_password=Mock(return_value=True),
              _t=lambda key, lang: key)
    exec(compile(ast.Module(body=selected, type_ignores=[]), 'app.py', 'exec'), ns)
    # Every test gets a fresh store, never the application's runtime state.
    if 'captcha_challenges' in ns:
        ns['captcha_challenges'] = type(ns['captcha_challenges'])()
    return app, ns, data


class CaptchaHandlerTests(unittest.TestCase):
    def setUp(self):
        self.app, self.ns, self.data = load_handlers()
        self.client = TestClient(self.app)

    def challenge(self):
        response = self.client.get('/api/auth/captcha')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['content-type'], 'image/png')
        self.assertEqual(response.content, PNG)
        return self.client.cookies.get('session')

    def login(self, answer=ANSWER):
        return self.client.post('/api/auth/login', json={
            'username': 'alice', 'password': 'test-password', 'captcha': answer})

    def replay_cookie(self, cookie):
        self.client.cookies.clear()
        self.client.cookies.set('session', cookie, domain='testserver.local', path='/')

    def test_cookie_contains_only_opaque_challenge_id(self):
        cookie = self.challenge()
        payload = json.loads(base64.b64decode(cookie.split('.')[0]))
        self.assertEqual(set(payload), {'captcha_challenge_id'})
        self.assertRegex(payload['captcha_challenge_id'], r'^[A-Za-z0-9_-]{43}$')
        self.assertNotIn(ANSWER.lower(), json.dumps(payload).lower())

    def test_solved_cookie_cannot_be_replayed(self):
        cookie = self.challenge()
        self.assertEqual(self.login(ANSWER.lower()).status_code, 200)
        self.replay_cookie(cookie)
        self.assertEqual(self.login().status_code, 400)
        self.assertEqual(self.ns['verify_password'].call_count, 1)

    def test_failed_or_missing_answer_consumes_challenge(self):
        for answer in ('wrong', '', None):
            with self.subTest(answer=answer):
                cookie = self.challenge()
                self.assertEqual(self.login(answer).status_code, 400)
                self.replay_cookie(cookie)
                self.assertEqual(self.login().status_code, 400)
        self.ns['verify_password'].assert_not_called()

    def test_bad_password_also_consumes_challenge(self):
        cookie = self.challenge()
        self.ns['verify_password'].return_value = False
        self.assertEqual(self.login().status_code, 401)
        self.ns['verify_password'].return_value = True
        self.replay_cookie(cookie)
        self.assertEqual(self.login().status_code, 400)

    def test_refresh_revokes_previous_challenge(self):
        old = self.challenge()
        new = self.challenge()
        self.assertNotEqual(old, new)
        self.replay_cookie(old)
        self.assertEqual(self.login().status_code, 400)
        self.replay_cookie(new)
        self.assertEqual(self.login().status_code, 200)

    def test_no_challenge_rejected_before_password_verification(self):
        self.assertEqual(self.login().status_code, 400)
        self.ns['verify_password'].assert_not_called()

    def test_disabled_captcha_does_not_block_login(self):
        self.data['settings']['captcha']['enabled'] = False
        self.assertEqual(self.login(None).status_code, 200)

    def test_missing_generator_retains_error_response(self):
        self.ns['CaptchaGenerator'] = None
        response = self.client.get('/api/auth/captcha')
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {'error': 'multicolorcaptcha is not installed'})


class ChallengeStoreTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('captcha_challenges'),
                             'server-side challenge store is required')
        from captcha_challenges import CaptchaChallengeStore
        self.now = 100.0
        self.store = CaptchaChallengeStore(ttl_seconds=60, max_entries=3,
                                          clock=lambda: self.now)

    def test_exact_expiry_boundary_and_expired_cleanup(self):
        old = self.store.issue(ANSWER)
        self.now += 59
        self.assertTrue(self.store.consume(old, ANSWER))
        expired = self.store.issue(ANSWER)
        self.now += 60
        self.assertFalse(self.store.consume(expired, ANSWER))
        self.assertEqual(len(self.store), 0)

    def test_capacity_evicts_oldest_not_newest(self):
        ids = [self.store.issue(ANSWER) for _ in range(4)]
        self.assertEqual(len(self.store), 3)
        self.assertFalse(self.store.consume(ids[0], ANSWER))
        for token in ids[1:]:
            self.assertTrue(self.store.consume(token, ANSWER))

    def test_expired_entries_are_pruned_when_issuing(self):
        self.store.issue(ANSWER)
        self.store.issue(ANSWER)
        self.now += 60
        self.store.issue(ANSWER)
        self.assertEqual(len(self.store), 1)

    def test_concurrent_consume_allows_one_winner(self):
        token = self.store.issue(ANSWER)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: self.store.consume(token, ANSWER), range(32)))
        self.assertEqual(sum(results), 1)

    def test_concurrent_issue_stays_bounded(self):
        with ThreadPoolExecutor(max_workers=16) as pool:
            ids = list(pool.map(lambda _: self.store.issue(ANSWER), range(64)))
        self.assertEqual(len(set(ids)), 64)
        self.assertEqual(len(self.store), 3)

    def test_discard_and_unknown_id_fail_closed(self):
        token = self.store.issue(ANSWER)
        self.store.discard(token)
        self.assertFalse(self.store.consume(token, ANSWER))
        self.assertFalse(self.store.consume('unknown', ANSWER))
        self.assertFalse(self.store.consume(None, ANSWER))


if __name__ == '__main__':
    unittest.main()

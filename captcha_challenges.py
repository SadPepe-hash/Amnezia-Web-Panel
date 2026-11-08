"""Bounded, one-use CAPTCHA challenges for the single-process panel.

Only random opaque IDs may be placed in the signed (not encrypted) session.
Answers stay in process memory. Challenges expire after five minutes, are
consumed on every validation attempt, and oldest entries are evicted at capacity.
Cleanup is lazy on store operations; no background thread is needed.

Deployment: use ONE application worker. Multiple workers/replicas require a
shared TTL store with atomic consume (e.g. Redis GETDEL); otherwise challenges
issued by another worker fail closed. Restarting also invalidates challenges.
This does not replace endpoint rate limiting: flooding can evict live challenges.
"""
from collections import OrderedDict
import secrets
import threading
import time


class CaptchaChallengeStore:
    def __init__(self, ttl_seconds=300, max_entries=4096, clock=time.monotonic):
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError('CAPTCHA TTL and capacity must be positive')
        self._ttl = ttl_seconds
        self._capacity = max_entries
        self._clock = clock
        self._entries = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, now):
        # Fixed TTL and monotonic insertion order mean oldest expires first.
        while self._entries:
            token, (_, deadline) = next(iter(self._entries.items()))
            if deadline > now:
                break
            del self._entries[token]

    def issue(self, answer):
        with self._lock:
            now = self._clock()
            self._prune(now)
            token = secrets.token_urlsafe(32)
            while token in self._entries:
                token = secrets.token_urlsafe(32)
            while len(self._entries) >= self._capacity:
                self._entries.popitem(last=False)
            self._entries[token] = (answer.lower(), now + self._ttl)
            return token

    def consume(self, token, answer):
        with self._lock:
            self._prune(self._clock())
            entry = self._entries.pop(token, None) if isinstance(token, str) else None
            # Pop before checking the answer: wrong/empty answers consume too.
            return bool(entry and isinstance(answer, str) and answer
                        and secrets.compare_digest(entry[0].encode('utf-8'),
                                                   answer.lower().encode('utf-8')))

    def discard(self, token):
        with self._lock:
            self._prune(self._clock())
            if isinstance(token, str):
                self._entries.pop(token, None)

    def __len__(self):
        with self._lock:
            self._prune(self._clock())
            return len(self._entries)


captcha_challenges = CaptchaChallengeStore()

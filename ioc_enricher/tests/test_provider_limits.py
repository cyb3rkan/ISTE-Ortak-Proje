"""
Provider rate limits, circuit breaker and enrichment deadlines.

A fake clock and a fake sleep keep these tests deterministic: nothing waits in
real time for a quota window, and every HTTP answer comes from a local fake.
The aggregator tests need real threads; they use short, event-driven waits
and a safety timer so a regression fails instead of hanging.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import MagicMock

import pytest
import requests
from urllib3.util.retry import RequestHistory

from ioc_enricher.core.aggregator import ProviderAggregator
from ioc_enricher.enricher import IOCEnricher
from ioc_enricher.models import IOCType, ProviderResult, ProviderStatus
from ioc_enricher.providers import GreyNoiseProvider, VirusTotalProvider
from ioc_enricher.providers import base
from ioc_enricher.utils import rate_limiter
from ioc_enricher.utils.cache import Cache
from ioc_enricher.utils.config import Config

_KEY = "phase6-fake-key-1b2c"
_IP = "203.0.113.7"
_IP6 = "2001:db8::7"


class _Clock:
    """Fake monotonic clock; ``sleep`` advances it and records the request."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now
        self.slept: list = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _limiter(clock: _Clock, limits=None, max_wait: float = 20.0):
    return rate_limiter.RateLimiter(limits, max_wait=max_wait, clock=clock, sleep=clock.sleep)


def _resp(status: int, body=None, headers=None, text=None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = dict(headers or {})
    if text is not None:
        resp.json.side_effect = ValueError("body is not JSON")
        resp.text = text
    else:
        resp.json.return_value = {} if body is None else body
        resp.text = json.dumps(resp.json.return_value)
    return resp


class _Probe(base.BaseProvider):
    """Minimal provider: every lookup is one ``_request``."""

    SUPPORTED_IOC_TYPES = frozenset({IOCType.IPV4})

    @property
    def name(self) -> str:
        return "Probe"

    def _get_headers(self):
        return {}

    def lookup_ip(self, ip: str) -> ProviderResult:
        return self._request("GET", f"https://probe.example.test/{ip}")


def _probe(clock: _Clock, *responses, limiter=None):
    provider = _Probe(api_key=_KEY, timeout=5, rate_limiter=limiter or _limiter(
        clock, {"Probe": (6000, 1000)}))
    provider._clock = clock
    provider._circuit = base._CircuitState(clock=clock)
    provider._session.request = MagicMock(side_effect=list(responses))
    return provider


def _sent(provider) -> int:
    return provider._session.request.call_count


class _Tokens:
    """Limiter stand-in that counts the tokens taken; never waits."""

    def __init__(self) -> None:
        self.taken = 0
        self.backoffs: list = []

    def wait(self, provider: str, max_wait=None) -> bool:
        self.taken += 1
        return True

    def backoff(self, provider: str, delay=None) -> float:
        self.backoffs.append(delay)
        return 60.0


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:

    def test_burst_then_paced_by_the_clock(self):
        clock = _Clock()
        limiter = _limiter(clock, {"P": (4, 4)}, max_wait=30)
        assert all(limiter.wait("P") for _ in range(4))
        assert clock.slept == []
        assert limiter.wait("P") is True
        assert clock.slept == [pytest.approx(15.0)]

    def test_wait_never_exceeds_its_budget(self):
        clock = _Clock()
        limiter = _limiter(clock, {"P": (4, 4)}, max_wait=30)
        for _ in range(4):
            limiter.wait("P")
        assert limiter.wait("P", max_wait=5) is False
        assert clock.slept == []
        clock.now += 15          # the refused caller did not take the next token
        assert limiter.wait("P", max_wait=0) is True

    def test_configured_budget_caps_a_longer_request(self):
        clock = _Clock()
        limiter = _limiter(clock, {"P": (4, 4)}, max_wait=10)
        for _ in range(4):
            limiter.wait("P")
        assert limiter.wait("P", max_wait=600) is False
        assert clock.slept == []

    def test_concurrent_waiters_queue_for_separate_tokens(self):
        # The fake sleep does not advance the clock, so each waiter's delay
        # shows which token it reserved: the second waiter must wait for the
        # second token, not slip through on the first one.
        clock = _Clock()
        delays: list = []
        limiter = rate_limiter.RateLimiter(
            {"P": (4, 1)}, max_wait=60, clock=clock, sleep=delays.append)
        assert limiter.wait("P") is True
        barrier = threading.Barrier(2)

        def caller():
            barrier.wait()
            limiter.wait("P")

        threads = [threading.Thread(target=caller) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert sorted(delays) == [pytest.approx(15.0), pytest.approx(30.0)]

    def test_concurrent_callers_never_overspend(self):
        clock = _Clock()
        limiter = _limiter(clock, {"P": (1, 5)}, max_wait=0)
        barrier = threading.Barrier(40)
        granted: list = []
        lock = threading.Lock()

        def caller():
            barrier.wait()
            ok = limiter.wait("P", max_wait=0)
            with lock:
                granted.append(ok)

        threads = [threading.Thread(target=caller) for _ in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert granted.count(True) == 5
        assert len(granted) == 40

    def test_backoff_uses_the_given_delay_and_fails_fast(self):
        clock = _Clock()
        limiter = _limiter(clock, {"P": (60, 10)})
        assert limiter.backoff("P", 120) == 120
        assert limiter.wait("P") is False
        assert clock.slept == []
        clock.now += 120
        assert limiter.wait("P") is True

    @pytest.mark.parametrize("delay, applied", [
        pytest.param(None, 60.0, id="no-retry-after"),
        pytest.param(10**9, 3600.0, id="capped"),
        pytest.param(-5, 1.0, id="negative"),
        pytest.param(0, 1.0, id="zero"),
        pytest.param(float("nan"), 60.0, id="nan"),
    ])
    def test_backoff_is_clamped(self, delay, applied):
        limiter = _limiter(_Clock(), {"P": (60, 10)})
        assert limiter.backoff("P", delay) == applied

    def test_backoff_never_shortens_an_active_pause(self):
        clock = _Clock()
        limiter = _limiter(clock, {"P": (60, 10)})
        limiter.backoff("P", 300)
        limiter.backoff("P", 10)
        clock.now += 100
        assert limiter.wait("P", max_wait=0) is False

    def test_429_arriving_during_a_wait_is_honoured(self):
        clock = _Clock()

        def sleep(seconds):
            clock.sleep(seconds)
            limiter.backoff("P", 600)   # another worker got HTTP 429 meanwhile

        limiter = rate_limiter.RateLimiter({"P": (4, 1)}, max_wait=20, clock=clock, sleep=sleep)
        limiter.wait("P")
        assert limiter.wait("P") is False

    def test_short_429_pause_during_a_wait_is_waited_out(self):
        clock = _Clock()

        def sleep(seconds):
            clock.sleep(seconds)
            if len(clock.slept) == 1:
                limiter.backoff("P", 3)

        limiter = rate_limiter.RateLimiter({"P": (4, 1)}, max_wait=20, clock=clock, sleep=sleep)
        limiter.wait("P")
        assert limiter.wait("P") is True
        assert clock.slept == [pytest.approx(15.0), pytest.approx(3.0)]

    def test_limits_are_configurable(self):
        limits = rate_limiter.parse_limits(
            "VirusTotal=500:10; AlienVault OTX=30 ;bad;X=abc;=5;Y=0;Z=5:0"
        )
        assert limits == {"VirusTotal": (500, 10), "AlienVault OTX": (30, 10)}
        clock = _Clock()
        limiter = _limiter(clock, rate_limiter.parse_limits("P=120:2"))
        assert limiter.wait("P") and limiter.wait("P")
        assert limiter.wait("P") is True
        assert clock.slept == [pytest.approx(0.5)]

    def test_default_limits_are_unchanged(self):
        clock = _Clock()
        limiter = _limiter(clock, max_wait=60)
        for _ in range(4):
            limiter.wait("VirusTotal")
        assert clock.slept == []
        limiter.wait("VirusTotal")
        assert clock.slept == [pytest.approx(15.0)]


class TestRetryAfter:

    _NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)

    @pytest.mark.parametrize("value, expected", [
        ("120", 120.0), (" 7 ", 7.0), ("0", 0.0), ("99999999", 99999999.0),
        (None, None), ("soon", None), ("-5", None), ("", None), (12, None),
    ])
    def test_delta_seconds(self, value, expected):
        assert rate_limiter.retry_after_seconds(value, now=self._NOW) == expected

    def test_http_date(self):
        future = format_datetime(self._NOW + timedelta(seconds=90), usegmt=True)
        past = format_datetime(self._NOW - timedelta(seconds=90), usegmt=True)
        assert rate_limiter.retry_after_seconds(future, now=self._NOW) == pytest.approx(90.0)
        assert rate_limiter.retry_after_seconds(past, now=self._NOW) == 0.0
        # "-0000" (no zone information) is read as UTC.
        assert rate_limiter.retry_after_seconds(
            "Tue, 27 Oct 2026 12:01:30 -0000", now=self._NOW) == pytest.approx(90.0)


@pytest.mark.parametrize("raw, expected", [
    ("45", 45.0), ("abc", 60.0), ("nan", 60.0), ("1e9", 600.0), ("-5", 0.0),
])
def test_numeric_settings_are_parsed_safely(monkeypatch, raw, expected):
    from ioc_enricher.utils.config import _env_float
    monkeypatch.setenv("IOC_TEST_SECONDS", raw)
    assert _env_float("IOC_TEST_SECONDS", 60.0, 0.0, 600.0) == expected


# ---------------------------------------------------------------------------
# HTTP retries inside one request
# ---------------------------------------------------------------------------

class TestHttpRetryPolicy:

    @staticmethod
    def _retry():
        provider = _Probe(api_key=_KEY, timeout=5)
        return provider._session.get_adapter("https://probe.example.test").max_retries

    def test_retry_after_is_never_slept_inside_a_request(self):
        # urllib3 would otherwise sleep a 429/503 Retry-After (up to 6 hours)
        # inside the worker; the limiter handles 429 without blocking.
        retry = self._retry()
        assert retry.respect_retry_after_header is False
        assert retry.is_retry("GET", 429, has_retry_after=True) is False

    def test_transient_server_errors_get_a_small_bounded_retry_budget(self):
        retry = self._retry()
        assert retry.is_retry("GET", 503, has_retry_after=True) is True
        assert retry.total <= 2
        history = tuple(RequestHistory("GET", "/", None, 503, None) for _ in range(2))
        assert retry.new(history=history).get_backoff_time() <= 2.0


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class TestCircuitBreaker:

    @pytest.mark.parametrize("status", [400, 403, 404, 422])
    def test_client_errors_do_not_open_the_circuit(self, status):
        clock = _Clock()
        provider = _probe(clock, *[_resp(status) for _ in range(6)])
        for _ in range(6):
            provider.lookup_ip(_IP)
        assert _sent(provider) == 6
        assert provider._circuit.allow_request() is True

    @pytest.mark.parametrize("failure", [
        pytest.param(lambda: _resp(500), id="500"),
        pytest.param(lambda: _resp(502), id="502"),
        pytest.param(lambda: _resp(503), id="503"),
        pytest.param(lambda: _resp(504), id="504"),
        pytest.param(lambda: requests.exceptions.ReadTimeout("slow"), id="timeout"),
        pytest.param(lambda: requests.exceptions.ConnectionError("reset"), id="connection"),
        pytest.param(lambda: _resp(200, text="<html>proxy</html>"), id="non-json-2xx"),
    ])
    def test_transient_failures_open_the_circuit(self, failure):
        clock = _Clock()
        provider = _probe(clock, *[failure() for _ in range(6)])
        for _ in range(5):
            provider.lookup_ip(_IP)
        result = provider.lookup_ip(_IP)
        assert _sent(provider) == 5
        assert result.status == ProviderStatus.ERROR
        assert "circuit breaker" in result.error
        assert provider._circuit.is_open() is True

    def test_rate_limit_answers_do_not_touch_the_circuit(self):
        clock = _Clock()
        provider = _probe(clock, *[_resp(429, headers={"Retry-After": "1"}) for _ in range(6)])
        for _ in range(6):
            assert provider.lookup_ip(_IP).status == ProviderStatus.RATE_LIMITED
            clock.now += 2
        assert _sent(provider) == 6
        assert provider._circuit.failures == 0
        assert provider._circuit.allow_request() is True

    def test_half_open_lets_exactly_one_trial_through(self):
        clock = _Clock()
        circuit = base._CircuitState(clock=clock)
        for _ in range(circuit.FAILURE_THRESHOLD):
            circuit.record_failure()
        assert circuit.allow_request() is False
        clock.now += circuit.RECOVERY_TIMEOUT_SECONDS
        assert circuit.allow_request() is True     # the trial
        assert circuit.allow_request() is False    # nobody else meanwhile
        circuit.record_failure()                   # trial failed: open again
        clock.now += 1
        assert circuit.allow_request() is False
        clock.now += circuit.RECOVERY_TIMEOUT_SECONDS
        assert circuit.allow_request() is True
        circuit.record_success()                   # trial succeeded: closed
        assert all(circuit.allow_request() for _ in range(3))

    def test_concurrent_failures_are_counted_exactly(self):
        circuit = base._CircuitState(clock=_Clock())
        circuit.FAILURE_THRESHOLD = 10_000
        barrier = threading.Barrier(50)

        def fail_ten_times():
            barrier.wait()
            for _ in range(10):
                circuit.record_failure()

        threads = [threading.Thread(target=fail_ten_times) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert circuit.failures == 500
        assert circuit.allow_request() is True


class TestRejectedApiKey:

    def test_rejected_key_is_not_retried_during_the_cooldown(self):
        clock = _Clock()
        tokens = _Tokens()
        provider = _probe(clock, _resp(401), _resp(401), limiter=tokens)
        first = provider.lookup_ip(_IP)
        assert (first.status, first.error) == (ProviderStatus.ERROR, "HTTP 401")
        for _ in range(3):
            again = provider.lookup_ip(_IP)
            assert again.status == ProviderStatus.ERROR
            assert "401" in again.error and "API key" in again.error
        assert _sent(provider) == 1
        assert tokens.taken == 1
        assert provider._circuit.allow_request() is True
        clock.now += provider.AUTH_RETRY_SECONDS
        provider.lookup_ip(_IP)
        assert _sent(provider) == 2


class TestRateLimitedAnswers:

    def test_429_pauses_the_provider_for_retry_after(self):
        clock = _Clock()
        provider = _probe(clock, _resp(429, headers={"Retry-After": "120"}), _resp(200, {"ok": 1}))
        first = provider.lookup_ip(_IP)
        assert first.status == ProviderStatus.RATE_LIMITED
        assert "120" in first.error
        second = provider.lookup_ip(_IP)
        assert second.status == ProviderStatus.RATE_LIMITED
        assert _sent(provider) == 1
        assert clock.slept == []
        clock.now += 120
        assert provider.lookup_ip(_IP).status == ProviderStatus.SUCCESS

    def test_429_retry_after_is_capped(self):
        clock = _Clock()
        provider = _probe(clock, _resp(429, headers={"Retry-After": "999999"}), _resp(200, {"ok": 1}))
        assert "3600" in provider.lookup_ip(_IP).error
        clock.now += 3600
        assert provider.lookup_ip(_IP).status == ProviderStatus.SUCCESS

    def test_429_http_date_retry_after(self):
        clock = _Clock()
        when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=600), usegmt=True)
        provider = _probe(clock, _resp(429, headers={"Retry-After": when}), _resp(200, {"ok": 1}))
        provider.lookup_ip(_IP)
        clock.now += 500
        assert provider.lookup_ip(_IP).status == ProviderStatus.RATE_LIMITED
        clock.now += 101
        assert provider.lookup_ip(_IP).status == ProviderStatus.SUCCESS

    def test_429_without_retry_after_pauses_sixty_seconds(self):
        # 60s pause, 20s wait budget: 21s left is refused at once, 19s left
        # is waited out (on the fake clock) and the request goes through.
        clock = _Clock()
        provider = _probe(clock, _resp(429), _resp(200, {"ok": 1}))
        provider.lookup_ip(_IP)
        clock.now += 39
        assert provider.lookup_ip(_IP).status == ProviderStatus.RATE_LIMITED
        assert clock.slept == []
        clock.now += 2
        assert provider.lookup_ip(_IP).status == ProviderStatus.SUCCESS
        assert clock.slept == [pytest.approx(19.0)]


class TestRequestDeadline:

    def test_nothing_is_sent_after_the_deadline(self):
        clock = _Clock()
        tokens = _Tokens()
        provider = _probe(clock, _resp(200, {"ok": 1}), limiter=tokens)
        with base.call_deadline(clock() - 1):
            result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.TIMEOUT
        assert "deadline" in result.error
        assert (_sent(provider), tokens.taken) == (0, 0)

    def test_rate_limit_wait_is_capped_by_the_deadline(self):
        clock = _Clock()
        limiter = _limiter(clock, {"Probe": (4, 1)}, max_wait=20)
        provider = _probe(clock, _resp(200, {"ok": 1}), _resp(200, {"ok": 1}), limiter=limiter)
        provider.lookup_ip(_IP)
        with base.call_deadline(clock() + 5):
            result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.RATE_LIMITED
        assert _sent(provider) == 1
        assert clock.slept == []

    def test_deadline_reached_while_waiting_for_a_slot_sends_nothing(self):
        clock = _Clock()
        limiter = _limiter(clock, {"Probe": (4, 1)}, max_wait=20)
        provider = _probe(clock, _resp(200, {"ok": 1}), _resp(200, {"ok": 1}), limiter=limiter)
        provider.lookup_ip(_IP)
        with base.call_deadline(clock() + 15):     # the next slot is due exactly then
            result = provider.lookup_ip(_IP)
        assert result.status == ProviderStatus.TIMEOUT
        assert _sent(provider) == 1

    def test_timeouts_shrink_to_the_deadline_without_blaming_the_provider(self):
        clock = _Clock()
        provider = _probe(clock, *[requests.exceptions.ReadTimeout("slow") for _ in range(6)])
        for _ in range(6):
            with base.call_deadline(clock() + 3):
                result = provider.lookup_ip(_IP)
        connect, read = provider._session.request.call_args.kwargs["timeout"]
        assert connect <= 3 and read <= 3
        assert result.status == ProviderStatus.TIMEOUT
        assert provider._circuit.failures == 0


# ---------------------------------------------------------------------------
# GreyNoise fallback budget
# ---------------------------------------------------------------------------

_GN_COMMUNITY = {"ip": _IP, "noise": True, "riot": False, "classification": "unknown",
                 "name": "unknown", "last_seen": "2026-10-20", "message": "Success"}


def _greynoise(clock: _Clock, *responses):
    tokens = _Tokens()
    provider = GreyNoiseProvider(api_key=_KEY, timeout=5, rate_limiter=tokens)
    provider._clock = clock
    provider._session.request = MagicMock(side_effect=list(responses))
    return provider, tokens


def _paths(provider) -> list:
    return [c.args[1].split("api.greynoise.io")[1] for c in provider._session.request.call_args_list]


class TestGreyNoiseFallbackBudget:

    def test_plan_denial_falls_back_once_then_goes_straight_to_community(self):
        clock = _Clock()
        provider, tokens = _greynoise(
            clock, _resp(403, {"message": "Forbidden"}), _resp(200, _GN_COMMUNITY),
            _resp(200, _GN_COMMUNITY), _resp(200, _GN_COMMUNITY))
        assert provider.lookup_ip(_IP).status == ProviderStatus.SUCCESS
        assert provider.lookup_ip(_IP).status == ProviderStatus.SUCCESS
        assert _paths(provider) == [f"/v3/ip/{_IP}", f"/v3/community/{_IP}", f"/v3/community/{_IP}"]
        assert tokens.taken == 3        # every HTTP request takes its own token

    def test_rejected_key_gets_no_fallback(self):
        clock = _Clock()
        provider, tokens = _greynoise(clock, _resp(401, {"message": "Unauthorized"}),
                                      _resp(200, _GN_COMMUNITY))
        result = provider.lookup_ip(_IP)
        assert (result.status, result.error) == (ProviderStatus.ERROR, "HTTP 401")
        assert _paths(provider) == [f"/v3/ip/{_IP}"]
        assert tokens.taken == 1

    def test_ip_lookup_is_tried_again_after_the_denial_expires(self):
        clock = _Clock()
        provider, _ = _greynoise(
            clock, _resp(403, {}), _resp(200, _GN_COMMUNITY),
            _resp(200, {"ip": _IP, "internet_scanner_intelligence": {"found": True, "classification": "benign"},
                        "business_service_intelligence": {"found": False}}))
        provider.lookup_ip(_IP)
        clock.now += provider.IP_LOOKUP_RETRY_SECONDS
        provider.lookup_ip(_IP)
        assert _paths(provider)[-1] == f"/v3/ip/{_IP}"

    def test_ipv6_with_denied_ip_lookup_sends_nothing(self):
        clock = _Clock()
        provider, tokens = _greynoise(clock, _resp(403, {}), _resp(200, _GN_COMMUNITY),
                                      _resp(403, {}), _resp(403, {}))
        provider.lookup_ip(_IP)
        sent_before = provider._session.request.call_count
        result = provider.lookup_ip(_IP6)
        assert result.status == ProviderStatus.ERROR
        assert "IPv4" in result.error
        assert provider._session.request.call_count == sent_before


# ---------------------------------------------------------------------------
# Aggregator: deadline, partial results, bounded workers
# ---------------------------------------------------------------------------

class _Tracker:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.threads: set = set()
        self.calls: list = []

    def enter(self, name: str) -> None:
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.threads.add(threading.get_ident())
            self.calls.append(name)

    def leave(self) -> None:
        with self.lock:
            self.active -= 1


class _FakeProvider:
    def __init__(self, name: str, tracker: _Tracker, gate: threading.Event | None = None,
                 hold: float = 0.0) -> None:
        self.name = name
        self._tracker = tracker
        self._gate = gate
        self._hold = hold

    def supports(self, ioc_type) -> bool:
        return True

    def lookup_ip(self, ip: str) -> ProviderResult:
        self._tracker.enter(self.name)
        try:
            if self._gate is not None:
                self._gate.wait(10)
            if self._hold:
                time.sleep(self._hold)
            return ProviderResult(provider=self.name, status=ProviderStatus.SUCCESS, data={"ok": 1})
        finally:
            self._tracker.leave()


@pytest.fixture
def gate():
    event = threading.Event()
    safety = threading.Timer(5.0, event.set)   # a regression fails, never hangs
    safety.start()
    yield event
    event.set()
    safety.cancel()


class TestAggregatorLimits:

    def test_slow_provider_times_out_and_partial_results_are_kept(self, gate):
        tracker = _Tracker()
        providers = [_FakeProvider("Fast A", tracker), _FakeProvider("Fast B", tracker),
                     _FakeProvider("Slow", tracker, gate)]
        aggregator = ProviderAggregator(providers, max_workers=3, deadline_seconds=0.3)
        started = time.monotonic()
        results = aggregator.query(_IP, IOCType.IPV4)
        assert time.monotonic() - started < 2.0
        assert results["Fast A"].status == ProviderStatus.SUCCESS
        assert results["Fast B"].status == ProviderStatus.SUCCESS
        assert results["Slow"].status == ProviderStatus.TIMEOUT
        assert "deadline" in results["Slow"].error
        aggregator.close()

    def test_calls_still_queued_at_the_deadline_never_run(self, gate):
        tracker = _Tracker()
        providers = [_FakeProvider("Slow", tracker, gate),
                     _FakeProvider("Queued A", tracker), _FakeProvider("Queued B", tracker)]
        aggregator = ProviderAggregator(providers, max_workers=1, deadline_seconds=0.2)
        results = aggregator.query(_IP, IOCType.IPV4)
        assert {r.status for r in results.values()} == {ProviderStatus.TIMEOUT}
        gate.set()
        aggregator.close(wait=True)
        assert tracker.calls == ["Slow"]

    def test_workers_are_reused_across_iocs(self):
        tracker = _Tracker()
        providers = [_FakeProvider(n, tracker) for n in ("A", "B", "C")]
        aggregator = ProviderAggregator(providers, max_workers=2)
        for _ in range(10):
            aggregator.query(_IP, IOCType.IPV4)
        assert len(tracker.threads) <= 2
        aggregator.close()

    def test_concurrent_enrichments_share_the_worker_limit(self):
        tracker = _Tracker()
        providers = [_FakeProvider(n, tracker, hold=0.05) for n in ("A", "B", "C")]
        aggregator = ProviderAggregator(providers, max_workers=2)
        callers = [threading.Thread(target=aggregator.query, args=(_IP, IOCType.IPV4))
                   for _ in range(3)]
        for t in callers:
            t.start()
        for t in callers:
            t.join(10)
        assert tracker.peak <= 2
        assert len(tracker.calls) == 9
        aggregator.close()

    def test_no_worker_threads_outlive_close(self, gate):
        before = set(threading.enumerate())
        tracker = _Tracker()
        providers = [_FakeProvider("Slow", tracker, gate), _FakeProvider("Fast", tracker)]
        aggregator = ProviderAggregator(providers, max_workers=2, deadline_seconds=0.1)
        for _ in range(5):
            aggregator.query(_IP, IOCType.IPV4)
        workers = [t for t in threading.enumerate()
                   if t not in before and t.name.startswith("ioc-provider")]
        assert 0 < len(workers) <= 2
        gate.set()
        aggregator.close(wait=True)
        assert not any(t.is_alive() for t in workers)

    def test_queued_provider_sends_no_request_after_the_deadline(self, gate):
        # A provider call still queued behind a slow one at the IOC deadline
        # never runs: it spends no token and sends no request.
        tracker = _Tracker()
        clock_tokens = _Tokens()
        late = _Probe(api_key=_KEY, timeout=5, rate_limiter=clock_tokens)
        late._session.request = MagicMock(return_value=_resp(200, {"ok": 1}))
        aggregator = ProviderAggregator([_FakeProvider("Slow", tracker, gate), late],
                                        max_workers=1, deadline_seconds=0.1)
        results = aggregator.query(_IP, IOCType.IPV4)
        assert results["Probe"].status == ProviderStatus.TIMEOUT
        gate.set()
        aggregator.close(wait=True)
        assert late._session.request.call_count == 0
        assert clock_tokens.taken == 0


class _QuickDeadline(Config):
    VIRUSTOTAL_API_KEY = _KEY
    ABUSEIPDB_API_KEY = ""
    SHODAN_API_KEY = ""
    OTX_API_KEY = ""
    GREYNOISE_API_KEY = ""
    ZEROBOUNCE_API_KEY = ""
    IOC_DEADLINE_SECONDS = 0.25


def test_enrichment_returns_partial_results_at_the_ioc_deadline(tmp_path, gate):
    enricher = IOCEnricher(config=_QuickDeadline,
                           cache=Cache(cache_dir=tmp_path, enabled=False), ai_enabled=False)
    [virustotal] = enricher._providers
    virustotal._limiter = _Tokens()

    def hang(*args, **kwargs):
        gate.wait(10)
        return _resp(200, {"data": {"attributes": {"last_analysis_stats": {"undetected": 60}}}})

    virustotal._session.request = MagicMock(side_effect=hang)
    started = time.monotonic()
    result = enricher.enrich(_IP, use_cache=False)
    assert time.monotonic() - started < 2.0
    assert result.provider_results["VirusTotal"].status == ProviderStatus.TIMEOUT
    assert result.risk_score.provider_coverage["failed"] == 1
    gate.set()

"""Fixture-only tests for REQ-14 production HTTP transports."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import time
import unittest
import urllib.error
from datetime import datetime, timezone

from collector.discovery.sourcegraph import SourcegraphDiscovery
from collector.github_client import GitHubGraphQLClient
from collector.http_transport import (
    GitHubCodeSearchTransport,
    GitHubCredentialError,
    GitHubGraphQLTransport,
    GitHubRepositoryRESTTransport,
    SourcegraphStreamTransport,
    TransportBudget,
    TransportBudgetError,
    TransportCircuitOpen,
    TransportError,
    resolve_github_token,
)


class FakeClock:
    def __init__(self, start=1_000.0):
        self.value = float(start)
        self.sleeps: list[float] = []

    def monotonic(self):
        return self.value

    def wall_time(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


class FakeResponse:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self._body = body
        self._offset = 0
        self.headers = headers or {}
        self.closed = False

    def read(self, size=-1):
        if self._offset >= len(self._body):
            return b""
        if size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk

    def close(self):
        self.closed = True


class SequenceOpener:
    def __init__(self, responses, clock=None):
        self.responses = iter(responses)
        self.requests = []
        self.timeouts = []
        self.times = []
        self.clock = clock

    def __call__(self, request, *, timeout):
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self.clock is not None:
            self.times.append(self.clock.monotonic())
        value = next(self.responses)
        if isinstance(value, BaseException):
            raise value
        return value


def budget(
    *,
    requests=20,
    response_bytes=1024 * 1024,
    total_bytes=8 * 1024 * 1024,
    retry_seconds=300,
):
    return TransportBudget(
        max_requests=requests,
        max_response_bytes=response_bytes,
        max_total_response_bytes=total_bytes,
        max_total_retry_seconds=retry_seconds,
    )


def search_body(name="acme/public", total_count=1):
    return json.dumps(
        {
            "total_count": total_count,
            "incomplete_results": False,
            "items": [
                {
                    "path": "src/use.cu",
                    "sha": "abc",
                    "repository": {
                        "node_id": "R_1",
                        "full_name": name,
                        "private": False,
                    },
                }
            ],
        }
    ).encode()


def graphql_body(name="acme/public", remaining=4_900):
    return json.dumps(
        {
            "data": {
                "r0": {
                    "__typename": "Repository",
                    "id": "R_1",
                    "nameWithOwner": name,
                    "visibility": "PUBLIC",
                    "isPrivate": False,
                    "isFork": False,
                    "isArchived": False,
                    "defaultBranchRef": {
                        "name": "main",
                        "target": {"oid": "a" * 40},
                    },
                },
                "rateLimit": {
                    "cost": 1,
                    "remaining": remaining,
                    "resetAt": "2026-07-27T13:00:00Z",
                },
            }
        }
    ).encode()


SSE_BODY = b"""event: matches
data: [{"repository":"github.com/acme/public","path":"src/use.cu","commit":"abc"}]

event: progress
data: {"done":true,"matchCount":1,"durationMs":1000}

event: done
data: {}

"""


class CredentialTests(unittest.TestCase):
    def test_environment_precedence_avoids_command(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("gh must not be called")

        self.assertEqual(
            resolve_github_token(
                environment={"GITHUB_TOKEN": " first ", "GH_TOKEN": "second"},
                command_runner=forbidden,
            ),
            "first",
        )
        self.assertEqual(
            resolve_github_token(
                environment={"GH_TOKEN": " second "},
                command_runner=forbidden,
            ),
            "second",
        )

    def test_gh_fallback_and_redacted_failure(self):
        completed = subprocess.CompletedProcess(
            ["gh", "auth", "token"], 0, stdout="from-gh\n", stderr=""
        )
        self.assertEqual(
            resolve_github_token(
                environment={},
                command_runner=lambda *_args, **_kwargs: completed,
            ),
            "from-gh",
        )
        with self.assertRaises(GitHubCredentialError) as raised:
            resolve_github_token(
                environment={},
                command_runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("secret-token")
                ),
            )
        self.assertNotIn("secret-token", str(raised.exception))

    def test_transport_redacts_token_loader_exceptions(self):
        def broken_loader():
            raise RuntimeError("private-token-value")

        with self.assertRaises(GitHubCredentialError) as raised:
            GitHubGraphQLTransport(token_loader=broken_loader)
        self.assertNotIn("private-token-value", str(raised.exception))


class SearchTransportTests(unittest.TestCase):
    def test_absolute_deadline_interrupts_blocking_open_and_body_read(self):
        class BlockingResponse(FakeResponse):
            def read(self, _size=-1):
                time.sleep(0.158)
                return search_body()

        scenarios = {
            "open": lambda _request, *, timeout: (
                time.sleep(0.158) or FakeResponse(200, search_body())
            ),
            "body": SequenceOpener((BlockingResponse(200),)),
        }
        for phase, opener in scenarios.items():
            with self.subTest(phase=phase):
                transport = GitHubCodeSearchTransport(
                    token="token",
                    opener=opener,
                    budget=budget(),
                    timeout=60,
                    max_retries=0,
                    min_interval=7,
                )
                started = time.monotonic()
                with self.assertRaisesRegex(
                    TransportBudgetError, "deadline"
                ):
                    transport(
                        query="TOKEN",
                        page=1,
                        per_page=100,
                        deadline_monotonic=time.monotonic() + 0.020,
                    )
                self.assertLess(time.monotonic() - started, 0.100)

    def test_absolute_deadline_interrupts_slow_drip_body(self):
        class SlowDripResponse(FakeResponse):
            def read(self, _size=-1):
                time.sleep(0.012)
                return b"x"

        transport = GitHubCodeSearchTransport(
            token="token",
            opener=SequenceOpener((SlowDripResponse(200),)),
            budget=budget(),
            timeout=60,
            max_retries=0,
            min_interval=7,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(TransportBudgetError, "deadline"):
            transport(
                query="TOKEN",
                page=1,
                per_page=100,
                deadline_monotonic=time.monotonic() + 0.020,
            )
        self.assertLess(time.monotonic() - started, 0.100)

    def test_deadline_bounds_socket_timeout_and_stops_expired_request(self):
        clock = FakeClock()
        opener = SequenceOpener((FakeResponse(200, search_body()),), clock)
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(),
            timeout=60,
            max_retries=0,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )
        transport(
            query="TOKEN",
            page=1,
            per_page=100,
            deadline_monotonic=clock.value + 3,
        )
        self.assertEqual(opener.timeouts, [3.0])
        with self.assertRaisesRegex(
            TransportBudgetError, "deadline"
        ):
            transport(
                query="TOKEN",
                page=2,
                per_page=100,
                deadline_monotonic=clock.value,
            )
        self.assertEqual(len(opener.requests), 1)

    def test_search_is_serialized_paced_authenticated_and_timeout_bounded(self):
        clock = FakeClock()
        first = FakeResponse(
            200,
            search_body(),
            headers={
                "X-RateLimit-Remaining": "4876",
                "X-RateLimit-Limit": "5000",
                "X-RateLimit-Used": "124",
                "X-RateLimit-Reset": "1785123456",
                "X-RateLimit-Resource": "search",
            },
        )
        second = FakeResponse(200, search_body())
        opener = SequenceOpener((first, second), clock)
        transport = GitHubCodeSearchTransport(
            token="top-secret-token",
            opener=opener,
            budget=budget(),
            timeout=17,
            max_retries=0,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )
        transport(query="TOKEN extension:cu", page=1, per_page=100)
        transport(query="TOKEN extension:cpp", page=1, per_page=100)
        self.assertEqual(opener.timeouts, [17, 17])
        self.assertEqual(opener.times, [1_000.0, 1_007.0])
        self.assertEqual(clock.sleeps, [7.0])
        self.assertEqual(
            opener.requests[0].get_header("Authorization"),
            "Bearer top-secret-token",
        )
        self.assertIn("q=TOKEN+extension%3Acu", opener.requests[0].full_url)
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["attempts"], 2)
        self.assertEqual(metrics["successes"], 2)
        self.assertEqual(metrics["pacing_sleep_seconds"], 7.0)
        self.assertGreaterEqual(metrics["attempt_seconds"], 0.0)
        self.assertGreaterEqual(metrics["max_attempt_seconds"], 0.0)
        self.assertEqual(metrics["rate_limit_remaining"], 4876)
        self.assertEqual(metrics["rate_limit_limit"], 5000)
        self.assertEqual(metrics["rate_limit_used"], 124)
        self.assertEqual(metrics["rate_limit_reset"], 1785123456)
        self.assertEqual(metrics["rate_limit_resource"], "search")
        encoded_metrics = json.dumps(metrics)
        self.assertNotIn("top-secret-token", encoded_metrics)
        self.assertNotIn("TOKEN", encoded_metrics)

    def test_search_rejects_ten_per_minute_or_faster_configuration(self):
        with self.assertRaises(ValueError):
            GitHubCodeSearchTransport(token="token", min_interval=6.0)

    def test_retry_after_is_honored_with_pacing_and_bounded_attempts(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(
                    429,
                    headers={
                        "Retry-After": "3",
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "2000",
                    },
                ),
                FakeResponse(200, search_body()),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="top-secret-token",
            opener=opener,
            budget=budget(),
            max_retries=1,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )
        status, data, _headers = transport(
            query="TOKEN", page=1, per_page=100
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["total_count"], 1)
        # Retry-After waits 3s, then the 7s search pacer adds the remaining 4s.
        self.assertEqual(clock.sleeps, [3.0, 4.0])
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["attempts"], 2)
        self.assertEqual(metrics["retries"], 1)
        self.assertEqual(metrics["rate_limited_attempts"], 1)
        self.assertEqual(metrics["primary_rate_limit_attempts"], 1)
        self.assertEqual(metrics["secondary_rate_limit_attempts"], 0)
        self.assertEqual(metrics["retry_after_backoffs"], 1)
        self.assertEqual(metrics["rate_limit_reset_backoffs"], 0)
        self.assertEqual(metrics["secondary_rate_limit_backoffs"], 0)
        self.assertEqual(metrics["retry_sleep_seconds"], 3.0)
        encoded_metrics = json.dumps(metrics)
        self.assertNotIn("top-secret-token", encoded_metrics)
        self.assertNotIn("TOKEN", encoded_metrics)

    def test_primary_rate_limit_uses_reset_when_retry_after_is_absent(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(
                    429,
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "1010",
                    },
                ),
                FakeResponse(200, search_body()),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(),
            max_retries=1,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )

        self.assertEqual(
            transport(query="TOKEN", page=1, per_page=100)[0],
            200,
        )
        self.assertEqual(clock.sleeps, [11.0])
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["primary_rate_limit_attempts"], 1)
        self.assertEqual(metrics["secondary_rate_limit_attempts"], 0)
        self.assertEqual(metrics["retry_after_backoffs"], 0)
        self.assertEqual(metrics["rate_limit_reset_backoffs"], 1)
        self.assertEqual(metrics["secondary_rate_limit_backoffs"], 0)

    def test_secondary_rate_limit_recovers_after_60_120_240_backoffs(self):
        clock = FakeClock()
        secondary_headers = {
            "X-RateLimit-Remaining": "9",
            # A primary reset must not control a secondary-limit retry.
            "X-RateLimit-Reset": "9999999",
        }
        opener = SequenceOpener(
            (
                FakeResponse(429, headers=secondary_headers),
                FakeResponse(403, headers=secondary_headers),
                FakeResponse(429, headers=secondary_headers),
                FakeResponse(200, search_body()),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="secret-token",
            opener=opener,
            budget=budget(retry_seconds=600),
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )

        status, data, _headers = transport(
            query="PRIVATE-QUERY", page=1, per_page=100
        )

        self.assertEqual(status, 200)
        self.assertEqual(data["total_count"], 1)
        self.assertEqual(clock.sleeps, [60.0, 120.0, 240.0])
        self.assertEqual(opener.times, [1000.0, 1060.0, 1180.0, 1420.0])
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["attempts"], 4)
        self.assertEqual(metrics["retries"], 3)
        self.assertEqual(metrics["rate_limited_attempts"], 3)
        self.assertEqual(metrics["primary_rate_limit_attempts"], 0)
        self.assertEqual(metrics["secondary_rate_limit_attempts"], 3)
        self.assertEqual(metrics["secondary_rate_limit_backoffs"], 3)
        self.assertEqual(metrics["retry_sleep_seconds"], 420.0)
        self.assertEqual(metrics["secondary_pacing_escalations"], 3)
        self.assertEqual(
            metrics["secondary_pacing_interval_seconds"], 120.0
        )
        encoded_metrics = json.dumps(metrics)
        self.assertNotIn("secret-token", encoded_metrics)
        self.assertNotIn("PRIVATE-QUERY", encoded_metrics)

    def test_secondary_throttling_escalates_the_persistent_pacing_floor(self):
        clock = FakeClock()
        headers = {
            "Retry-After": "3",
            "X-RateLimit-Remaining": "9",
        }
        opener = SequenceOpener(
            (
                FakeResponse(429, headers=headers),
                FakeResponse(200, search_body()),
                FakeResponse(429, headers=headers),
                FakeResponse(200, search_body()),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(retry_seconds=600),
            max_retries=1,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )

        self.assertEqual(
            200,
            transport(query="TOKEN", page=1, per_page=100)[0],
        )
        self.assertEqual(
            200,
            transport(query="TOKEN", page=1, per_page=100)[0],
        )

        self.assertEqual(clock.sleeps, [3.0, 12.0, 15.0, 3.0, 57.0])
        self.assertEqual(opener.times, [1000.0, 1015.0, 1030.0, 1090.0])
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["secondary_rate_limit_attempts"], 2)
        self.assertEqual(metrics["secondary_pacing_escalations"], 2)
        self.assertEqual(
            metrics["secondary_pacing_interval_seconds"], 60.0
        )

    def test_saturated_searches_raise_pacing_before_throttling_then_decay(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(200, search_body(total_count=5_000)),
                FakeResponse(200, search_body(total_count=2_000)),
                FakeResponse(200, search_body(total_count=900)),
                *(
                    FakeResponse(200, search_body())
                    for _ in range(21)
                ),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(requests=30),
            max_retries=0,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )

        for _ in range(24):
            self.assertEqual(
                200,
                transport(query="TOKEN", page=1, per_page=100)[0],
            )

        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["saturation_pacing_escalations"], 3)
        self.assertEqual(metrics["secondary_pacing_escalations"], 0)
        self.assertEqual(metrics["adaptive_pacing_deescalations"], 1)
        self.assertEqual(
            metrics["secondary_pacing_interval_seconds"], 60.0
        )
        self.assertEqual(metrics["adaptive_pacing_success_streak"], 1)
        self.assertEqual(opener.times[:3], [1000.0, 1015.0, 1075.0])
        self.assertEqual(opener.times[-2:], [3475.0, 3535.0])

    def test_success_at_zero_remaining_waits_for_primary_reset_proactively(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(
                    200,
                    search_body(),
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "1010",
                    },
                ),
                FakeResponse(200, search_body()),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(),
            max_retries=0,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )

        self.assertEqual(
            200,
            transport(query="TOKEN", page=1, per_page=100)[0],
        )
        self.assertEqual(
            200,
            transport(query="TOKEN", page=1, per_page=100)[0],
        )

        self.assertEqual(clock.sleeps, [11.0])
        self.assertEqual(opener.times, [1000.0, 1011.0])
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["proactive_primary_reset_sleeps"], 1)
        self.assertEqual(
            metrics["proactive_primary_reset_sleep_seconds"], 11.0
        )

    def test_secondary_retry_refuses_before_crossing_wall_deadline(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(
                    429, headers={"X-RateLimit-Remaining": "1"}
                ),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(retry_seconds=600),
            max_retries=1,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )

        with self.assertRaisesRegex(TransportBudgetError, "wall deadline"):
            transport(
                query="TOKEN",
                page=1,
                per_page=100,
                deadline_monotonic=clock.value + 60,
            )

        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(clock.sleeps, [])
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["retries"], 0)
        self.assertEqual(metrics["secondary_rate_limit_backoffs"], 0)
        self.assertEqual(metrics["budget_rejections"], 1)

    def test_secondary_retry_refuses_before_exceeding_total_wait_budget(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(
                    429, headers={"X-RateLimit-Remaining": "1"}
                ),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(retry_seconds=59),
            max_retries=1,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )

        with self.assertRaisesRegex(TransportBudgetError, "retry-wait budget"):
            transport(query="TOKEN", page=1, per_page=100)

        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(clock.sleeps, [])
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["retries"], 0)
        self.assertEqual(metrics["secondary_rate_limit_backoffs"], 0)
        self.assertEqual(metrics["budget_rejections"], 1)

    def test_http_error_response_is_closed_before_retry(self):
        clock = FakeClock()
        body = FakeResponse(429)
        error = urllib.error.HTTPError(
            "https://api.github.invalid",
            429,
            "rate limited",
            {"Retry-After": "0"},
            body,
        )
        opener = SequenceOpener(
            (error, FakeResponse(200, search_body())),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(),
            max_retries=1,
            min_interval=7,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )
        status, _data, _headers = transport(
            query="TOKEN", page=1, per_page=100
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.closed)
        self.assertEqual(clock.sleeps, [0.0, 15.0])

    def test_retry_delay_above_bound_fails_without_a_second_request(self):
        opener = SequenceOpener(
            (FakeResponse(429, headers={"Retry-After": "601"}),)
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(retry_seconds=600),
            max_retries=1,
        )
        with self.assertRaises(TransportBudgetError):
            transport(query="TOKEN", page=1, per_page=100)
        self.assertEqual(len(opener.requests), 1)
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["failures"], 1)
        self.assertEqual(metrics["last_retry_wait_seconds"], 601.0)
        self.assertEqual(metrics["last_retry_backoff_kind"], "retry_after")

    def test_long_server_retry_after_is_honored_within_total_budget(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(429, headers={"Retry-After": "300"}),
                FakeResponse(200, search_body()),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(retry_seconds=600),
            max_retries=1,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )
        self.assertEqual(
            200,
            transport(query="TOKEN", page=1, per_page=100)[0],
        )
        self.assertEqual([300.0], clock.sleeps)
        metrics = transport.metrics_snapshot()
        self.assertEqual(300.0, metrics["last_retry_wait_seconds"])
        self.assertEqual(300.0, metrics["max_retry_wait_seconds"])
        self.assertEqual("retry_after", metrics["last_retry_backoff_kind"])

    def test_fourth_secondary_backoff_is_bounded_before_fifth_request(self):
        clock = FakeClock()
        opener = SequenceOpener(
            tuple(
                FakeResponse(
                    429, headers={"X-RateLimit-Remaining": "1"}
                )
                for _ in range(4)
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(retry_seconds=600),
            max_retries=4,
            max_retry_delay=240,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )

        with self.assertRaisesRegex(TransportBudgetError, "configured bound"):
            transport(query="TOKEN", page=1, per_page=100)

        self.assertEqual(len(opener.requests), 4)
        self.assertEqual(clock.sleeps, [60.0, 120.0, 240.0])
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["retries"], 3)
        self.assertEqual(metrics["secondary_rate_limit_attempts"], 4)
        self.assertEqual(metrics["secondary_rate_limit_backoffs"], 3)
        self.assertEqual(metrics["retry_sleep_seconds"], 420.0)
        self.assertEqual(metrics["budget_rejections"], 1)

    def test_request_budget_stops_before_opening_another_connection(self):
        opener = SequenceOpener((FakeResponse(200, search_body()),))
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(requests=1),
            max_retries=0,
        )
        transport(query="TOKEN", page=1, per_page=100)
        with self.assertRaises(TransportBudgetError):
            transport(query="OTHER", page=1, per_page=100)
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(transport.metrics_snapshot()["budget_rejections"], 1)

    def test_prior_run_usage_is_charged_before_the_first_socket(self):
        opener = SequenceOpener((FakeResponse(200, search_body()),))
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(requests=5),
            max_retries=0,
        )
        transport.charge_prior_requests(4)
        transport(query="TOKEN", page=1, per_page=100)
        with self.assertRaisesRegex(
            TransportBudgetError, "request budget"
        ):
            transport(query="OTHER", page=1, per_page=100)
        metrics = transport.metrics_snapshot()
        self.assertEqual(4, metrics["prior_request_attempts"])
        self.assertEqual(1, metrics["attempts"])
        self.assertEqual(0, metrics["requests_remaining"])
        self.assertEqual(1, len(opener.requests))
        with self.assertRaisesRegex(
            TransportBudgetError, "before network work"
        ):
            transport.charge_prior_requests(4)

    def test_response_byte_budget_fails_closed(self):
        opener = SequenceOpener((FakeResponse(200, b"x" * 11),))
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(response_bytes=10, total_bytes=20),
            max_retries=0,
        )
        with self.assertRaises(TransportBudgetError):
            transport(query="TOKEN", page=1, per_page=100)
        self.assertTrue(opener.requests)

    def test_circuit_opens_then_allows_one_half_open_probe(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(503),
                FakeResponse(503),
                FakeResponse(200, search_body()),
            ),
            clock,
        )
        transport = GitHubCodeSearchTransport(
            token="token",
            opener=opener,
            budget=budget(),
            max_retries=0,
            circuit_failure_threshold=2,
            circuit_open_seconds=60,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )
        self.assertEqual(transport(query="A", page=1, per_page=100)[0], 503)
        self.assertEqual(transport(query="B", page=1, per_page=100)[0], 503)
        with self.assertRaises(TransportCircuitOpen):
            transport(query="private/repository-name", page=1, per_page=100)
        self.assertEqual(len(opener.requests), 2)
        clock.value += 61
        self.assertEqual(transport(query="C", page=1, per_page=100)[0], 200)
        self.assertFalse(transport.metrics_snapshot()["circuit_open"])


class GraphQLTransportTests(unittest.TestCase):
    def test_graphql_post_is_compatible_with_budgeted_client(self):
        opener = SequenceOpener((FakeResponse(200, graphql_body()),))
        transport = GitHubGraphQLTransport(
            token="token",
            opener=opener,
            budget=budget(),
            max_retries=0,
            min_interval=0,
        )
        client = GitHubGraphQLClient(
            transport,
            min_interval=0,
            max_retries=0,
            minimum_remaining=2_500,
        )
        result = client.resolve(names=("acme/public",))
        self.assertTrue(result.repositories[0].publishable)
        request = opener.requests[0]
        self.assertEqual(request.method, "POST")
        payload = json.loads(request.data)
        self.assertIn("rateLimit", payload["query"])
        self.assertEqual(payload["variables"]["owner0"], "acme")
        self.assertEqual(payload["variables"]["name0"], "public")
        self.assertEqual(request.get_header("Authorization"), "Bearer token")

    def test_rate_reset_header_is_honored_and_errors_are_redacted(self):
        clock = FakeClock()
        opener = SequenceOpener(
            (
                FakeResponse(
                    429,
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "1010",
                    },
                ),
                FakeResponse(200, graphql_body()),
            ),
            clock,
        )
        transport = GitHubGraphQLTransport(
            token="do-not-print",
            opener=opener,
            budget=budget(),
            max_retries=1,
            min_interval=0,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )
        status, _data, _headers = transport(
            query="query($name:String!){repository(name:$name){id}}",
            variables={"name": "secret-private-name"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(clock.sleeps, [11.0])
        encoded = json.dumps(transport.metrics_snapshot())
        self.assertNotIn("secret-private-name", encoded)
        self.assertNotIn("do-not-print", encoded)

    def test_malformed_json_and_network_errors_are_secret_redacted(self):
        malformed = GitHubGraphQLTransport(
            token="token-value",
            opener=SequenceOpener(
                (FakeResponse(200, b"secret/private-name token-value"),)
            ),
            budget=budget(),
            max_retries=0,
            min_interval=0,
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaises(TransportError) as malformed_error:
                malformed(query="query Private", variables={"name": "private/name"})
        message = str(malformed_error.exception)
        self.assertNotIn("private/name", message)
        self.assertNotIn("token-value", message)
        self.assertEqual(output.getvalue(), "")

        network = GitHubGraphQLTransport(
            token="token-value",
            opener=SequenceOpener(
                (urllib.error.URLError("private/name token-value"),)
            ),
            budget=budget(),
            max_retries=0,
            min_interval=0,
        )
        with self.assertRaises(TransportError) as network_error:
            network(query="query Private", variables={"name": "private/name"})
        self.assertNotIn("private/name", str(network_error.exception))
        self.assertNotIn("token-value", str(network_error.exception))


class RepositoryRESTTransportTests(unittest.TestCase):
    def test_conditional_get_returns_repository_json_and_records_success(self):
        payload = {
            "full_name": "acme/public",
            "homepage": "https://example.test/project",
        }
        opener = SequenceOpener(
            (
                FakeResponse(
                    200,
                    json.dumps(payload).encode(),
                    headers={"ETag": '"new-value"'},
                ),
            )
        )
        transport = GitHubRepositoryRESTTransport(
            token="token",
            opener=opener,
            budget=budget(),
            max_retries=0,
            min_interval=0,
        )

        status, data, headers = transport(full_name="acme/public")

        self.assertEqual(status, 200)
        self.assertEqual(data, payload)
        self.assertEqual(headers["etag"], '"new-value"')
        request = opener.requests[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.full_url, "https://api.github.com/repos/acme/public")
        self.assertEqual(request.get_header("Authorization"), "Bearer token")
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["operations"], 1)
        self.assertEqual(metrics["successes"], 1)
        self.assertEqual(metrics["conditional_hits"], 0)

    def test_http_304_uses_etag_without_decoding_an_empty_body(self):
        opener = SequenceOpener(
            (FakeResponse(304, headers={"ETag": '"same-value"'}),)
        )
        transport = GitHubRepositoryRESTTransport(
            token="token",
            opener=opener,
            budget=budget(),
            max_retries=0,
            min_interval=0,
        )

        status, data, headers = transport(
            full_name="acme/public", etag='"same-value"'
        )

        self.assertEqual(status, 304)
        self.assertIsNone(data)
        self.assertEqual(headers["etag"], '"same-value"')
        self.assertEqual(
            opener.requests[0].get_header("If-none-match"),
            '"same-value"',
        )
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["successes"], 1)
        self.assertEqual(metrics["failures"], 0)
        self.assertEqual(metrics["conditional_hits"], 1)

    def test_unavailable_and_rate_limited_responses_use_shared_counters(self):
        for unavailable in (404, 451):
            with self.subTest(status=unavailable):
                transport = GitHubRepositoryRESTTransport(
                    token="token",
                    opener=SequenceOpener((FakeResponse(unavailable),)),
                    budget=budget(),
                    max_retries=0,
                    min_interval=0,
                )
                status, data, _headers = transport(full_name="acme/public")
                self.assertEqual(status, unavailable)
                self.assertEqual(data, {"error": "http_error"})
                self.assertEqual(transport.metrics_snapshot()["failures"], 1)

        clock = FakeClock()
        transport = GitHubRepositoryRESTTransport(
            token="token",
            opener=SequenceOpener(
                (
                    FakeResponse(429, headers={"Retry-After": "2"}),
                    FakeResponse(200, b'{"homepage":null}'),
                ),
                clock,
            ),
            budget=budget(),
            max_retries=1,
            min_interval=0,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall_time=clock.wall_time,
        )
        self.assertEqual(transport(full_name="acme/public")[0], 200)
        metrics = transport.metrics_snapshot()
        self.assertEqual(metrics["rate_limited_attempts"], 1)
        self.assertEqual(metrics["retries"], 1)
        self.assertEqual(metrics["attempts"], 2)

    def test_malformed_payload_and_metrics_are_secret_redacted(self):
        transport = GitHubRepositoryRESTTransport(
            token="token-value",
            opener=SequenceOpener(
                (FakeResponse(200, b"private/name token-value"),)
            ),
            budget=budget(),
            max_retries=0,
            min_interval=0,
        )

        with self.assertRaises(TransportError) as raised:
            transport(full_name="private/name")

        rendered = str(raised.exception) + json.dumps(
            transport.metrics_snapshot()
        )
        self.assertNotIn("private/name", rendered)
        self.assertNotIn("token-value", rendered)


class SourcegraphTransportTests(unittest.TestCase):
    def test_absolute_attempt_timeout_preserves_bounded_retries(self):
        attempts = []

        def blocking_opener(_request, *, timeout):
            attempts.append(timeout)
            time.sleep(0.030)
            return FakeResponse(200, SSE_BODY)

        transport = SourcegraphStreamTransport(
            opener=blocking_opener,
            budget=budget(),
            timeout=0.010,
            max_retries=1,
            min_interval=0,
            sleep=lambda _seconds: None,
        )
        with self.assertRaises(TransportError):
            transport("TOKEN")
        self.assertEqual(len(attempts), 2)
        self.assertTrue(all(timeout == 0.010 for timeout in attempts))
        self.assertEqual(
            transport.metrics_snapshot()["network_error_attempts"], 2
        )

    def test_stream_transport_is_compatible_with_strict_sse_adapter(self):
        opener = SequenceOpener((FakeResponse(200, SSE_BODY),))
        transport = SourcegraphStreamTransport(
            opener=opener,
            budget=budget(response_bytes=10_000, total_bytes=20_000),
            max_retries=0,
            min_interval=0,
        )
        times = iter(
            (
                # Sourcegraph adapter start and completion.
                datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc),
                datetime(2026, 7, 27, 12, 0, 1, tzinfo=timezone.utc),
            )
        )
        result = SourcegraphDiscovery(
            transport, clock=lambda: next(times)
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(result.observations[0].repo_full_name, "acme/public")
        self.assertIn("count%3A50000", opener.requests[0].full_url)
        self.assertIn("v=V3", opener.requests[0].full_url)
        self.assertIn("t=keyword", opener.requests[0].full_url)
        self.assertEqual(opener.requests[0].get_header("Accept"), "text/event-stream")

    def test_sourcegraph_http_error_is_generic(self):
        transport = SourcegraphStreamTransport(
            opener=SequenceOpener((FakeResponse(503),)),
            budget=budget(),
            max_retries=0,
            min_interval=0,
        )
        with self.assertRaises(TransportError) as raised:
            transport("repo:private/name secret-token")
        self.assertNotIn("private/name", str(raised.exception))
        self.assertNotIn("secret-token", str(raised.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)

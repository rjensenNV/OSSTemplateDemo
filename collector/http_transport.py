"""Production stdlib HTTP transports for the REQ-14 source adapters.

These transports own credentials, request budgets, pacing, bounded retries,
and a small circuit breaker.  They intentionally expose only aggregate metrics:
queries, repository names, GraphQL variables, URLs, response bodies, and
credentials never appear in exceptions or metrics.

When these transports are used, configure the higher-level GitHub adapters with
``min_interval=0`` and ``max_retries=0`` so pacing/retries have one owner.
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Callable, Mapping, TypeVar


USER_AGENT = "cuda-x-developer-intelligence"
GITHUB_API = "https://api.github.com"
SOURCEGRAPH_STREAM = "https://sourcegraph.com/.api/search/stream"
_RETRYABLE_STATUS = frozenset((403, 429, 500, 502, 503, 504))
_T = TypeVar("_T")


def _call_with_absolute_deadline(
    operation: Callable[[], _T],
    *,
    remaining: Callable[[], float | None],
    timeout_error: Callable[[], BaseException],
    late_result: Callable[[_T], None] | None = None,
) -> _T:
    """Run one potentially blocking call without trusting socket timeouts.

    ``urllib`` timeout values apply to individual socket operations. A peer
    can therefore slow-drip forever, and a test double or resolver can ignore
    the timeout entirely. With a deadline, isolate the call in a daemon thread
    and wait only for the remaining absolute wall budget. A late result can be
    closed without delaying the caller.
    """
    wait = remaining()
    if wait is None:
        return operation()
    result: dict[str, object] = {}
    finished = threading.Event()
    abandoned = threading.Event()

    def invoke() -> None:
        try:
            value = operation()
            result["value"] = value
        except BaseException as exc:
            result["error"] = exc
        finally:
            finished.set()
        if (
            abandoned.is_set()
            and late_result is not None
            and "value" in result
        ):
            try:
                late_result(result["value"])  # type: ignore[arg-type]
            except BaseException:
                pass

    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    if not finished.wait(max(0.0, float(wait))):
        abandoned.set()
        # Close a value that crossed the deadline in the completion race.
        if (
            finished.is_set()
            and late_result is not None
            and "value" in result
        ):
            try:
                late_result(result["value"])  # type: ignore[arg-type]
            except BaseException:
                pass
        raise timeout_error()
    error = result.get("error")
    if isinstance(error, BaseException):
        raise error
    return result["value"]  # type: ignore[return-value]


def _close_without_blocking(value: object) -> None:
    close = getattr(value, "close", None)
    if not callable(close):
        return

    def invoke() -> None:
        try:
            close()
        except BaseException:
            pass

    threading.Thread(target=invoke, daemon=True).start()


class TransportError(RuntimeError):
    """A secret-redacted HTTP transport failure."""


class TransportBudgetError(TransportError):
    """A configured request, byte, or retry-wait budget was exhausted."""


class TransportCircuitOpen(TransportError):
    """The endpoint circuit is open after repeated bounded failures."""


class GitHubCredentialError(TransportError):
    """No GitHub credential was available."""


@dataclass(frozen=True)
class TransportBudget:
    max_requests: int
    max_response_bytes: int
    max_total_response_bytes: int
    max_total_retry_seconds: float

    def __post_init__(self) -> None:
        if self.max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if self.max_response_bytes <= 0 or self.max_total_response_bytes <= 0:
            raise ValueError("response byte budgets must be positive")
        if self.max_response_bytes > self.max_total_response_bytes:
            raise ValueError("per-response budget exceeds total byte budget")
        if self.max_total_retry_seconds < 0:
            raise ValueError("retry wait budget cannot be negative")


DEFAULT_GITHUB_BUDGET = TransportBudget(
    max_requests=1_000,
    max_response_bytes=16 * 1024 * 1024,
    max_total_response_bytes=512 * 1024 * 1024,
    max_total_retry_seconds=600.0,
)
DEFAULT_SOURCEGRAPH_BUDGET = TransportBudget(
    max_requests=250,
    max_response_bytes=128 * 1024 * 1024,
    max_total_response_bytes=2 * 1024 * 1024 * 1024,
    max_total_retry_seconds=600.0,
)
# A certified full reconciliation can spend hours walking one broad,
# non-overlapping search partition tree. Preserve the 36-hour run wall as the
# outer bound while allowing that attended mode to honor intermittent GitHub
# secondary delays without forcing a replay of the whole task.
RECONCILE_GITHUB_RETRY_WAIT_SECONDS = 2 * 60 * 60


@dataclass
class _Counters:
    prior_request_attempts: int = 0
    operations: int = 0
    attempts: int = 0
    successes: int = 0
    conditional_hits: int = 0
    failures: int = 0
    retries: int = 0
    rate_limited_attempts: int = 0
    primary_rate_limit_attempts: int = 0
    secondary_rate_limit_attempts: int = 0
    server_error_attempts: int = 0
    network_error_attempts: int = 0
    retry_after_backoffs: int = 0
    rate_limit_reset_backoffs: int = 0
    secondary_rate_limit_backoffs: int = 0
    fallback_backoffs: int = 0
    last_retry_wait_seconds: float | None = None
    max_retry_wait_seconds: float = 0.0
    last_retry_backoff_kind: str | None = None
    secondary_pacing_escalations: int = 0
    saturation_pacing_escalations: int = 0
    secondary_pacing_interval_seconds: float = 0.0
    adaptive_pacing_deescalations: int = 0
    adaptive_pacing_success_streak: int = 0
    proactive_primary_reset_sleeps: int = 0
    proactive_primary_reset_sleep_seconds: float = 0.0
    request_bytes: int = 0
    response_bytes: int = 0
    pacing_sleep_seconds: float = 0.0
    retry_sleep_seconds: float = 0.0
    attempt_seconds: float = 0.0
    max_attempt_seconds: float = 0.0
    circuit_open_rejections: int = 0
    budget_rejections: int = 0
    last_status: int | None = None
    rate_limit_remaining: int | None = None
    rate_limit_limit: int | None = None
    rate_limit_used: int | None = None
    rate_limit_reset: int | None = None
    rate_limit_resource: str | None = None


def resolve_github_token(
    *,
    environment: Mapping[str, str] | None = None,
    command_runner: Callable[..., object] = subprocess.run,
) -> str:
    """Resolve a token without ever returning command diagnostics to callers."""
    env = os.environ if environment is None else environment
    for key in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = env.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    try:
        result = command_runner(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        returncode = getattr(result, "returncode", 1)
        stdout = getattr(result, "stdout", "")
        if returncode == 0 and isinstance(stdout, str) and stdout.strip():
            return stdout.strip()
    except Exception:
        pass
    raise GitHubCredentialError("GitHub credential is unavailable")


def _load_github_token(
    token: str | None, token_loader: Callable[[], str]
) -> str:
    if isinstance(token, str) and token.strip():
        return token.strip()
    try:
        loaded = token_loader()
    except GitHubCredentialError:
        raise
    except Exception:
        raise GitHubCredentialError("GitHub credential is unavailable") from None
    if not isinstance(loaded, str) or not loaded.strip():
        raise GitHubCredentialError("GitHub credential is unavailable")
    return loaded.strip()


def _lower_headers(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if hasattr(value, "items"):
        try:
            return {str(key).lower(): str(item) for key, item in value.items()}
        except Exception:
            return {}
    return {}


class _HTTPTransport:
    def __init__(
        self,
        *,
        endpoint_name: str,
        opener: Callable[..., object] = urllib.request.urlopen,
        budget: TransportBudget,
        timeout: float = 60.0,
        max_retries: int = 3,
        max_retry_delay: float = 120.0,
        circuit_failure_threshold: int = 3,
        circuit_open_seconds: float = 60.0,
        min_interval: float = 0.0,
        secondary_pacing_steps: tuple[float, ...] = (),
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_retries < 0 or max_retry_delay < 0:
            raise ValueError("retry settings cannot be negative")
        if circuit_failure_threshold <= 0 or circuit_open_seconds < 0:
            raise ValueError("invalid circuit-breaker settings")
        if min_interval < 0:
            raise ValueError("min_interval cannot be negative")
        if any(
            not math.isfinite(step) or step <= min_interval
            for step in secondary_pacing_steps
        ) or any(
            later <= earlier
            for earlier, later in zip(
                secondary_pacing_steps,
                secondary_pacing_steps[1:],
            )
        ):
            raise ValueError(
                "secondary pacing steps must be finite, increasing, and "
                "greater than the base interval"
            )
        self._endpoint_name = endpoint_name
        self._opener = opener
        self._budget = budget
        self._timeout = timeout
        self._max_retries = max_retries
        self._max_retry_delay = max_retry_delay
        self._circuit_failure_threshold = circuit_failure_threshold
        self._circuit_open_seconds = circuit_open_seconds
        self._min_interval = min_interval
        self._secondary_pacing_steps = tuple(secondary_pacing_steps)
        self._secondary_pacing_level = -1
        self._adaptive_pacing_success_streak = 0
        self._primary_not_before: float | None = None
        self._sleep = sleep
        self._monotonic = monotonic
        self._wall_time = wall_time
        self._operation_lock = threading.RLock()
        self._metrics_lock = threading.Lock()
        self._counters = _Counters()
        self._last_attempt_at: float | None = None
        self._consecutive_failures = 0
        self._circuit_open_until: float | None = None

    def _remaining(self, deadline_monotonic: float | None) -> float | None:
        if deadline_monotonic is None:
            return None
        remaining = float(deadline_monotonic) - self._monotonic()
        if remaining <= 0:
            self._metric("budget_rejections")
            raise TransportBudgetError(
                "%s wall deadline is exhausted" % self._endpoint_name
            )
        return remaining

    def _deadline_error(self) -> TransportBudgetError:
        self._metric("budget_rejections")
        return TransportBudgetError(
            "%s wall deadline is exhausted" % self._endpoint_name
        )

    def _attempt_remaining(
        self,
        deadline_monotonic: float | None,
        attempt_deadline: float,
    ) -> float:
        remaining = attempt_deadline - time.monotonic()
        if remaining <= 0:
            raise self._deadline_error()
        outer = self._remaining(deadline_monotonic)
        return remaining if outer is None else min(remaining, outer)

    def _metric(self, name: str, amount: int | float = 1) -> None:
        with self._metrics_lock:
            setattr(
                self._counters,
                name,
                getattr(self._counters, name) + amount,
            )

    def _record_rate_limit_headers(
        self, headers: Mapping[str, str]
    ) -> None:
        parsed: dict[str, int] = {}
        for header, field in (
            ("x-ratelimit-remaining", "rate_limit_remaining"),
            ("x-ratelimit-limit", "rate_limit_limit"),
            ("x-ratelimit-used", "rate_limit_used"),
            ("x-ratelimit-reset", "rate_limit_reset"),
        ):
            value = headers.get(header)
            if value is None:
                continue
            try:
                parsed[field] = max(0, int(value))
            except (TypeError, ValueError):
                continue
        with self._metrics_lock:
            for field, value in parsed.items():
                setattr(self._counters, field, value)
            resource = headers.get("x-ratelimit-resource")
            if isinstance(resource, str) and resource:
                self._counters.rate_limit_resource = resource[:40]

    def metrics_snapshot(self) -> dict[str, int | float | str | None | bool]:
        """Return aggregate, secret-free endpoint metrics."""
        with self._metrics_lock:
            counters = dict(vars(self._counters))
        now = self._monotonic()
        circuit_open = (
            self._circuit_open_until is not None
            and now < self._circuit_open_until
        )
        counters.update(
            {
                "endpoint": self._endpoint_name,
                "request_budget": self._budget.max_requests,
                "requests_remaining": max(
                    0,
                    self._budget.max_requests
                    - int(counters["prior_request_attempts"])
                    - int(counters["attempts"]),
                ),
                "response_byte_budget": self._budget.max_total_response_bytes,
                "response_bytes_remaining": max(
                    0,
                    self._budget.max_total_response_bytes
                    - int(counters["response_bytes"]),
                ),
                "retry_seconds_budget": self._budget.max_total_retry_seconds,
                "retry_seconds_remaining": max(
                    0.0,
                    self._budget.max_total_retry_seconds
                    - float(counters["retry_sleep_seconds"]),
                ),
                "circuit_open": circuit_open,
            }
        )
        return counters

    def charge_prior_requests(self, count: int) -> None:
        """Debit durable same-run request use before any new HTTP attempt."""
        if not isinstance(count, int) or count < 0:
            raise ValueError("prior request count must be a non-negative integer")
        with self._metrics_lock:
            if self._counters.operations or self._counters.attempts:
                raise TransportBudgetError(
                    "%s prior usage must be charged before network work"
                    % self._endpoint_name
                )
            if self._counters.prior_request_attempts not in (0, count):
                raise TransportBudgetError(
                    "%s prior usage was already charged differently"
                    % self._endpoint_name
                )
            if count > self._budget.max_requests:
                raise TransportBudgetError(
                    "%s prior usage exhausts its request budget"
                    % self._endpoint_name
                )
            self._counters.prior_request_attempts = count

    def _check_circuit(self) -> None:
        now = self._monotonic()
        if self._circuit_open_until is None:
            return
        if now >= self._circuit_open_until:
            self._circuit_open_until = None
            # A half-open attempt must succeed to fully reset the circuit.
            self._consecutive_failures = self._circuit_failure_threshold - 1
            return
        self._metric("circuit_open_rejections")
        raise TransportCircuitOpen(
            "%s transport circuit is open" % self._endpoint_name
        )

    def _record_failure(self) -> None:
        self._metric("failures")
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._circuit_failure_threshold:
            self._circuit_open_until = (
                self._monotonic() + self._circuit_open_seconds
            )

    def _record_success(self) -> None:
        self._metric("successes")
        self._consecutive_failures = 0
        self._circuit_open_until = None

    def _consume_attempt(self, request_bytes: int) -> None:
        with self._metrics_lock:
            if (
                self._counters.prior_request_attempts
                + self._counters.attempts
                >= self._budget.max_requests
            ):
                self._counters.budget_rejections += 1
                raise TransportBudgetError(
                    "%s request budget is exhausted" % self._endpoint_name
                )
            self._counters.attempts += 1
            self._counters.request_bytes += request_bytes

    def _pace(self, deadline_monotonic: float | None = None) -> None:
        now = self._monotonic()
        with self._metrics_lock:
            adaptive_interval = (
                self._counters.secondary_pacing_interval_seconds
            )
        interval = max(self._min_interval, adaptive_interval)
        wait = 0.0
        if self._last_attempt_at is not None:
            wait = max(
                wait,
                interval - (now - self._last_attempt_at),
            )
        primary_wait = 0.0
        if self._primary_not_before is not None:
            primary_wait = max(0.0, self._primary_not_before - now)
            wait = max(wait, primary_wait)
        if wait > 0:
            remaining = self._remaining(deadline_monotonic)
            if remaining is not None and wait >= remaining:
                raise TransportBudgetError(
                    "%s pacing would cross the wall deadline"
                    % self._endpoint_name
                )
            self._sleep(wait)
            self._metric("pacing_sleep_seconds", wait)
            if primary_wait > 0 and wait == primary_wait:
                self._metric("proactive_primary_reset_sleeps")
                self._metric(
                    "proactive_primary_reset_sleep_seconds",
                    primary_wait,
                )
        self._last_attempt_at = self._monotonic()

    def _record_successful_primary_boundary(
        self,
        headers: Mapping[str, str],
    ) -> None:
        if headers.get("x-ratelimit-remaining") != "0":
            return
        reset = headers.get("x-ratelimit-reset")
        if reset is None:
            return
        try:
            wait = float(reset) - self._wall_time() + 1.0
        except (TypeError, ValueError):
            return
        if not math.isfinite(wait) or wait <= 0:
            return
        self._primary_not_before = max(
            self._primary_not_before or 0.0,
            self._monotonic() + wait,
        )

    def _escalate_search_pacing(self, *, reason: str) -> None:
        if not self._secondary_pacing_steps:
            return
        if reason not in {"secondary", "saturation"}:
            raise ValueError("invalid adaptive pacing reason")
        self._adaptive_pacing_success_streak = 0
        next_level = min(
            self._secondary_pacing_level + 1,
            len(self._secondary_pacing_steps) - 1,
        )
        with self._metrics_lock:
            self._counters.adaptive_pacing_success_streak = 0
            if next_level == self._secondary_pacing_level:
                return
            self._secondary_pacing_level = next_level
            interval = self._secondary_pacing_steps[next_level]
            counter = (
                "secondary_pacing_escalations"
                if reason == "secondary"
                else "saturation_pacing_escalations"
            )
            setattr(
                self._counters,
                counter,
                getattr(self._counters, counter) + 1,
            )
            self._counters.secondary_pacing_interval_seconds = interval

    def _record_search_pressure(
        self,
        *,
        saturated: bool,
        deescalate_after: int,
    ) -> None:
        if not self._secondary_pacing_steps:
            return
        if deescalate_after <= 0:
            raise ValueError("adaptive pacing decay must be positive")
        if saturated:
            self._escalate_search_pacing(reason="saturation")
            return
        if self._secondary_pacing_level < 0:
            return
        self._adaptive_pacing_success_streak += 1
        with self._metrics_lock:
            self._counters.adaptive_pacing_success_streak = (
                self._adaptive_pacing_success_streak
            )
        if self._adaptive_pacing_success_streak < deescalate_after:
            return
        self._adaptive_pacing_success_streak = 0
        self._secondary_pacing_level -= 1
        interval = (
            self._secondary_pacing_steps[self._secondary_pacing_level]
            if self._secondary_pacing_level >= 0
            else 0.0
        )
        with self._metrics_lock:
            self._counters.adaptive_pacing_success_streak = 0
            self._counters.adaptive_pacing_deescalations += 1
            self._counters.secondary_pacing_interval_seconds = interval

    def _rate_limit_class(self, headers: Mapping[str, str]) -> str:
        remaining = headers.get("x-ratelimit-remaining")
        if remaining is not None:
            try:
                if int(remaining) == 0:
                    return "primary"
            except (TypeError, ValueError):
                pass
        return "secondary"

    def _retry_after_wait(
        self, headers: Mapping[str, str]
    ) -> float | None:
        retry_after = headers.get("retry-after")
        if not retry_after:
            return None
        try:
            wait = float(retry_after)
        except ValueError:
            try:
                parsed = parsedate_to_datetime(retry_after)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                wait = parsed.timestamp() - self._wall_time()
            except (TypeError, ValueError, OverflowError):
                return None
        if not math.isfinite(wait):
            return None
        return max(0.0, wait)

    def _retry_wait(
        self,
        status: int,
        headers: Mapping[str, str],
        attempt: int,
    ) -> tuple[float, str]:
        rate_limit_class = (
            self._rate_limit_class(headers)
            if status in (403, 429)
            else None
        )
        retry_after_wait = self._retry_after_wait(headers)
        if retry_after_wait is not None:
            wait = retry_after_wait
            backoff_kind = "retry_after"
        elif status in (403, 429):
            rate_limit_class = self._rate_limit_class(headers)
            reset = headers.get("x-ratelimit-reset")
            if rate_limit_class == "primary" and reset:
                try:
                    wait = float(reset) - self._wall_time() + 1.0
                except (TypeError, ValueError):
                    wait = float(60 * (2**attempt))
                    backoff_kind = "fallback"
                else:
                    if math.isfinite(wait):
                        backoff_kind = "rate_limit_reset"
                    else:
                        wait = float(60 * (2**attempt))
                        backoff_kind = "fallback"
            elif rate_limit_class == "secondary":
                wait = float(60 * (2**attempt))
                backoff_kind = "secondary_rate_limit"
            else:
                # A primary-limit response without a usable reset is still
                # paced conservatively instead of falling back to a rapid
                # one-second retry.
                wait = float(60 * (2**attempt))
                backoff_kind = "fallback"
        else:
            wait = float(2**attempt)
            backoff_kind = "fallback"
        wait = max(0.0, wait)
        if rate_limit_class == "secondary":
            self._escalate_search_pacing(reason="secondary")
        with self._metrics_lock:
            self._counters.last_retry_wait_seconds = wait
            self._counters.max_retry_wait_seconds = max(
                self._counters.max_retry_wait_seconds, wait
            )
            self._counters.last_retry_backoff_kind = backoff_kind
        if wait > self._max_retry_delay:
            self._metric("budget_rejections")
            raise TransportBudgetError(
                "%s retry delay exceeds its configured bound"
                % self._endpoint_name
            )
        return wait, backoff_kind

    def _sleep_for_retry(
        self,
        wait: float,
        deadline_monotonic: float | None = None,
        *,
        backoff_kind: str = "fallback",
    ) -> None:
        counter = {
            "retry_after": "retry_after_backoffs",
            "rate_limit_reset": "rate_limit_reset_backoffs",
            "secondary_rate_limit": "secondary_rate_limit_backoffs",
            "fallback": "fallback_backoffs",
        }.get(backoff_kind)
        if counter is None:
            raise ValueError("invalid backoff metric kind")
        remaining = self._remaining(deadline_monotonic)
        if remaining is not None and wait >= remaining:
            self._metric("budget_rejections")
            raise TransportBudgetError(
                "%s retry would cross the wall deadline" % self._endpoint_name
            )
        with self._metrics_lock:
            projected = self._counters.retry_sleep_seconds + wait
            if projected > self._budget.max_total_retry_seconds:
                self._counters.budget_rejections += 1
                raise TransportBudgetError(
                    "%s retry-wait budget is exhausted" % self._endpoint_name
                )
            self._counters.retry_sleep_seconds = projected
            self._counters.retries += 1
            setattr(
                self._counters,
                counter,
                getattr(self._counters, counter) + 1,
            )
        self._sleep(wait)

    def _read_response(
        self,
        response: object,
        *,
        remaining: Callable[[], float | None],
        timeout_error: Callable[[], BaseException],
    ) -> bytes:
        def read_all() -> bytes:
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise TransportError(
                        "%s returned a non-byte response"
                        % self._endpoint_name
                    )
                size += len(chunk)
                if size > self._budget.max_response_bytes:
                    self._metric("budget_rejections")
                    raise TransportBudgetError(
                        "%s response byte budget is exhausted"
                        % self._endpoint_name
                    )
                chunks.append(chunk)
            return b"".join(chunks)

        body = _call_with_absolute_deadline(
            read_all,
            remaining=remaining,
            timeout_error=timeout_error,
        )
        size = len(body)
        if size > self._budget.max_response_bytes:
            self._metric("budget_rejections")
            raise TransportBudgetError(
                "%s response byte budget is exhausted" % self._endpoint_name
            )
        with self._metrics_lock:
            projected = self._counters.response_bytes + size
            if projected > self._budget.max_total_response_bytes:
                self._counters.budget_rejections += 1
                raise TransportBudgetError(
                    "%s total response byte budget is exhausted"
                    % self._endpoint_name
                )
            self._counters.response_bytes = projected
        return body

    def _attempt(
        self,
        request: urllib.request.Request,
        *,
        deadline_monotonic: float | None = None,
    ) -> tuple[int, bytes, dict]:
        started = self._monotonic()
        response = None
        try:
            remaining = self._remaining(deadline_monotonic)
            timeout = (
                self._timeout
                if remaining is None
                else max(0.001, min(self._timeout, remaining))
            )
            outer_deadline_is_bound = (
                remaining is not None and remaining <= self._timeout
            )
            attempt_deadline = time.monotonic() + timeout

            def attempt_remaining() -> float:
                return self._attempt_remaining(
                    deadline_monotonic, attempt_deadline
                )

            def attempt_timeout_error() -> BaseException:
                if outer_deadline_is_bound:
                    return self._deadline_error()
                return TimeoutError(
                    "%s response timed out" % self._endpoint_name
                )

            response = _call_with_absolute_deadline(
                lambda: self._opener(request, timeout=timeout),
                remaining=attempt_remaining,
                timeout_error=attempt_timeout_error,
                late_result=_close_without_blocking,
            )
            status = getattr(response, "status", None)
            if status is None and hasattr(response, "getcode"):
                status = response.getcode()
            if not isinstance(status, int):
                raise TransportError(
                    "%s returned no HTTP status" % self._endpoint_name
                )
            headers = _lower_headers(getattr(response, "headers", None))
            body = self._read_response(
                response,
                remaining=attempt_remaining,
                timeout_error=attempt_timeout_error,
            )
            return status, body, headers
        except urllib.error.HTTPError as exc:
            try:
                return int(exc.code), b"", _lower_headers(exc.headers)
            finally:
                try:
                    exc.close()
                except Exception:
                    pass
        finally:
            elapsed = max(0.0, self._monotonic() - started)
            with self._metrics_lock:
                self._counters.attempt_seconds += elapsed
                self._counters.max_attempt_seconds = max(
                    self._counters.max_attempt_seconds, elapsed
                )
            if response is not None:
                _close_without_blocking(response)

    def _perform(
        self,
        request: urllib.request.Request,
        *,
        decoder: Callable[[bytes], object] | None = None,
        success_statuses: frozenset[int] = frozenset(),
        decode_statuses: frozenset[int] | None = None,
        deadline_monotonic: float | None = None,
    ) -> tuple[int, object, dict[str, str]]:
        request_bytes = len(request.data or b"")
        with self._operation_lock:
            self._check_circuit()
            self._metric("operations")
            final_status: int | None = None
            final_body = b""
            final_headers: dict[str, str] = {}
            for attempt in range(self._max_retries + 1):
                self._remaining(deadline_monotonic)
                self._consume_attempt(request_bytes)
                self._pace(deadline_monotonic)
                try:
                    status, body, headers = self._attempt(
                        request,
                        deadline_monotonic=deadline_monotonic,
                    )
                except TransportBudgetError:
                    self._record_failure()
                    raise
                except (
                    urllib.error.URLError,
                    TimeoutError,
                    OSError,
                    TransportError,
                ):
                    self._metric("network_error_attempts")
                    if attempt < self._max_retries:
                        try:
                            self._sleep_for_retry(
                                float(2**attempt), deadline_monotonic
                            )
                        except TransportBudgetError:
                            self._record_failure()
                            raise
                        continue
                    self._record_failure()
                    raise TransportError(
                        "%s transport failed after bounded retries"
                        % self._endpoint_name
                    ) from None
                with self._metrics_lock:
                    self._counters.last_status = status
                self._record_rate_limit_headers(headers)
                final_status, final_body, final_headers = status, body, headers
                if 200 <= status < 300 or status in success_statuses:
                    if (
                        decoder is not None
                        and (
                            decode_statuses is None
                            or status in decode_statuses
                        )
                    ):
                        try:
                            decoded = _call_with_absolute_deadline(
                                lambda: decoder(body),
                                remaining=lambda: self._remaining(
                                    deadline_monotonic
                                ),
                                timeout_error=self._deadline_error,
                            )
                        except TransportError:
                            self._record_failure()
                            raise
                    else:
                        decoded = body
                    self._record_successful_primary_boundary(headers)
                    self._record_success()
                    return status, decoded, headers
                if status in (403, 429):
                    self._metric("rate_limited_attempts")
                    self._metric(
                        self._rate_limit_class(headers)
                        + "_rate_limit_attempts"
                    )
                elif status >= 500:
                    self._metric("server_error_attempts")
                if status in _RETRYABLE_STATUS and attempt < self._max_retries:
                    try:
                        retry_wait, backoff_kind = self._retry_wait(
                            status, headers, attempt
                        )
                        self._sleep_for_retry(
                            retry_wait,
                            deadline_monotonic,
                            backoff_kind=backoff_kind,
                        )
                    except TransportBudgetError:
                        self._record_failure()
                        raise
                    continue
                self._record_failure()
                return status, body, headers
            if final_status is None:
                self._record_failure()
                raise TransportError(
                    "%s exhausted without an HTTP result" % self._endpoint_name
                )
            self._record_failure()
            return final_status, final_body, final_headers

    def _decode_json(self, body: bytes) -> object:
        try:
            return json.loads(body.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TransportError(
                "%s returned malformed JSON" % self._endpoint_name
            ) from None

    def _decode_text(self, body: bytes) -> str:
        try:
            return body.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise TransportError(
                "%s returned malformed UTF-8" % self._endpoint_name
            ) from None


class GitHubCodeSearchTransport(_HTTPTransport):
    """Callable transport for :class:`collector.discovery.GitHubCodeSearch`."""

    def __init__(
        self,
        *,
        token: str | None = None,
        token_loader: Callable[[], str] = resolve_github_token,
        opener: Callable[..., object] = urllib.request.urlopen,
        budget: TransportBudget = DEFAULT_GITHUB_BUDGET,
        timeout: float = 60.0,
        max_retries: int = 3,
        max_retry_delay: float = 600.0,
        circuit_failure_threshold: int = 3,
        circuit_open_seconds: float = 60.0,
        min_interval: float = 7.0,
        secondary_pacing_steps: tuple[float, ...] = (
            15.0,
            60.0,
            120.0,
        ),
        saturation_threshold: int = 900,
        adaptive_deescalate_after: int = 20,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        if min_interval <= 6.0:
            raise ValueError(
                "GitHub code search pacing must remain below 10 requests/minute"
            )
        if saturation_threshold <= 0 or adaptive_deescalate_after <= 0:
            raise ValueError("invalid adaptive GitHub search pacing")
        self._token = _load_github_token(token, token_loader)
        self._saturation_threshold = saturation_threshold
        self._adaptive_deescalate_after = adaptive_deescalate_after
        super().__init__(
            endpoint_name="github-code-search",
            opener=opener,
            budget=budget,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_delay=max_retry_delay,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_open_seconds=circuit_open_seconds,
            min_interval=min_interval,
            secondary_pacing_steps=secondary_pacing_steps,
            sleep=sleep,
            monotonic=monotonic,
            wall_time=wall_time,
        )

    def __call__(
        self,
        *,
        query: str,
        page: int,
        per_page: int,
        deadline_monotonic: float | None = None,
    ) -> tuple[int, object, dict]:
        if not isinstance(query, str) or not query:
            raise ValueError("query must be a non-empty string")
        if page <= 0 or not 1 <= per_page <= 100:
            raise ValueError("invalid GitHub code-search pagination")
        url = GITHUB_API + "/search/code?" + urllib.parse.urlencode(
            {"q": query, "page": page, "per_page": per_page}
        )
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with self._operation_lock:
            status, body, headers = self._perform(
                request,
                decoder=self._decode_json,
                deadline_monotonic=deadline_monotonic,
            )
            data = body if 200 <= status < 300 else {"error": "http_error"}
            if status == 200 and isinstance(data, Mapping):
                total_count = data.get("total_count")
                self._record_search_pressure(
                    saturated=(
                        isinstance(total_count, int)
                        and not isinstance(total_count, bool)
                        and total_count >= self._saturation_threshold
                    ),
                    deescalate_after=self._adaptive_deescalate_after,
                )
        return status, data, headers


class GitHubGraphQLTransport(_HTTPTransport):
    """Callable transport for :class:`collector.github_client.GitHubGraphQLClient`."""

    def __init__(
        self,
        *,
        token: str | None = None,
        token_loader: Callable[[], str] = resolve_github_token,
        opener: Callable[..., object] = urllib.request.urlopen,
        budget: TransportBudget = DEFAULT_GITHUB_BUDGET,
        timeout: float = 60.0,
        max_retries: int = 3,
        max_retry_delay: float = 120.0,
        circuit_failure_threshold: int = 3,
        circuit_open_seconds: float = 60.0,
        min_interval: float = 0.1,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        self._token = _load_github_token(token, token_loader)
        super().__init__(
            endpoint_name="github-graphql",
            opener=opener,
            budget=budget,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_delay=max_retry_delay,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_open_seconds=circuit_open_seconds,
            min_interval=min_interval,
            sleep=sleep,
            monotonic=monotonic,
            wall_time=wall_time,
        )

    def __call__(
        self,
        *,
        query: str,
        variables: Mapping[str, str],
        deadline_monotonic: float | None = None,
    ) -> tuple[int, object, dict]:
        if not isinstance(query, str) or not query:
            raise ValueError("query must be a non-empty string")
        if not isinstance(variables, Mapping):
            raise ValueError("variables must be a mapping")
        body = json.dumps(
            {"query": query, "variables": dict(variables)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            GITHUB_API + "/graphql",
            data=body,
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        status, response_body, headers = self._perform(
            request,
            decoder=self._decode_json,
            deadline_monotonic=deadline_monotonic,
        )
        data = response_body if 200 <= status < 300 else {"error": "http_error"}
        return status, data, headers


class GitHubRepositoryRESTTransport(_HTTPTransport):
    """Bounded conditional GET transport for one public GitHub repository.

    The higher-level client must establish explicit public visibility through
    GraphQL before calling this transport.  Keeping that policy above the HTTP
    layer makes the ordering testable and prevents a REST response from being
    used as a visibility fallback.
    """

    def __init__(
        self,
        *,
        token: str | None = None,
        token_loader: Callable[[], str] = resolve_github_token,
        opener: Callable[..., object] = urllib.request.urlopen,
        budget: TransportBudget = DEFAULT_GITHUB_BUDGET,
        timeout: float = 60.0,
        max_retries: int = 3,
        max_retry_delay: float = 120.0,
        circuit_failure_threshold: int = 3,
        circuit_open_seconds: float = 60.0,
        min_interval: float = 0.1,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        self._token = _load_github_token(token, token_loader)
        super().__init__(
            endpoint_name="github-repository-rest",
            opener=opener,
            budget=budget,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_delay=max_retry_delay,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_open_seconds=circuit_open_seconds,
            min_interval=min_interval,
            sleep=sleep,
            monotonic=monotonic,
            wall_time=wall_time,
        )

    def _decode_repository(self, body: bytes) -> object:
        payload = self._decode_json(body)
        if not isinstance(payload, Mapping):
            raise TransportError(
                "github-repository-rest returned a malformed payload"
            )
        return payload

    def __call__(
        self,
        *,
        full_name: str,
        etag: str | None = None,
        deadline_monotonic: float | None = None,
    ) -> tuple[int, object | None, dict[str, str]]:
        if not isinstance(full_name, str):
            raise ValueError("full_name must be OWNER/REPO")
        owner, separator, name = full_name.partition("/")
        if (
            not separator
            or not owner
            or not name
            or "/" in name
            or full_name != full_name.strip()
        ):
            raise ValueError("full_name must be OWNER/REPO")
        if etag is not None and (
            not isinstance(etag, str)
            or not etag
            or etag != etag.strip()
            or "\r" in etag
            or "\n" in etag
        ):
            raise ValueError("etag must be a non-empty safe header value")

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self._token,
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if etag is not None:
            headers["If-None-Match"] = etag
        request = urllib.request.Request(
            "%s/repos/%s/%s"
            % (
                GITHUB_API,
                urllib.parse.quote(owner, safe=""),
                urllib.parse.quote(name, safe=""),
            ),
            method="GET",
            headers=headers,
        )
        status, response_body, response_headers = self._perform(
            request,
            decoder=self._decode_repository,
            success_statuses=frozenset((304,)),
            decode_statuses=frozenset((200,)),
            deadline_monotonic=deadline_monotonic,
        )
        if status == 304:
            self._metric("conditional_hits")
            return status, None, response_headers
        if status == 200:
            return status, response_body, response_headers
        return status, {"error": "http_error"}, response_headers


class SourcegraphStreamTransport(_HTTPTransport):
    """Callable public Sourcegraph SSE transport."""

    def __init__(
        self,
        *,
        opener: Callable[..., object] = urllib.request.urlopen,
        budget: TransportBudget = DEFAULT_SOURCEGRAPH_BUDGET,
        timeout: float = 120.0,
        max_retries: int = 3,
        max_retry_delay: float = 120.0,
        circuit_failure_threshold: int = 3,
        circuit_open_seconds: float = 60.0,
        min_interval: float = 0.25,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            endpoint_name="sourcegraph-stream",
            opener=opener,
            budget=budget,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_delay=max_retry_delay,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_open_seconds=circuit_open_seconds,
            min_interval=min_interval,
            sleep=sleep,
            monotonic=monotonic,
            wall_time=wall_time,
        )

    def __call__(
        self, query: str, *, deadline_monotonic: float | None = None
    ) -> str:
        if not isinstance(query, str) or not query:
            raise ValueError("query must be a non-empty string")
        url = SOURCEGRAPH_STREAM + "?" + urllib.parse.urlencode(
            {
                "q": query,
                "v": "V3",
                "t": "keyword",
            }
        )
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "text/event-stream",
                "User-Agent": USER_AGENT,
            },
        )
        status, body, _headers = self._perform(
            request,
            decoder=self._decode_text,
            deadline_monotonic=deadline_monotonic,
        )
        if not 200 <= status < 300:
            raise TransportError("sourcegraph-stream returned an HTTP error")
        if not isinstance(body, str):
            raise TransportError("sourcegraph-stream returned malformed text")
        return body

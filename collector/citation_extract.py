"""Bounded public-source extraction for REQ-14 citation enrichment.

This module has no GitHub credential or publication capability.  It accepts an
already-public OpenAlex work, downloads only its public arXiv/PDF source, and
extracts GitHub repository URLs under strict network, byte, archive, parser,
and wall-time limits.
"""

from __future__ import annotations

import dataclasses
import http.client
import io
import ipaddress
import os
import queue
import re
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse

from .http_transport import (
    _call_with_absolute_deadline,
    _close_without_blocking,
)


_OPENALEX_MAILTO = os.environ.get("OPENALEX_MAILTO", "").strip()
if any(ord(character) < 32 for character in _OPENALEX_MAILTO):
    raise ValueError("OPENALEX_MAILTO cannot contain control characters")
USER_AGENT = "cuda-x-developer-intelligence"
if _OPENALEX_MAILTO:
    USER_AGENT += " (mailto:%s)" % _OPENALEX_MAILTO
_GITHUB_RE = re.compile(
    r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
_TRAILING_PUNCTUATION = re.compile(r"[.,);:]+$")
_HAVE_PDFTOTEXT = shutil.which("pdftotext") is not None
_WARNED_NO_PDFTOTEXT = [False]

MAX_FETCH_BYTES = 64 * 1024 * 1024
MAX_TAR_MEMBERS = 2_000
MAX_TAR_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_EXTRACTED_TEXT_BYTES = 32 * 1024 * 1024


@dataclasses.dataclass(frozen=True)
class RepositoryURLExtraction:
    """Outcome of inspecting the public source surfaces for one work.

    ``not_available`` means OpenAlex exposed neither an arXiv source nor an
    open-access PDF.  It is not an operational failure and therefore does not
    stale otherwise-complete citation data.  ``failed`` means at least one
    source was available but none could be inspected successfully.
    """

    urls: tuple[str, ...]
    attempted_sources: tuple[str, ...]
    successful_sources: tuple[str, ...]
    errors: tuple[str, ...]
    status: str
    source_available: bool

    def __post_init__(self) -> None:
        if self.status not in {"complete", "not_available", "failed"}:
            raise ValueError("invalid repository URL extraction status")
        if self.source_available != bool(
            self.attempted_sources or self.status == "failed"
        ):
            raise ValueError(
                "repository URL extraction availability is inconsistent"
            )
        if self.status == "complete" and not self.successful_sources:
            raise ValueError(
                "complete repository URL extraction requires a successful source"
            )
        if self.status == "not_available" and (
            self.source_available
            or self.attempted_sources
            or self.successful_sources
            or self.errors
        ):
            raise ValueError(
                "not-available repository URL extraction cannot carry attempts"
            )
        if self.status == "failed" and (
            not self.source_available
            or not self.attempted_sources
            or self.successful_sources
            or not self.errors
        ):
            raise ValueError(
                "failed repository URL extraction requires failed attempts"
            )


def _log(message: str) -> None:
    print(message, flush=True)


def _native_parser_env() -> dict[str, str]:
    """Return a minimal environment without collector/API credentials."""
    environment = {
        "PATH": os.environ.get(
            "PATH",
            "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
    }
    for name in ("LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _remaining_timeout(
    deadline_monotonic: float | None,
    maximum: float,
) -> float:
    if deadline_monotonic is None:
        return float(maximum)
    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("citation wall deadline exhausted")
    return min(float(maximum), remaining)


def _resolve_public_addresses(
    hostname: str,
    port: int,
    deadline_monotonic: float | None = None,
) -> tuple[str, ...]:
    result_queue: queue.Queue[object] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result_queue.put(
                socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                )
            )
        except BaseException as exc:
            result_queue.put(exc)

    thread = threading.Thread(target=resolve, daemon=True)
    thread.start()
    thread.join(_remaining_timeout(deadline_monotonic, 30))
    if thread.is_alive():
        raise TimeoutError("citation DNS resolution exceeded wall deadline")
    result = result_queue.get_nowait()
    if isinstance(result, BaseException):
        raise ValueError("source hostname could not be resolved") from result
    addresses = {
        item[4][0]
        for item in result
        if item and len(item) > 4 and item[4]
    }
    if not addresses or any(
        not ipaddress.ip_address(address).is_global
        for address in addresses
    ):
        raise ValueError("source URL resolves to a non-public address")
    return tuple(sorted(addresses))


def _validated_public_target(
    url: str,
    deadline_monotonic: float | None = None,
) -> tuple[urllib.parse.SplitResult, int, tuple[str, ...]]:
    parsed = urllib.parse.urlsplit(str(url))
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("source URL must be public HTTP(S)")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = _resolve_public_addresses(
        parsed.hostname,
        port,
        deadline_monotonic,
    )
    return parsed, port, addresses


def _validate_public_http_url(url: str) -> str:
    _validated_public_target(url)
    return url


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        address: str,
        port: int,
        timeout: float,
    ) -> None:
        super().__init__(
            hostname,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._validated_address = address

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._validated_address, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(
            sock,
            server_hostname=self.host,
        )


def _fetch(
    url: str,
    timeout: float = 30,
    max_bytes: int = MAX_FETCH_BYTES,
    deadline_monotonic: float | None = None,
) -> bytes:
    current_url = str(url)
    operation_deadline = time.monotonic() + float(timeout)
    if deadline_monotonic is not None:
        operation_deadline = min(
            operation_deadline,
            float(deadline_monotonic),
        )

    def remaining() -> float:
        return _remaining_timeout(operation_deadline, timeout)

    def timeout_error() -> TimeoutError:
        return TimeoutError("citation wall deadline exhausted")

    for redirect_count in range(6):
        parsed, port, addresses = _validated_public_target(
            current_url,
            operation_deadline,
        )
        address = addresses[0]
        request_timeout = (
            remaining()
            if deadline_monotonic is not None
            else float(timeout)
        )
        if parsed.scheme == "https":
            connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
                parsed.hostname or "",
                address,
                port,
                request_timeout,
            )
        else:
            connection = http.client.HTTPConnection(
                address,
                port=port,
                timeout=request_timeout,
            )
        path = urllib.parse.urlunsplit(
            ("", "", parsed.path or "/", parsed.query, "")
        )
        host = parsed.hostname or ""
        if parsed.port is not None:
            host += ":" + str(parsed.port)
        try:
            _call_with_absolute_deadline(
                lambda: connection.request(
                    "GET",
                    path,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Host": host,
                    },
                ),
                remaining=remaining,
                timeout_error=timeout_error,
            )
            response = _call_with_absolute_deadline(
                connection.getresponse,
                remaining=remaining,
                timeout_error=timeout_error,
                late_result=_close_without_blocking,
            )
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location:
                    raise ValueError(
                        "source redirect omitted Location"
                    )
                if redirect_count >= 5:
                    raise ValueError(
                        "source redirect limit exceeded"
                    )
                current_url = urllib.parse.urljoin(
                    current_url,
                    location,
                )
                continue
            if response.status < 200 or response.status >= 300:
                raise ValueError(
                    "source HTTP status %d" % response.status
                )
            length = getattr(response, "headers", {}).get(
                "Content-Length"
            )
            if length is not None:
                try:
                    if int(length) > max_bytes:
                        raise ValueError(
                            "source response exceeds byte limit"
                        )
                except ValueError as exc:
                    if "exceeds" in str(exc):
                        raise

            def read_all() -> bytes:
                chunks = []
                total = 0
                while True:
                    socket_timeout = remaining()
                    if connection.sock is not None:
                        connection.sock.settimeout(socket_timeout)
                    chunk = response.read(
                        min(64 * 1024, max_bytes - total + 1)
                    )
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise ValueError(
                            "source returned a non-byte response"
                        )
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(
                            "source response exceeds byte limit"
                        )
                    chunks.append(chunk)
                return b"".join(chunks)

            return _call_with_absolute_deadline(
                read_all,
                remaining=remaining,
                timeout_error=timeout_error,
            )
        finally:
            _close_without_blocking(connection)
    raise ValueError("source redirect limit exceeded")


def _repos_from_text(text: str) -> set[str]:
    found = set()
    for match in _GITHUB_RE.finditer(text):
        owner = match.group(1)
        name = _TRAILING_PUNCTUATION.sub("", match.group(2))
        if name.lower().endswith(".git"):
            name = name[:-4]
        if name and name not in (".", ".."):
            found.add(owner + "/" + name)
    return found


def _repos_from_tar(
    blob: bytes,
    *,
    deadline_monotonic: float | None = None,
) -> set[str]:
    urls = set()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
        members = archive.getmembers()
        if len(members) > MAX_TAR_MEMBERS:
            raise ValueError("source archive has too many members")
        expanded = sum(
            member.size for member in members if member.isfile()
        )
        if expanded > MAX_TAR_UNCOMPRESSED_BYTES:
            raise ValueError(
                "source archive exceeds expansion limit"
            )
        text_bytes = 0
        for member in members:
            _remaining_timeout(deadline_monotonic, 60)
            if not (
                member.isfile()
                and member.name.lower().endswith((".tex", ".bbl"))
            ):
                continue
            if member.size > MAX_EXTRACTED_TEXT_BYTES:
                raise ValueError(
                    "source text member exceeds byte limit"
                )
            stream = archive.extractfile(member)
            if stream is None:
                continue
            remaining = MAX_EXTRACTED_TEXT_BYTES - text_bytes
            content = stream.read(remaining + 1)
            text_bytes += len(content)
            if text_bytes > MAX_EXTRACTED_TEXT_BYTES:
                raise ValueError(
                    "source text exceeds byte limit"
                )
            urls |= _repos_from_text(
                content.decode("utf-8", "ignore")
            )
    return urls


def _repos_from_pdf(
    blob: bytes,
    *,
    deadline_monotonic: float | None = None,
) -> set[str]:
    if not _HAVE_PDFTOTEXT:
        raise RuntimeError("pdftotext is unavailable")
    with tempfile.TemporaryDirectory(
        prefix="cxit-citation-pdf-"
    ) as temporary:
        source = os.path.join(
            temporary,
            "source.pdf",
        )
        output = os.path.join(
            temporary,
            "source.txt",
        )
        with open(source, "wb") as stream:
            stream.write(blob)
        conversion = subprocess.run(
            ["pdftotext", "-q", source, output],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=_remaining_timeout(
                deadline_monotonic,
                60,
            ),
            check=False,
            env=_native_parser_env(),
        )
        if (
            conversion.returncode != 0
            or not os.path.isfile(output)
        ):
            raise ValueError(
                "PDF text extraction failed"
            )
        if (
            os.path.getsize(output)
            > MAX_EXTRACTED_TEXT_BYTES
        ):
            raise ValueError(
                "PDF text exceeds byte limit"
            )
        with open(output, "rb") as stream:
            payload = stream.read(
                MAX_EXTRACTED_TEXT_BYTES + 1
            )
        if len(payload) > MAX_EXTRACTED_TEXT_BYTES:
            raise ValueError(
                "PDF text exceeds byte limit"
            )
        return _repos_from_text(
            payload.decode("utf-8", "ignore")
        )


def extract_repo_urls(
    work: dict,
    *,
    deadline_monotonic: float | None = None,
) -> RepositoryURLExtraction:
    """Extract GitHub URLs from one public work under bounded resources."""
    urls: set[str] = set()
    attempted: list[str] = []
    successful: list[str] = []
    errors: list[str] = []
    arxiv = (work.get("ids") or {}).get("arxiv") or ""
    arxiv_id = (
        arxiv.rstrip("/").split("/")[-1].replace("abs/", "")
        if arxiv
        else ""
    )
    if arxiv_id:
        attempted.append("arxiv")
        try:
            blob = _fetch(
                "https://arxiv.org/e-print/" + arxiv_id,
                timeout=40,
                deadline_monotonic=deadline_monotonic,
            )
            try:
                urls |= _repos_from_tar(
                    blob,
                    deadline_monotonic=deadline_monotonic,
                )
            except (tarfile.TarError, EOFError):
                urls |= _repos_from_text(
                    blob.decode("utf-8", "ignore")
                )
            successful.append("arxiv")
        except Exception as exc:
            errors.append(
                "arxiv source fetch/parse failed: %s: %s"
                % (type(exc).__name__, exc)
            )
    if not urls:
        pdf = (
            (work.get("open_access") or {}).get("oa_url")
            or (work.get("primary_location") or {}).get("pdf_url")
        )
        if pdf:
            attempted.append("pdf")
            try:
                blob = _fetch(
                    pdf,
                    timeout=40,
                    deadline_monotonic=deadline_monotonic,
                )
                urls |= _repos_from_pdf(
                    blob,
                    deadline_monotonic=deadline_monotonic,
                )
                successful.append("pdf")
            except Exception as exc:
                errors.append(
                    "pdf source fetch/parse failed: %s: %s"
                    % (type(exc).__name__, exc)
                )
        if pdf and not _HAVE_PDFTOTEXT and not _WARNED_NO_PDFTOTEXT[0]:
            _log(
                "    NOTE pdftotext is unavailable; "
                "PDF code-link extraction is incomplete."
            )
            _WARNED_NO_PDFTOTEXT[0] = True
    if successful:
        status = "complete"
    elif attempted:
        status = "failed"
    else:
        status = "not_available"
    return RepositoryURLExtraction(
        urls=tuple(sorted(urls, key=str.casefold)),
        attempted_sources=tuple(attempted),
        successful_sources=tuple(successful),
        errors=tuple(errors),
        status=status,
        source_available=bool(attempted),
    )

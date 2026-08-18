"""Budgeted, fail-closed GitHub GraphQL metadata/HEAD client.

The client batches repository node IDs and OWNER/REPO names.  HTTP is supplied
by an injected transport so retry, partial-error, quota, rename, and visibility
behavior can be tested without credentials or network access.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence


class GitHubGraphQLError(RuntimeError):
    """The GraphQL response cannot safely resolve repository metadata."""


class GitHubBudgetError(GitHubGraphQLError):
    """A configured point or remaining-quota reserve would be crossed."""


# The selected GraphQL shape contains every metadata field with a real
# consumer.  Keep the conditional REST mechanism explicit, but dormant until
# a future consumer requires a field that GraphQL cannot provide.
REST_FALLBACK_FIELDS: tuple[str, ...] = ()
_COMMIT_OID = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class RepositoryLookup:
    node_id: str | None = None
    full_name: str | None = None

    def __post_init__(self) -> None:
        if self.node_id is not None and (
            not isinstance(self.node_id, str)
            or not self.node_id
            or self.node_id != self.node_id.strip()
        ):
            raise ValueError("node_id must be a non-empty trimmed string")
        if not self.node_id and not self.full_name:
            raise ValueError("lookup requires a node_id or full_name")
        if self.full_name:
            owner, separator, name = self.full_name.partition("/")
            if (
                not separator
                or not owner
                or not name
                or "/" in name
                or self.full_name != self.full_name.strip()
            ):
                raise ValueError("full_name must be OWNER/REPO")

    @property
    def key(self) -> str:
        return "node:" + self.node_id if self.node_id else "name:" + str(self.full_name)


@dataclass(frozen=True)
class RepositoryMetadata:
    request_key: str
    requested_node_id: str | None
    requested_full_name: str | None
    node_id: str | None
    full_name: str | None
    visibility: str | None
    is_private: bool | None
    is_fork: bool | None
    is_archived: bool | None
    default_branch: str | None
    head_oid: str | None
    renamed: bool
    status: str
    errors: tuple[str, ...] = ()
    disk_usage_kb: int | None = None
    description: str | None = None
    stars: int = 0
    forks: int = 0
    language: str | None = None
    created_at: str | None = None
    pushed_at: str | None = None

    @property
    def explicitly_public(self) -> bool:
        return self.visibility == "PUBLIC" and self.is_private is False

    @property
    def publishable(self) -> bool:
        return (
            self.status in ("ok", "empty")
            and self.explicitly_public
            and self.is_fork is False
            and self.is_archived is False
        )

    def to_dict(self) -> dict:
        return {
            "request_key": self.request_key,
            "requested_node_id": self.requested_node_id,
            "requested_full_name": self.requested_full_name,
            "node_id": self.node_id,
            "full_name": self.full_name,
            "visibility": self.visibility,
            "is_private": self.is_private,
            "is_fork": self.is_fork,
            "is_archived": self.is_archived,
            "default_branch": self.default_branch,
            "head_oid": self.head_oid,
            "renamed": self.renamed,
            "status": self.status,
            "errors": list(self.errors),
            "disk_usage_kb": self.disk_usage_kb,
            "display": {
                "description": self.description,
                "stars": self.stars,
                "forks": self.forks,
                "language": self.language,
                "created_at": self.created_at,
                "pushed_at": self.pushed_at,
            },
            "explicitly_public": self.explicitly_public,
            "publishable": self.publishable,
        }


@dataclass(frozen=True)
class RESTFallbackResolution:
    """Result of the optional metadata fallback without publishing raw REST."""

    status: str
    request_count: int
    fields: Mapping[str, object]
    etag: str | None


class GitHubRESTFallbackClient:
    """Fetch only explicitly contracted fields after public GraphQL proof."""

    def __init__(
        self,
        transport: Callable[..., object],
        *,
        fields: Iterable[str] = REST_FALLBACK_FIELDS,
    ) -> None:
        requested = tuple(fields)
        if any(
            not isinstance(field, str)
            or not field
            or field != field.strip()
            for field in requested
        ):
            raise ValueError("REST fallback fields must be non-empty strings")
        if len(set(requested)) != len(requested):
            raise ValueError("REST fallback fields must be unique")
        self._transport = transport
        self._fields = requested

    @property
    def fields(self) -> tuple[str, ...]:
        return self._fields

    def resolve(
        self,
        metadata: RepositoryMetadata,
        *,
        etag: str | None = None,
        cached_fields: Mapping[str, object] | None = None,
        deadline_monotonic: float | None = None,
    ) -> RESTFallbackResolution:
        # This is the normal path: the GraphQL shape is complete, so no REST
        # request (and no token/quota spend) is permitted.
        if not self._fields:
            return RESTFallbackResolution("not_required", 0, {}, etag)

        # Visibility is intentionally established before the repository name,
        # cache, or transport is consulted. REST must never act as a visibility
        # probe for private or ambiguous GraphQL results.
        if not metadata.explicitly_public:
            raise GitHubGraphQLError(
                "REST fallback requires explicitly public GraphQL metadata"
            )
        if not metadata.publishable or metadata.full_name is None:
            raise GitHubGraphQLError(
                "REST fallback requires publishable GraphQL metadata"
            )

        try:
            raw = self._transport(
                full_name=metadata.full_name,
                etag=etag,
                deadline_monotonic=deadline_monotonic,
            )
            response = _normalize_response(raw)
        except Exception as exc:
            raise GitHubGraphQLError(
                "REST fallback transport failed (%s)"
                % type(exc).__name__
            ) from None

        response_etag = response.headers.get("etag") or etag
        if response.status == 200:
            if not isinstance(response.data, Mapping):
                raise GitHubGraphQLError(
                    "REST fallback returned a malformed payload"
                )
            missing = tuple(
                field for field in self._fields if field not in response.data
            )
            if missing:
                raise GitHubGraphQLError(
                    "REST fallback omitted contracted metadata fields"
                )
            return RESTFallbackResolution(
                "updated",
                1,
                {field: response.data[field] for field in self._fields},
                response_etag,
            )
        if response.status == 304:
            cached = {} if cached_fields is None else dict(cached_fields)
            if any(field not in cached for field in self._fields):
                raise GitHubGraphQLError(
                    "REST fallback cache is incomplete after HTTP 304"
                )
            return RESTFallbackResolution(
                "not_modified",
                1,
                {field: cached[field] for field in self._fields},
                response_etag,
            )
        if response.status in (404, 451):
            raise GitHubGraphQLError(
                "REST fallback repository is unavailable (HTTP %d)"
                % response.status
            )
        if response.status in (403, 429):
            raise GitHubGraphQLError(
                "REST fallback rate limit persisted (HTTP %d)"
                % response.status
            )
        raise GitHubGraphQLError(
            "REST fallback returned HTTP %d" % response.status
        )


@dataclass(frozen=True)
class GraphQLError:
    message: str
    request_key: str | None = None
    error_type: str | None = None

    def to_dict(self) -> dict:
        return {
            "message": self.message,
            "request_key": self.request_key,
            "error_type": self.error_type,
        }


@dataclass(frozen=True)
class GraphQLResolution:
    repositories: tuple[RepositoryMetadata, ...]
    errors: tuple[GraphQLError, ...]
    request_count: int
    points_used: int
    remaining: int
    reset_at: str | None

    @property
    def complete(self) -> bool:
        return all(
            item.status not in ("partial_error", "unverified_visibility")
            for item in self.repositories
        )

    def by_request_key(self) -> dict[str, RepositoryMetadata]:
        return {item.request_key: item for item in self.repositories}


@dataclass(frozen=True)
class _Response:
    status: int
    data: object
    headers: Mapping[str, str]


def _headers(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key).lower(): str(item) for key, item in value.items()}


def _normalize_response(value: object) -> _Response:
    if isinstance(value, _Response):
        return value
    if isinstance(value, tuple):
        if len(value) == 3:
            status, data, headers = value
            return _Response(int(status), data, _headers(headers))
        if len(value) == 2:
            data, headers = value
            return _Response(200, data, _headers(headers))
    if hasattr(value, "status") and hasattr(value, "data"):
        return _Response(
            int(getattr(value, "status")),
            getattr(value, "data"),
            _headers(getattr(value, "headers", {})),
        )
    if isinstance(value, Mapping):
        if "status" in value and "data" in value:
            return _Response(
                int(value["status"]), value["data"], _headers(value.get("headers", {}))
            )
        return _Response(200, value, {})
    raise TypeError("GraphQL transport returned an unsupported response")


_REPOSITORY_FIELDS = """
    __typename
    id
    nameWithOwner
    visibility
    isPrivate
    isFork
    isArchived
    diskUsage
    description
    stargazerCount
    forkCount
    primaryLanguage { name }
    createdAt
    pushedAt
    defaultBranchRef {
      name
      target { ... on Commit { oid } }
    }
"""


class GitHubGraphQLClient:
    """Resolve GitHub repository state without spending the owner's reserve."""

    def __init__(
        self,
        transport: Callable[..., object],
        *,
        batch_size: int = 50,
        point_budget: int = 2_500,
        minimum_remaining: int = 2_500,
        estimated_points_per_batch: int = 1,
        maximum_points_per_batch: int = 100,
        max_retries: int = 2,
        min_interval: float = 0.1,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        if not 1 <= batch_size <= 100:
            raise ValueError("batch_size must be between 1 and 100")
        if point_budget <= 0 or minimum_remaining < 0:
            raise ValueError("invalid GraphQL budget")
        if estimated_points_per_batch <= 0:
            raise ValueError("estimated_points_per_batch must be positive")
        if maximum_points_per_batch < estimated_points_per_batch:
            raise ValueError("maximum_points_per_batch is below the estimate")
        if min_interval < 0:
            raise ValueError("min_interval cannot be negative")
        self._transport = transport
        self._batch_size = batch_size
        self._point_budget = point_budget
        self._minimum_remaining = minimum_remaining
        self._estimate = estimated_points_per_batch
        self._max_points = maximum_points_per_batch
        self._max_retries = max_retries
        self._min_interval = min_interval
        self._sleep = sleep
        self._monotonic = monotonic
        self._wall_time = wall_time
        self._lock = threading.Lock()
        self._budget_lock = threading.Lock()
        self._last_request: float | None = None
        self._points_spent = 0
        self._known_remaining: int | None = None
        self._known_reset_at: str | None = None

    @property
    def points_spent(self) -> int:
        return self._points_spent

    @property
    def remaining(self) -> int | None:
        return self._known_remaining

    @property
    def batch_size(self) -> int:
        """Maximum lookup count resolved by one atomic GraphQL request."""
        return self._batch_size

    def restore_run_budget(
        self,
        *,
        points_spent: int,
        remaining: int | None,
        reset_at: str | None,
    ) -> None:
        """Restore conservative same-run accounting before journal resume."""
        if points_spent < 0 or (
            remaining is not None and remaining < 0
        ):
            raise ValueError(
                "restored GraphQL budget values cannot be negative"
            )
        with self._budget_lock:
            self._points_spent = max(
                self._points_spent, int(points_spent)
            )
            if remaining is not None:
                self._known_remaining = (
                    int(remaining)
                    if self._known_remaining is None
                    else min(self._known_remaining, int(remaining))
                )
            if reset_at is not None:
                self._known_reset_at = reset_at

    @staticmethod
    def _retry_wait(headers: Mapping[str, str], wall_time: float) -> float:
        value = headers.get("retry-after")
        if value:
            try:
                return min(120.0, max(0.0, float(value)))
            except ValueError:
                pass
        value = headers.get("x-ratelimit-reset")
        if value:
            try:
                return min(120.0, max(0.0, float(value) - wall_time) + 1.0)
            except ValueError:
                pass
        return 60.0

    def _call(
        self,
        query: str,
        variables: Mapping[str, str],
        *,
        deadline_monotonic: float | None = None,
    ) -> _Response:
        with self._lock:
            for attempt in range(self._max_retries + 1):
                now = self._monotonic()
                if (
                    deadline_monotonic is not None
                    and now >= deadline_monotonic
                ):
                    raise GitHubBudgetError("GraphQL wall deadline exhausted")
                if self._last_request is not None:
                    pace = self._min_interval - (now - self._last_request)
                    if pace > 0:
                        if (
                            deadline_monotonic is not None
                            and pace >= deadline_monotonic - now
                        ):
                            raise GitHubBudgetError(
                                "GraphQL pacing would cross wall deadline"
                            )
                        self._sleep(pace)
                self._last_request = self._monotonic()
                try:
                    kwargs = {
                        "query": query,
                        "variables": dict(variables),
                        "deadline_monotonic": deadline_monotonic,
                    }
                    if hasattr(self._transport, "graphql"):
                        call = self._transport.graphql
                    else:
                        call = self._transport
                    try:
                        raw = call(**kwargs)
                    except TypeError as exc:
                        if "deadline_monotonic" not in str(exc):
                            raise
                        kwargs.pop("deadline_monotonic")
                        raw = call(**kwargs)
                    response = _normalize_response(raw)
                except Exception as exc:
                    if attempt < self._max_retries:
                        wait = float(2**attempt)
                        if (
                            deadline_monotonic is not None
                            and wait >= deadline_monotonic - self._monotonic()
                        ):
                            raise GitHubBudgetError(
                                "GraphQL retry would cross wall deadline"
                            ) from exc
                        self._sleep(wait)
                        continue
                    raise GitHubGraphQLError(
                        "GraphQL transport failed after retries (%s)"
                        % type(exc).__name__
                    ) from exc
                if response.status not in (403, 429):
                    if response.status != 200:
                        raise GitHubGraphQLError(
                            "GraphQL returned HTTP %d" % response.status
                        )
                    return response
                if attempt < self._max_retries:
                    wait = self._retry_wait(
                        response.headers, self._wall_time()
                    )
                    if (
                        deadline_monotonic is not None
                        and wait >= deadline_monotonic - self._monotonic()
                    ):
                        raise GitHubBudgetError(
                            "GraphQL retry would cross wall deadline"
                        )
                    self._sleep(wait)
                    continue
                raise GitHubGraphQLError(
                    "GraphQL rate-limit response persisted after retries (HTTP %d)"
                    % response.status
                )
        raise AssertionError("unreachable")

    @staticmethod
    def _query(
        batch: Sequence[RepositoryLookup],
    ) -> tuple[str, dict[str, str], dict[str, RepositoryLookup]]:
        definitions: list[str] = []
        selections: list[str] = []
        variables: dict[str, str] = {}
        aliases: dict[str, RepositoryLookup] = {}
        for index, lookup in enumerate(batch):
            alias = "r%d" % index
            aliases[alias] = lookup
            if lookup.node_id:
                variable = "id%d" % index
                definitions.append("$%s: ID!" % variable)
                variables[variable] = lookup.node_id
                selections.append(
                    "%s: node(id: $%s) { ... on Repository { %s } }"
                    % (alias, variable, _REPOSITORY_FIELDS)
                )
            else:
                owner, name = str(lookup.full_name).split("/", 1)
                owner_variable = "owner%d" % index
                name_variable = "name%d" % index
                definitions.extend(
                    ["$%s: String!" % owner_variable, "$%s: String!" % name_variable]
                )
                variables[owner_variable] = owner
                variables[name_variable] = name
                selections.append(
                    "%s: repository(owner: $%s, name: $%s) { %s }"
                    % (
                        alias,
                        owner_variable,
                        name_variable,
                        _REPOSITORY_FIELDS,
                    )
                )
        operation = "query(%s) { %s rateLimit { cost remaining resetAt } }" % (
            ", ".join(definitions),
            " ".join(selections),
        )
        return operation, variables, aliases

    @staticmethod
    def _partial_errors(
        raw_errors: object, aliases: Mapping[str, RepositoryLookup]
    ) -> tuple[list[GraphQLError], dict[str, list[str]], list[str]]:
        errors: list[GraphQLError] = []
        by_alias: dict[str, list[str]] = {}
        global_errors: list[str] = []
        if raw_errors is None:
            return errors, by_alias, global_errors
        if not isinstance(raw_errors, list):
            raise GitHubGraphQLError("GraphQL errors field is malformed")
        for raw in raw_errors:
            if not isinstance(raw, Mapping) or not isinstance(raw.get("message"), str):
                raise GitHubGraphQLError("GraphQL contains a malformed error")
            message = raw["message"]
            extensions = raw.get("extensions")
            error_type = (
                extensions.get("type")
                if isinstance(extensions, Mapping)
                and isinstance(extensions.get("type"), str)
                else (
                    raw.get("type")
                    if isinstance(raw.get("type"), str)
                    else None
                )
            )
            path = raw.get("path")
            alias = path[0] if isinstance(path, list) and path else None
            lookup = aliases.get(alias) if isinstance(alias, str) else None
            if lookup is None:
                global_errors.append(message)
                errors.append(GraphQLError(message, None, error_type))
            else:
                # GitHub returns an alias-scoped GraphQL NOT_FOUND when a
                # requested repository was deleted, renamed away, or is not
                # publicly visible to this request. That is a terminal
                # non-admission result, not an infrastructure partial error.
                # The null alias is still required below, and no visibility is
                # inferred from credential scope.
                if error_type == "NOT_FOUND":
                    continue
                by_alias.setdefault(alias, []).append(message)
                errors.append(GraphQLError(message, lookup.key, error_type))
        return errors, by_alias, global_errors

    @staticmethod
    def _metadata(
        lookup: RepositoryLookup,
        raw: object,
        errors: Sequence[str],
        *,
        alias_present: bool,
    ) -> RepositoryMetadata:
        base = {
            "request_key": lookup.key,
            "requested_node_id": lookup.node_id,
            "requested_full_name": lookup.full_name,
        }
        if not alias_present:
            return RepositoryMetadata(
                **base,
                node_id=None,
                full_name=None,
                visibility=None,
                is_private=None,
                is_fork=None,
                is_archived=None,
                default_branch=None,
                head_oid=None,
                renamed=False,
                status="partial_error",
                errors=tuple(errors) + ("response omitted repository alias",),
            )
        if raw is None and not errors:
            return RepositoryMetadata(
                **base,
                node_id=None,
                full_name=None,
                visibility=None,
                is_private=None,
                is_fork=None,
                is_archived=None,
                default_branch=None,
                head_oid=None,
                renamed=False,
                status="missing",
            )
        if not isinstance(raw, Mapping):
            return RepositoryMetadata(
                **base,
                node_id=None,
                full_name=None,
                visibility=None,
                is_private=None,
                is_fork=None,
                is_archived=None,
                default_branch=None,
                head_oid=None,
                renamed=False,
                status="partial_error",
                errors=tuple(errors) + ("repository payload is malformed",),
            )
        node_id = raw.get("id")
        full_name = raw.get("nameWithOwner")
        visibility = raw.get("visibility")
        private = raw.get("isPrivate")
        fork = raw.get("isFork")
        archived = raw.get("isArchived")
        disk_usage = raw.get("diskUsage")
        description = raw.get("description")
        stars = raw.get("stargazerCount")
        forks = raw.get("forkCount")
        primary_language = raw.get("primaryLanguage")
        created_at = raw.get("createdAt")
        pushed_at = raw.get("pushedAt")
        malformed: list[str] = list(errors)
        if raw.get("__typename") not in (None, "Repository"):
            malformed.append("node is not a Repository")
        if not isinstance(node_id, str) or not node_id:
            malformed.append("missing repository node ID")
            node_id = None
        if (
            not isinstance(full_name, str)
            or full_name.count("/") != 1
            or any(not part for part in full_name.split("/", 1))
        ):
            malformed.append("missing current repository name")
            full_name = None
        if visibility not in ("PUBLIC", "PRIVATE", "INTERNAL"):
            visibility = None
        if not isinstance(private, bool):
            private = None
        if not isinstance(fork, bool):
            fork = None
            malformed.append("missing fork state")
        if not isinstance(archived, bool):
            archived = None
            malformed.append("missing archive state")
        if (
            disk_usage is not None
            and (
                not isinstance(disk_usage, int)
                or isinstance(disk_usage, bool)
                or disk_usage < 0
            )
        ):
            disk_usage = None
        if not isinstance(description, str):
            description = None
        if not isinstance(stars, int) or isinstance(stars, bool) or stars < 0:
            stars = 0
        if not isinstance(forks, int) or isinstance(forks, bool) or forks < 0:
            forks = 0
        language = (
            primary_language.get("name")
            if isinstance(primary_language, Mapping)
            and isinstance(primary_language.get("name"), str)
            else None
        )
        if not isinstance(created_at, str):
            created_at = None
        if not isinstance(pushed_at, str):
            pushed_at = None

        default = raw.get("defaultBranchRef")
        branch: str | None = None
        head: str | None = None
        empty = default is None
        if default is not None:
            if not isinstance(default, Mapping):
                malformed.append("default branch payload is malformed")
            else:
                branch_value = default.get("name")
                target = default.get("target")
                if isinstance(branch_value, str) and branch_value:
                    branch = branch_value
                else:
                    malformed.append("default branch name is missing")
                oid = target.get("oid") if isinstance(target, Mapping) else None
                if isinstance(oid, str) and _COMMIT_OID.fullmatch(oid):
                    head = oid.lower()
                else:
                    malformed.append(
                        "default branch HEAD is missing or malformed"
                    )

        explicitly_public = visibility == "PUBLIC" and private is False
        explicitly_non_public = private is True or visibility in ("PRIVATE", "INTERNAL")
        if errors or malformed:
            status = "partial_error"
        elif explicitly_non_public:
            status = "private"
        elif not explicitly_public:
            status = "unverified_visibility"
        else:
            status = "empty" if empty else "ok"
        renamed = bool(
            lookup.full_name
            and full_name
            and lookup.full_name.casefold() != full_name.casefold()
        )
        return RepositoryMetadata(
            **base,
            node_id=node_id,
            full_name=full_name,
            visibility=visibility,
            is_private=private,
            is_fork=fork,
            is_archived=archived,
            default_branch=branch,
            head_oid=head,
            renamed=renamed,
            status=status,
            errors=tuple(malformed),
            disk_usage_kb=disk_usage,
            description=description,
            stars=stars,
            forks=forks,
            language=language,
            created_at=created_at,
            pushed_at=pushed_at,
        )

    def resolve(
        self,
        lookups: Iterable[RepositoryLookup] = (),
        *,
        node_ids: Iterable[str] = (),
        names: Iterable[str] = (),
        deadline_monotonic: float | None = None,
    ) -> GraphQLResolution:
        # Budget checks and requests are one serial transaction.  This prevents
        # concurrent callers (or many small sequential resolve calls) from
        # independently spending the same configured reserve.
        with self._budget_lock:
            return self._resolve(
                lookups=lookups,
                node_ids=node_ids,
                names=names,
                deadline_monotonic=deadline_monotonic,
            )

    def _resolve(
        self,
        lookups: Iterable[RepositoryLookup] = (),
        *,
        node_ids: Iterable[str] = (),
        names: Iterable[str] = (),
        deadline_monotonic: float | None = None,
    ) -> GraphQLResolution:
        requested = list(lookups)
        requested.extend(RepositoryLookup(node_id=value) for value in node_ids)
        requested.extend(RepositoryLookup(full_name=value) for value in names)
        unique: list[RepositoryLookup] = []
        seen: set[str] = set()
        for lookup in requested:
            if lookup.key not in seen:
                unique.append(lookup)
                seen.add(lookup.key)
        if not unique:
            return GraphQLResolution(
                (),
                (),
                0,
                0,
                (
                    self._known_remaining
                    if self._known_remaining is not None
                    else self._minimum_remaining
                ),
                self._known_reset_at,
            )

        results: list[RepositoryMetadata] = []
        all_errors: list[GraphQLError] = []
        call_spent = 0
        remaining = self._known_remaining
        reset_at = self._known_reset_at
        request_count = 0
        for offset in range(0, len(unique), self._batch_size):
            if (
                deadline_monotonic is not None
                and self._monotonic() >= deadline_monotonic
            ):
                raise GitHubBudgetError("GraphQL wall deadline exhausted")
            if self._points_spent + self._max_points > self._point_budget:
                raise GitHubBudgetError("GraphQL point budget would be exceeded")
            if (
                remaining is not None
                and remaining - self._max_points < self._minimum_remaining
            ):
                raise GitHubBudgetError("GraphQL remaining-quota reserve would be crossed")
            batch = unique[offset:offset + self._batch_size]
            query, variables, aliases = self._query(batch)
            response = self._call(
                query,
                variables,
                deadline_monotonic=deadline_monotonic,
            )
            if (
                deadline_monotonic is not None
                and self._monotonic() >= deadline_monotonic
            ):
                raise GitHubBudgetError("GraphQL wall deadline exhausted")
            request_count += 1
            payload = response.data
            if not isinstance(payload, Mapping):
                raise GitHubGraphQLError("GraphQL response is not an object")
            data = payload.get("data")
            if not isinstance(data, Mapping):
                raise GitHubGraphQLError("GraphQL response has no data object")
            rate = data.get("rateLimit")
            if not isinstance(rate, Mapping):
                raise GitHubGraphQLError("GraphQL response omitted rateLimit")
            cost = rate.get("cost")
            response_remaining = rate.get("remaining")
            if (
                not isinstance(cost, int)
                or isinstance(cost, bool)
                or cost < 0
                or not isinstance(response_remaining, int)
                or isinstance(response_remaining, bool)
                or response_remaining < 0
            ):
                raise GitHubGraphQLError("GraphQL rateLimit values are malformed")
            call_spent += cost
            self._points_spent += cost
            remaining = response_remaining
            self._known_remaining = remaining
            reset_value = rate.get("resetAt")
            reset_at = reset_value if isinstance(reset_value, str) else None
            self._known_reset_at = reset_at
            if cost > self._max_points:
                raise GitHubBudgetError(
                    "GraphQL batch cost %d exceeds maximum %d"
                    % (cost, self._max_points)
                )
            if self._points_spent > self._point_budget:
                raise GitHubBudgetError("GraphQL point budget was exceeded")
            if remaining < self._minimum_remaining:
                raise GitHubBudgetError(
                    "GraphQL remaining quota %d is below reserve %d"
                    % (remaining, self._minimum_remaining)
                )

            parsed_errors, alias_errors, global_errors = self._partial_errors(
                payload.get("errors"), aliases
            )
            all_errors.extend(parsed_errors)
            for alias, lookup in aliases.items():
                item_errors = list(alias_errors.get(alias, ())) + global_errors
                results.append(
                    self._metadata(
                        lookup,
                        data.get(alias),
                        item_errors,
                        alias_present=alias in data,
                    )
                )

        assert remaining is not None
        return GraphQLResolution(
            repositories=tuple(results),
            errors=tuple(all_errors),
            request_count=request_count,
            points_used=call_spent,
            remaining=remaining,
            reset_at=reset_at,
        )

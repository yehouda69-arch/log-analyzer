import re
import datetime
from typing import Optional, List

from app.schemas import LogAnalysisResponse, Hypothesis, NextStep


def _contains(pattern: str, text: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE) is not None


def _find_first_group(pattern: str, text: str, group: int = 1) -> Optional[str]:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(group) if m else None


def _has_real_timeout(log_text: str) -> bool:
    return _contains(
        r"(timeoutexception|sockettimeoutexception|timed out|request timeout"
        r"|time.?out|\bTIMEOUT\b|\b408\b|\b504\b|gateway timeout|read timed out"
        r"|connection timed out|operation timed out)",
        log_text
    )


def _smart_trim(log_text: str, max_lines: int = 500, context: int = 2) -> str:
    """
    Instead of cutting the log by position, scan the entire log
    and extract only lines that contain important signals + context around them.
    A failure on line 2500/3000 will still be caught.
    """
    lines = log_text.splitlines()

    # Already small enough
    if len(lines) <= max_lines:
        return log_text

    IMPORTANT = re.compile(
        r"(error|fatal|exception|critical|timeout|timed.?out|warn|"
        r"failed|failure|refused|denied|invalid|unauthorized|"
        r"\b408\b|\b500\b|\b502\b|\b503\b|\b504\b|"
        r"stacktrace|stack.?trace|at com\.|at org\.|at java\.|at System\.)",
        re.IGNORECASE
    )

    # Collect important line indices + context
    important_idx = set()
    for i, line in enumerate(lines):
        if IMPORTANT.search(line):
            for j in range(max(0, i - context), min(len(lines), i + context + 1)):
                important_idx.add(j)

    # Nothing found — fallback to first+last
    if not important_idx:
        half = max_lines // 2
        return "\n".join(lines[:half] + [f"... [{len(lines) - max_lines} lines skipped] ..."] + lines[-half:])

    selected = sorted(important_idx)

    # Still too many — keep first max_lines
    if len(selected) > max_lines:
        selected = selected[:max_lines]

    # Build result with gap markers
    result_lines = []
    prev = -1
    for i in selected:
        if prev != -1 and i > prev + 1:
            result_lines.append(f"... [{i - prev - 1} lines skipped] ...")
        result_lines.append(lines[i])
        prev = i

    trimmed = "\n".join(result_lines)
    trimmed += f"\n\n[Smart trim: {len(lines)} total lines → {len(selected)} relevant lines extracted]"
    return trimmed


def _extract_exception_type(log_text: str) -> Optional[str]:
    return _find_first_group(r"(?:System\.)?([A-Za-z]+Exception)\b", log_text, 1)


def _extract_request_exception_type(log_text: str) -> Optional[str]:
    return _find_first_group(
        r"([A-Za-z]+(?:NotFound|BadRequest|Unauthorized|Forbidden|Conflict|Request)"
        r"[A-Za-z]*(?:Exception|Error)?)\b",
        log_text, 1
    )


def _extract_method_hint(log_text: str) -> Optional[str]:
    hook = _find_first_group(r"hook method:\s*([A-Za-z0-9_]+)", log_text, 1)
    if hook:
        return hook
    return _find_first_group(r"\bat\s+[A-Za-z0-9_.]+\.(\w+)\s*\(", log_text, 1)


def _extract_top_frames(log_text: str, limit: int = 3) -> List[str]:
    frames = re.findall(r"\bat\s+([A-Za-z0-9_.]+\.\w+)\s*\(", log_text, flags=re.IGNORECASE)
    return frames[:limit]


def _extract_timestamp(log_text: str) -> Optional[str]:
    """
    Prefer a timestamp that comes from an actual error/failure line —
    not just the first timestamp in the text, which may belong to an
    unrelated INFO line that was only included as context.
    """
    ts_pattern = r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    err_pattern = re.compile(r"error|fail|exception|timeout|critical|fatal|denied|refused|unauthorized", re.IGNORECASE)

    first_ts = None
    for line in log_text.splitlines():
        m = re.search(ts_pattern, line)
        if not m:
            continue
        if first_ts is None:
            first_ts = m.group(1)
        if err_pattern.search(line):
            return m.group(1)

    if first_ts:
        return first_ts

    m = re.search(r'timestamp="(\d{13})"', log_text)
    if m:
        ts = int(m.group(1)) / 1000
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    return None


def _extract_event_id(log_text: str) -> Optional[str]:
    patterns = [
        r'name="EventId"\s+value="([^"]+)"',
        r'(?:EventId|RequestId|CorrelationId|TraceId|request[_-]?id)[=:\s"]+([a-f0-9\-]{8,})',
    ]
    for p in patterns:
        m = re.search(p, log_text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _extract_machine_name(log_text: str) -> Optional[str]:
    patterns = [
        r'name="log4jmachinename"\s+value="([^"]+)"',
        r'(?:machinename|hostname)[=:\s"]+([A-Za-z0-9._-]{3,})',
        # "server" must not be immediately preceded by error/failed/dns context to avoid
        # mistaking a failed lookup target (e.g. "DNS resolution failed host=X") for the analyzing server
        r'(?<!failed )(?<!error )server[=:\s"]+([A-Za-z0-9._-]{3,})',
    ]
    for p in patterns:
        m = re.search(p, log_text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _has_real_401(log_text: str) -> bool:
    """Real 401 HTTP response or Unauthorized exception — NOT health-check warnings."""
    if re.search(r"status[\s_-]?code[:\s\"]*401\b", log_text, re.IGNORECASE):
        return True
    if re.search(r"UnauthorizedAccessException|HttpStatusCode\.Unauthorized\b", log_text, re.IGNORECASE):
        return True
    if re.search(r"\b401\b", log_text):
        if not re.search(r"authorization is missing from headers", log_text, re.IGNORECASE):
            return True
    return False


def _has_method_not_allowed(log_text: str) -> bool:
    """HTTP 405 Method Not Allowed — wrong HTTP verb used against an endpoint."""
    return bool(re.search(
        r"(MethodNotAllowed|\b405\b|does not support http method"
        r"|method not allowed|StatusCode=MethodNotAllowed)",
        log_text, re.IGNORECASE
    ))


def _has_tcp_retry_exhausted(log_text: str) -> bool:
    """TCP connection failed after all retries — socket unreachable."""
    return bool(re.search(
        r"(failed to send.*after \d+ retr"
        r"|connection attempt.*failed due to timeout"
        r"|failed to send string to ip"
        r"|InvalidOperationException.*socket"
        r"|not connected socket"
        r"|unzul.ssig.*socket)",  # covers German: "für nicht verbundene Sockets unzulässig"
        log_text, re.IGNORECASE
    ))


def _extract_repeated_timeout_target(log_text: str):
    """
    Find the most frequently occurring (target, port) pair tied to timeout/connection-failure lines.
    Returns (target, port, count) or None if no repeated target found (need 2+ occurrences).
    """
    matches = re.findall(r"target=([\d.]+)\s+port=(\d+)", log_text, re.IGNORECASE)
    if not matches:
        return None
    counts = {}
    for pair in matches:
        counts[pair] = counts.get(pair, 0) + 1
    (target, port), count = max(counts.items(), key=lambda kv: kv[1])
    if count < 2:
        return None
    return target, port, count


def _extract_repeated_dns_failure(log_text: str):
    """
    Find the most frequently occurring hostname tied to DNS resolution failures.
    Returns (hostname, count) or None.
    """
    matches = re.findall(
        r"dns resolution failed\s+host=([A-Za-z0-9._-]+)",
        log_text, re.IGNORECASE
    )
    if not matches:
        return None
    counts = {}
    for h in matches:
        counts[h] = counts.get(h, 0) + 1
    host, count = max(counts.items(), key=lambda kv: kv[1])
    if count < 2:
        return None
    return host, count


def _count_vpn_disconnects(log_text: str) -> int:
    return len(re.findall(r"vpn tunnel disconnected", log_text, re.IGNORECASE))


def _count_gateway_timeouts(log_text: str) -> int:
    return len(re.findall(r"gateway[_ ]timeout|proxy connection failed", log_text, re.IGNORECASE))



def _severity_from_log(log_text: str) -> int:
    if _contains(
        r"\b503\b|\b502\b|\b500\b|outofmemory|no space left|sslhandshake"
        r"|certificateexpired|too many connections|circuit breaker.*open",
        log_text
    ):
        return 3
    if (
        _has_real_401(log_text)
        or _has_tcp_retry_exhausted(log_text)
        or _contains(r"\b404\b|rate limit|\b429\b|failed to acquire connection", log_text)
        or _has_real_timeout(log_text)
        or _contains(r"(?:system\.)?(?:aggregateexception|nullreferenceexception)\b", log_text)
    ):
        return 2
    if _contains(r"NotFound|BadRequest|RequestException", log_text) or _has_method_not_allowed(log_text):
        return 2
    return 1


def _severity_label(score: int) -> str:
    return {1: "Low", 2: "Medium", 3: "High"}.get(score, "Medium")


def _decode_log(log_text: str) -> str:
    """
    Handle UTF-16 encoded logs. Safe version: never raises UnicodeEncodeError.
    """
    try:
        if log_text.startswith('\xff\xfe') or log_text.startswith('\xfe\xff'):
            raw = log_text.encode('latin-1', errors='replace')
            return raw.decode('utf-16', errors='replace')
        sample = log_text[:200].replace('\r', '').replace('\n', '')
        null_count = sum(1 for c in sample if c == '\x00')
        if len(sample) > 10 and null_count > len(sample) // 4:
            raw = log_text.encode('latin-1', errors='replace')
            return raw.decode('utf-16', errors='replace')
    except Exception:
        pass
    return log_text


def analyze_log(log_text: str) -> LogAnalysisResponse:
    log_text = _decode_log(log_text)
    log_text = _smart_trim(log_text)
    facts: List[str] = []
    contradictions: List[str] = []

    ex_type = _extract_exception_type(log_text)
    req_ex_type = _extract_request_exception_type(log_text)
    method_hint = _extract_method_hint(log_text)
    top_frames = _extract_top_frames(log_text, limit=3)
    timestamp = _extract_timestamp(log_text)
    event_id = _extract_event_id(log_text)
    machine_name = _extract_machine_name(log_text)

    # --- Facts ---
    if timestamp:
        facts.append(f"Failure timestamp: {timestamp}")
    if event_id:
        facts.append(f"Request EventId: {event_id}")
    if machine_name:
        facts.append(f"Server: {machine_name}")
    if req_ex_type and req_ex_type != ex_type:
        facts.append(f"Log contains custom request exception: {req_ex_type}.")
    if ex_type:
        facts.append(f"Log contains exception: {ex_type}.")
    if _contains(r"object reference not set", log_text):
        facts.append("Log contains message: 'Object reference not set to an instance of an object'.")
    if _contains(r"failed to invoke hook method", log_text) and method_hint:
        facts.append(f"Log indicates failing hook method: {method_hint}.")
    if top_frames:
        facts.append("Top stack frames: " + " → ".join(top_frames))
    if _has_real_401(log_text):
        facts.append("Log contains an authentication failure (401/Unauthorized).")
    if _has_method_not_allowed(log_text):
        facts.append("Log contains HTTP 405 MethodNotAllowed — wrong HTTP verb used against endpoint.")
    if _has_tcp_retry_exhausted(log_text):
        facts.append("Log indicates TCP connection failure after all retries exhausted.")
    if _has_real_timeout(log_text):
        facts.append("Log contains an explicit timeout event.")
    if _contains(r"active connections:\s*\d+/\d+", log_text):
        facts.append("Log includes connection pool utilization metrics.")
    if _contains(r"failed to acquire connection|connection from pool|waiting for connection", log_text):
        facts.append("Log indicates connection acquisition failure from pool.")
    if _contains(r"circuit breaker.*open", log_text):
        facts.append("Log indicates Circuit Breaker OPEN state.")
    if _contains(r"too many connections", log_text):
        facts.append("Log includes DB server message: too many connections.")
    if _contains(r"no space left on device", log_text):
        facts.append("Log indicates disk is full (No space left on device).")
    if _contains(r"outofmemoryerror|killed process|heap space", log_text):
        facts.append("Log indicates out-of-memory condition (OOM).")
    if _contains(r"sslhandshake|pkix|certificateexpired", log_text):
        facts.append("Log indicates TLS/Certificate validation failure.")
    if _contains(r"unknownhostexception|name or service not known", log_text):
        facts.append("Log indicates DNS resolution failure.")
    if _contains(r"\b429\b|too many requests|rate limit", log_text):
        facts.append("Log indicates rate limiting (429/Too Many Requests).")

    repeated_target = _extract_repeated_timeout_target(log_text)
    if repeated_target:
        t_host, t_port, t_count = repeated_target
        facts.append(f"Detected {t_count} timeout events targeting {t_host}:{t_port}.")

    repeated_dns = _extract_repeated_dns_failure(log_text)
    if repeated_dns:
        d_host, d_count = repeated_dns
        facts.append(f"Detected {d_count} DNS resolution failures for host '{d_host}'.")

    vpn_count = _count_vpn_disconnects(log_text)
    if vpn_count >= 2:
        facts.append(f"Log shows {vpn_count} VPN tunnel disconnect events (keepalive timeout).")

    gw_count = _count_gateway_timeouts(log_text)
    if gw_count >= 2:
        facts.append(f"Log shows {gw_count} proxy/gateway timeout (504) events.")

    if not facts:
        facts.append("No recognizable failure signature found in provided log snippet.")

    if _contains(r"active connections:\s*100/100", log_text) and _contains(r"active connections:\s*5/100", log_text):
        contradictions.append(
            "Pool drops from 100/100 to 5/100 within the snippet; "
            "suggests transient stall/reset (not a persistent leak)."
        )

    severity_score = _severity_from_log(log_text)
    severity_label = _severity_label(severity_score)

    # --- Routing ---
    # Priority order (highest specificity first):
    # 1. TCP retry exhausted  — most specific network failure
    # 2. HTTP 405             — most specific HTTP error
    # 3. Timeout              — but only when NOT caused by TCP (handled via contradiction)
    # 4. NotFound             — resource missing
    # 5. NullReference        — code bug
    # 6. AggregateException   — wrapper exception
    # 7. 401 Unauthorized     — auth failure
    # 8. No space / OOM / SSL / DNS / 429 / pool — infrastructure failures
    # 9. Unknown

    if _has_tcp_retry_exhausted(log_text):
        ip = _find_first_group(r"ip '([^']+)'", log_text, 1) or              _find_first_group(r"to '([^']+)'", log_text, 1) or "remote host"
        retry_count = _find_first_group(r"after (\d+) retr", log_text, 1) or "multiple"
        primary_failure = f"TCP connection failure to {ip} after {retry_count} retries"
        root_cause = (
            f"Could not establish TCP connection to {ip}. "
            f"All {retry_count} retry attempts failed — the remote host is unreachable or refusing connections."
        )
        hypotheses = [
            Hypothesis(rank=1, description=f"Remote host {ip} is down or unreachable",
                       justification="Connection attempt timed out on every retry"),
            Hypothesis(rank=2, description="Firewall or network policy blocking the port",
                       justification="Socket error 'not connected' can indicate a blocked port"),
            Hypothesis(rank=3, description="Wrong IP/port configured for the destination service",
                       justification="Misconfiguration is a common cause of persistent TCP failures"),
        ]
        next_steps = [
            NextStep(text=f"Verify that {ip} is reachable from this host (ping / telnet / nc).", urgency="high"),
            NextStep(text="Check firewall rules and network ACLs for the target port.", urgency="high"),
            NextStep(text="Confirm the destination IP and port in the service configuration are correct.", urgency="medium"),
        ]
        if _has_real_timeout(log_text):
            contradictions.append(
                "Timeout also appears in log — it is a symptom of the TCP connection failure, not an independent root cause."
            )

    elif _has_method_not_allowed(log_text):
        endpoint = _find_first_group(r"requestUri:([^\s*]+)", log_text, 1) or "the endpoint"
        http_method = _find_first_group(r"(GET|POST|PUT|DELETE|PATCH)\s+-\s+(?:base|full|absolute)", log_text, 1) or "HTTP"
        primary_failure = f"HTTP 405 MethodNotAllowed on {endpoint}"
        root_cause = (
            f"The server rejected the {http_method} request to '{endpoint}' — "
            f"the endpoint does not support this HTTP verb."
        )
        hypotheses = [
            Hypothesis(rank=1, description="Wrong HTTP method used (e.g. POST instead of GET)",
                       justification="405 MethodNotAllowed means the URL exists but the verb is wrong"),
            Hypothesis(rank=2, description="API route changed or versioned differently",
                       justification="Endpoint may have moved and now expects a different verb"),
            Hypothesis(rank=3, description="Client code calling wrong endpoint URL",
                       justification="URL mismatch can cause method conflicts"),
        ]
        next_steps = [
            NextStep(text=f"Check the API documentation for '{endpoint}' and verify the correct HTTP verb (GET/POST/PUT).", urgency="high"),
            NextStep(text="Search for recent API changes or version upgrades that may have altered the expected verb.", urgency="medium"),
            NextStep(text="Add HTTP verb validation in client code to catch mismatches early.", urgency="low"),
        ]

    elif _has_real_timeout(log_text):
        repeated_target = _extract_repeated_timeout_target(log_text)
        repeated_dns = _extract_repeated_dns_failure(log_text)
        vpn_count = _count_vpn_disconnects(log_text)
        gw_count = _count_gateway_timeouts(log_text)

        if repeated_target:
            t_host, t_port, t_count = repeated_target
            primary_failure = f"Repeated connection timeouts to {t_host}:{t_port} ({t_count} occurrences)"

            extra_signals = []
            if repeated_dns:
                d_host, d_count = repeated_dns
                extra_signals.append(f"{d_count} DNS resolution failures for '{d_host}'")
            if gw_count >= 2:
                extra_signals.append(f"{gw_count} proxy/gateway timeout (504) events")
            if vpn_count >= 2:
                extra_signals.append(f"{vpn_count} VPN tunnel disconnects")

            root_cause = (
                f"The destination {t_host}:{t_port} consistently failed to respond within the configured "
                f"timeout, producing {t_count} separate timeout events across the log."
            )
            if extra_signals:
                root_cause += " This coincided with " + ", ".join(extra_signals) + " — consistent with a broader network/connectivity outage rather than an isolated app-level issue."

            hypotheses = [
                Hypothesis(rank=1, description=f"Target {t_host}:{t_port} is down, overloaded, or unreachable",
                           justification=f"{t_count} repeated timeouts all point to the same destination"),
                Hypothesis(rank=2, description="Network path degradation between source and target (latency/packet loss/routing)",
                           justification="Repeated timeouts to one fixed target typically indicate a network path issue rather than application logic"),
                Hypothesis(rank=3, description="Firewall/ACL silently dropping packets to this destination",
                           justification="Silent drops manifest as connection timeouts rather than explicit rejections"),
            ]
            next_steps = [
                NextStep(text=f"Verify {t_host}:{t_port} is up and accepting connections (ping / telnet / nc) from the affected network segment.", urgency="high"),
                NextStep(text="Run continuous ping/traceroute toward the target during the failure window to check for packet loss or routing changes.", urgency="high"),
                NextStep(text="Review firewall/ACL and VPN gateway logs for changes around the incident start time.", urgency="medium"),
            ]
            if repeated_dns:
                contradictions.append(
                    f"DNS resolution failures for '{repeated_dns[0]}' occur alongside the connection timeouts — "
                    f"verify whether this hostname is expected to resolve to {t_host}; if so, the DNS and TCP failures are likely the same incident."
                )
        else:
            primary_failure = "Timeout"
            root_cause = "Operation timed out (explicit timeout evidence present in log)"
            hypotheses = [
                Hypothesis(rank=1, description="DB latency / slow query caused the timeout",
                           justification="Explicit timeout evidence present in log"),
                Hypothesis(rank=2, description="Network stall between services",
                           justification="Timeout can be caused by slow downstream response"),
                Hypothesis(rank=3, description="Thread/connection pool starvation",
                           justification="Pool exhaustion can cause operations to time out waiting"),
            ]
            next_steps = [
                NextStep(text="Identify which exact operation timed out (DB query, HTTP call, pool acquire) using scoped timing logs.", urgency="high"),
                NextStep(text="Check DB slow-query log and network latency metrics around the timestamp.", urgency="high"),
                NextStep(text="Correlate with error rate and latency dashboards to identify the scope of the impact.", urgency="medium"),
            ]
        if _contains(r"(?:system\.)?nullreferenceexception\b", log_text):
            contradictions.append(
                "NullReferenceException also appears in log — likely a secondary failure "
                "caused by the timeout (e.g. null returned on timeout path). Treat Timeout as primary."
            )

    elif req_ex_type and _contains(r"NotFound|notfound", req_ex_type):
        entity = re.sub(r"(NotFound|Request|Exception|Error)", "", req_ex_type, flags=re.IGNORECASE).strip() or "Entity"
        primary_failure = f"{req_ex_type}: {entity} not found"
        root_cause = f"A requested {entity} resource does not exist or could not be located (based on {req_ex_type} in log)."
        hypotheses = [
            Hypothesis(rank=1, description=f"{entity} ID missing or incorrect",
                       justification=f"{req_ex_type} raised — resource lookup returned empty"),
            Hypothesis(rank=2, description=f"{entity} was deleted or never created",
                       justification="Not-found exceptions can indicate data consistency issues"),
            Hypothesis(rank=3, description="Wrong environment/tenant routing",
                       justification="Request may be reaching wrong DB or service instance"),
        ]
        next_steps = [
            NextStep(text=f"Verify the {entity} ID in the request exists in the database.", urgency="high"),
            NextStep(text=f"Check if {entity} was recently deleted, archived, or belongs to a different tenant/environment.", urgency="high"),
            NextStep(text="Add explicit not-found handling and return a clear 404 with resource details to aid debugging.", urgency="medium"),
        ]

    elif _contains(r"(?:system\.)?nullreferenceexception\b", log_text):
        primary_failure = "NullReferenceException"
        root_cause = "NullReferenceException present in log (object reference not set)."
        hypotheses = [
            Hypothesis(rank=1, description="Null object dereference in application code",
                       justification="NullReferenceException present in log"),
            Hypothesis(rank=2, description="Unexpected/invalid input leading to null values",
                       justification="NullReferenceException often triggered by missing fields"),
        ]
        next_steps = [
            NextStep(text="Locate the first NullReferenceException stack trace frame and identify which variable was null.", urgency="high"),
            NextStep(text="Add input validation/guards around the failing code path and log key identifiers (IDs) for reproducibility.", urgency="medium"),
        ]

    elif _contains(r"(?:system\.)?aggregateexception\b", log_text) and ex_type:
        primary_failure = "AggregateException"
        root_cause = "AggregateException present in log (one or more inner exceptions)."
        hypotheses = [
            Hypothesis(rank=1, description="Inner exception is the real root cause",
                       justification="AggregateException indicates inner exceptions"),
            Hypothesis(rank=2, description="Async task failure aggregated at await/wait boundary",
                       justification="AggregateException commonly wraps async failures"),
        ]
        next_steps = [
            NextStep(text="Find the first INNER exception inside AggregateException and treat that as root cause.", urgency="high"),
            NextStep(text="Log the inner exception type/message and first stack frame to speed up triage.", urgency="medium"),
        ]

    elif _has_real_401(log_text):
        primary_failure = "Downstream service rejected request (401 Unauthorized)"
        root_cause = "Missing/invalid Authorization for downstream call (based on 401 evidence in log)"
        hypotheses = [
            Hypothesis(rank=1, description="Authorization header missing or invalid",
                       justification="401/Unauthorized present in log"),
            Hypothesis(rank=2, description="Token expired or rotated",
                       justification="401 can be returned on expired credentials"),
        ]
        next_steps = [
            NextStep(text="Inspect outgoing request headers to downstream service (Authorization present? format correct?).", urgency="high"),
            NextStep(text="Validate credential source (env/secret store) and token expiry/rotation history.", urgency="medium"),
        ]

    elif _contains(r"no space left on device", log_text):
        primary_failure = "Write failed due to disk full"
        root_cause = "No space left on device"
        hypotheses = [Hypothesis(rank=1, description="Disk exhausted on host/container",
                                 justification="'No space left on device' present in log")]
        next_steps = [
            NextStep(text="Free disk space (rotate/delete old logs, clear temp/cache) and re-run failing operation.", urgency="high"),
            NextStep(text="Add disk usage alerting and log retention policy.", urgency="medium"),
        ]

    elif _contains(r"outofmemoryerror|heap space|killed process", log_text):
        primary_failure = "Process ran out of memory (OOM)"
        root_cause = "Memory limit exceeded (heap exhausted / workload too large)"
        hypotheses = [
            Hypothesis(rank=1, description="Heap too small for workload",
                       justification="OutOfMemory/heap space present in log"),
            Hypothesis(rank=2, description="Memory leak",
                       justification="OOM can be caused by gradual growth"),
        ]
        next_steps = [
            NextStep(text="Reduce batch size / payload or increase memory limit temporarily to restore service.", urgency="high"),
            NextStep(text="Enable heap dump / profiling and identify top allocators.", urgency="medium"),
        ]

    elif _contains(r"sslhandshake|pkix|certificateexpired", log_text):
        primary_failure = "TLS handshake failed"
        root_cause = "Certificate validation failure (often expired or untrusted chain)"
        hypotheses = [
            Hypothesis(rank=1, description="Certificate expired",
                       justification="CertificateExpired/NotAfter/PKIX failure patterns"),
            Hypothesis(rank=2, description="Missing intermediate CA",
                       justification="PKIX path validation failed can indicate chain issues"),
        ]
        next_steps = [
            NextStep(text="Check certificate expiry and renew/rotate certs for the target endpoint.", urgency="high"),
            NextStep(text="Verify trust store/intermediate chain configuration on client.", urgency="medium"),
        ]

    elif _contains(r"unknownhostexception|name or service not known", log_text):
        primary_failure = "DNS resolution failed"
        root_cause = "Service hostname cannot be resolved (DNS/service discovery issue)"
        hypotheses = [
            Hypothesis(rank=1, description="DNS outage/misconfig",
                       justification="UnknownHostException present in log"),
            Hypothesis(rank=2, description="Wrong hostname/env config",
                       justification="Common cause is incorrect service URL"),
        ]
        next_steps = [
            NextStep(text="Verify hostname and DNS resolution from the running environment (nslookup/dig).", urgency="high"),
            NextStep(text="Check service discovery / environment config for correct base URL.", urgency="medium"),
        ]

    elif _contains(r"\b429\b|too many requests|rate limit", log_text):
        primary_failure = "Rate limiting (429 Too Many Requests)"
        root_cause = "Traffic exceeded configured quota/limit"
        hypotheses = [
            Hypothesis(rank=1, description="Burst traffic", justification="Rate limit messages present"),
            Hypothesis(rank=2, description="Quota too low", justification="Limits may be mis-sized for current usage"),
        ]
        next_steps = [
            NextStep(text="Add client-side/backoff retry and reduce request rate.", urgency="medium"),
            NextStep(text="Review quota/limit configuration and scaling strategy.", urgency="low"),
        ]

    elif _contains(r"active connections:\s*100/100|failed to acquire connection|waiting for connection", log_text):
        primary_failure = "Connection pool exhaustion"
        root_cause = "No available DB connections in pool (pool saturation / acquire failure)"
        hypotheses = [
            Hypothesis(rank=1, description="Transient DB stall or blocking event holding connections",
                       justification="Pool saturation evidence in log"),
            Hypothesis(rank=2, description="DB server max_connections reached",
                       justification="'too many connections' may appear in log"),
            Hypothesis(rank=3, description="Long-running transactions or leak",
                       justification="Pool saturation can be caused by unreleased connections"),
        ]
        next_steps = [
            NextStep(text="Confirm whether timeout is pool-wait vs DB-call timeout (add scoped timing logs).", urgency="high"),
            NextStep(text="Check DB-side connection counts by client and max_connections.", urgency="high"),
            NextStep(text="Enable pool long-hold/leak detection and log slow queries.", urgency="medium"),
        ]

    else:
        primary_failure = "Unknown"
        root_cause = "Insufficient evidence in provided snippet to determine root cause"
        hypotheses = [Hypothesis(rank=1, description="Need more context",
                                 justification="No clear signature in snippet")]
        next_steps = [
            NextStep(text="Provide a wider time window (±2 minutes) around the failure.", urgency="medium"),
            NextStep(text="Include stack trace / error codes if available.", urgency="low"),
        ]
    unknowns = [
        "Exact component boundaries (client vs server) may be unclear without additional context.",
        "Cannot confirm causality direction without earlier log lines.",
    ]

    return LogAnalysisResponse(
        confirmed_facts=facts,
        primary_failure=primary_failure,
        root_cause=root_cause,
        unknowns=unknowns,
        hypotheses_ranked=hypotheses,
        next_steps=next_steps,
        contradictions=contradictions,
        severity_score=severity_score,
        severity_label=severity_label,
    )

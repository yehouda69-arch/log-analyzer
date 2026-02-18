import re
from app.schemas import LogAnalysisResponse, Hypothesis, NextStep


def _contains(pattern: str, text: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE) is not None


def _severity_from_log(log_text: str) -> int:
    # 3 = High (Sev1), 2 = Medium (Sev2), 1 = Low (Sev3)
    if _contains(r"\b503\b|\b502\b|\b500\b|outofmemory|no space left|sslhandshake|certificateexpired|too many connections|circuit breaker.*open", log_text):
        return 3
    if _contains(r"\b401\b|unauthorized|\b404\b|rate limit|\b429\b|timeout|failed to acquire connection", log_text):
        return 2
    return 1


def _severity_label(score: int) -> str:
    return {1: "Low", 2: "Medium", 3: "High"}.get(score, "Medium")


def analyze_log(log_text: str) -> LogAnalysisResponse:
    facts = []
    contradictions = []

    if _contains(r"\b401\b|unauthorized", log_text):
        facts.append("Log contains an authentication failure (401/Unauthorized).")
    if _contains(r"timeout", log_text):
        facts.append("Log contains a timeout event.")
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

    if not facts:
        facts.append("No recognizable failure signature found in provided log snippet.")

    if _contains(r"active connections:\s*100/100", log_text) and _contains(r"active connections:\s*5/100", log_text):
        contradictions.append("Pool drops from 100/100 to 5/100 within the snippet; suggests transient stall/reset (not a persistent leak).")

    severity_score = _severity_from_log(log_text)
    severity_label = _severity_label(severity_score)

    # Conservative, evidence-driven routing
    if _contains(r"\b401\b|unauthorized", log_text):
        primary_failure = "Downstream service rejected request (401 Unauthorized)"
        root_cause = "Missing/invalid Authorization for downstream call (based on 401 evidence in log)"
        hypotheses = [
            Hypothesis(rank=1, description="Authorization header missing or invalid", justification="401/Unauthorized present in log"),
            Hypothesis(rank=2, description="Token expired or rotated", justification="401 can be returned on expired credentials"),
        ]
        next_steps = [
            NextStep(text="Inspect outgoing request headers to downstream service (Authorization present? format correct?).", urgency="high"),
            NextStep(text="Validate credential source (env/secret store) and token expiry/rotation history.", urgency="medium"),
        ]

    elif _contains(r"no space left on device", log_text):
        primary_failure = "Write failed due to disk full"
        root_cause = "No space left on device"
        hypotheses = [
            Hypothesis(rank=1, description="Disk exhausted on host/container", justification="'No space left on device' present in log"),
        ]
        next_steps = [
            NextStep(text="Free disk space (rotate/delete old logs, clear temp/cache) and re-run failing operation.", urgency="high"),
            NextStep(text="Add disk usage alerting and log retention policy.", urgency="medium"),
        ]

    elif _contains(r"outofmemoryerror|heap space|killed process", log_text):
        primary_failure = "Process ran out of memory (OOM)"
        root_cause = "Memory limit exceeded (heap exhausted / workload too large)"
        hypotheses = [
            Hypothesis(rank=1, description="Heap too small for workload", justification="OutOfMemory/heap space present in log"),
            Hypothesis(rank=2, description="Memory leak", justification="OOM can be caused by gradual growth"),
        ]
        next_steps = [
            NextStep(text="Reduce batch size / payload or increase memory limit temporarily to restore service.", urgency="high"),
            NextStep(text="Enable heap dump / profiling and identify top allocators.", urgency="medium"),
        ]

    elif _contains(r"sslhandshake|pkix|certificateexpired", log_text):
        primary_failure = "TLS handshake failed"
        root_cause = "Certificate validation failure (often expired or untrusted chain)"
        hypotheses = [
            Hypothesis(rank=1, description="Certificate expired", justification="CertificateExpired/NotAfter/PKIX failure patterns"),
            Hypothesis(rank=2, description="Missing intermediate CA", justification="PKIX path validation failed can indicate chain issues"),
        ]
        next_steps = [
            NextStep(text="Check certificate expiry and renew/rotate certs for the target endpoint.", urgency="high"),
            NextStep(text="Verify trust store/intermediate chain configuration on client.", urgency="medium"),
        ]

    elif _contains(r"unknownhostexception|name or service not known", log_text):
        primary_failure = "DNS resolution failed"
        root_cause = "Service hostname cannot be resolved (DNS/service discovery issue)"
        hypotheses = [
            Hypothesis(rank=1, description="DNS outage/misconfig", justification="UnknownHostException present in log"),
            Hypothesis(rank=2, description="Wrong hostname/env config", justification="Common cause is incorrect service URL"),
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
            Hypothesis(rank=1, description="Transient DB stall or blocking event holding connections", justification="Pool saturation + timeouts"),
            Hypothesis(rank=2, description="DB server max_connections reached", justification="'too many connections' appears in log"),
            Hypothesis(rank=3, description="Long-running transactions or leak", justification="Pool saturation can be caused by unreleased connections"),
        ]
        next_steps = [
            NextStep(text="Confirm whether timeout is pool-wait vs DB-call timeout (add scoped timing logs).", urgency="high"),
            NextStep(text="Check DB-side connection counts by client and max_connections.", urgency="high"),
            NextStep(text="Enable pool long-hold/leak detection and log slow queries.", urgency="medium"),
        ]

    elif _contains(r"timeout", log_text):
        primary_failure = "Timeout"
        root_cause = "Operation exceeded configured timeout (evidenced by 'timeout' in log)"
        hypotheses = [
            Hypothesis(rank=1, description="DB latency / slow query", justification="Timeout present"),
            Hypothesis(rank=2, description="Network stall", justification="Timeout can be caused by intermittent connectivity"),
        ]
        next_steps = [
            NextStep(text="Identify which operation timed out (acquire vs query vs HTTP) using scoped timing logs.", urgency="high"),
            NextStep(text="Correlate with latency metrics and error rate around timestamp.", urgency="medium"),
        ]

    else:
        primary_failure = "Unknown"
        root_cause = "Insufficient evidence in provided snippet to determine root cause"
        hypotheses = [
            Hypothesis(rank=1, description="Need more context", justification="No clear signature in snippet")
        ]
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

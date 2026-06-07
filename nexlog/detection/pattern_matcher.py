"""
detection/pattern_matcher.py â€” NexLog Layer 2
Four matcher types, each handling one rule type.
All matchers return (matched: bool, context: dict).

RegexMatcher     â€” single-line, single-field pattern check
ThresholdMatcher â€” stateful, count-based with sliding window
SequenceMatcher  â€” stateful, ordered step matching with min_count + must_follow
CompositeRule    â€” combines multiple sub-matchers with AND/OR logic

Changes from v1:
  - SequenceMatcher._step_matches: handles min_count (repeat a step N times
    before advancing) and must_follow (enforce ordering within window)
  - _entry_matches_filter: added username_contains, hostname_contains,
    severity_in, category_in filter keys
  - CompositeRule: new class â€” fires when a configured combination of
    sub-rules all match (AND) or any match (OR) for the same group key
"""

import re
import sys
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
from models import LogEntry

_MAX_REGEX_PATTERN_CHARS = 6000
_MAX_REGEX_GROUPS = 120
_MAX_REGEX_ALTERNATIONS = 600


def _reject_unsafe_regex(pattern: str) -> None:
    """Reject patterns that are too expensive to compile safely in-process."""
    if len(pattern) > _MAX_REGEX_PATTERN_CHARS:
        raise ValueError(f"Regex pattern too large ({len(pattern)} chars)")
    if pattern.count("(") > _MAX_REGEX_GROUPS:
        raise ValueError(f"Regex pattern has too many groups ({pattern.count('(')})")
    if pattern.count("|") > _MAX_REGEX_ALTERNATIONS:
        raise ValueError(f"Regex pattern has too many alternations ({pattern.count('|')})")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SHARED HELPERS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _get_field(entry: LogEntry, field_name: str) -> Optional[str]:
    """
    Get a field from LogEntry by name. Returns string or None.
    Supports dotted paths into entry.extra: "extra.logon_type_name"
    Converts non-string values to string for regex matching.
    """
    if "." in field_name:
        parts  = field_name.split(".", 1)
        parent = getattr(entry, parts[0], None)
        val    = parent.get(parts[1]) if isinstance(parent, dict) else None
    else:
        val = getattr(entry, field_name, None)

    return str(val) if val is not None else None


def _entry_matches_filter(entry: LogEntry, filter_dict: dict) -> bool:
    """
    Check whether an entry satisfies ALL conditions in a filter dict.
    Used by ThresholdMatcher and CompositeRule as a pre-screen.

    Supported filter keys
    â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    auth_result:          str   â€” "failure" | "success"
    http_status_in:       list  â€” [401, 403, ...]
    http_method:          str   â€” "POST" | "GET" ...
    event_id:             str   â€” "4625"
    process_name_contains: str  â€” substring, case-insensitive
    username_contains:    str   â€” substring on entry.username
    hostname_contains:    str   â€” substring on entry.hostname
    severity_in:          list  â€” ["HIGH", "CRITICAL"]
    category_in:          list  â€” ["auth", "web_attack"]   (Finding category,
                                    rarely needed in YAML but useful in code)
    """
    if not filter_dict:
        return True

    if "auth_result" in filter_dict:
        if entry.auth_result != filter_dict["auth_result"]:
            return False

    if "http_status_in" in filter_dict:
        if entry.http_status not in filter_dict["http_status_in"]:
            return False

    if "http_method" in filter_dict:
        if (entry.http_method or "").upper() != filter_dict["http_method"].upper():
            return False

    if "event_id" in filter_dict:
        if entry.event_id != str(filter_dict["event_id"]):
            return False

    if "process_name_contains" in filter_dict:
        pn = entry.process_name or ""
        if filter_dict["process_name_contains"].lower() not in pn.lower():
            return False

    if "username_contains" in filter_dict:
        un = entry.username or ""
        if filter_dict["username_contains"].lower() not in un.lower():
            return False

    if "hostname_contains" in filter_dict:
        hn = entry.hostname or ""
        if filter_dict["hostname_contains"].lower() not in hn.lower():
            return False

    if "severity_in" in filter_dict:
        sev = getattr(entry, "severity", None) or ""
        if str(sev).upper() not in [s.upper() for s in filter_dict["severity_in"]]:
            return False

    if "category_in" in filter_dict:
        cat = getattr(entry, "category", None) or ""
        if cat not in filter_dict["category_in"]:
            return False

    return True


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# REGEX MATCHER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class RegexMatcher:
    """
    Evaluates a single regex pattern against one LogEntry field.
    Stateless â€” safe to share across threads.

    YAML keys used:
        match_field   required  â€” LogEntry field to test
        pattern       required  â€” regex string
        filter        optional  â€” pre-filter dict (see _entry_matches_filter)
    """

    def __init__(self, match_field: str, pattern: str,
                 filter_dict: dict | None = None):
        self.match_field = match_field
        self.filter_dict = filter_dict or {}
        # Strip whitespace inserted by YAML block-scalar folding, then compile
        clean = re.sub(r'\s+', '', pattern)
        _reject_unsafe_regex(clean)
        self.compiled = re.compile(clean, re.IGNORECASE)

    def match(self, entry: LogEntry) -> tuple[bool, dict]:
        """Returns (matched, context_dict)."""
        if not _entry_matches_filter(entry, self.filter_dict):
            return False, {}

        value = _get_field(entry, self.match_field)
        if value is None:
            return False, {}

        m = self.compiled.search(value)
        if not m:
            return False, {}

        context: dict = {
            "matched_field": self.match_field,
            "matched_value": value[:500],
            "matched_text":  m.group(0)[:200],
        }
        if m.groupdict():
            context["captures"] = m.groupdict()

        return True, context


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# THRESHOLD MATCHER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ThresholdMatcher:
    """
    Fires when a group (e.g. source_ip) accumulates >= count matching
    entries within a sliding time window.

    Stateful â€” one instance per rule, persists across LogEntry calls.
    Uses a per-group deque for O(1) window expiry.

    YAML keys used:
        group_by        required  â€” LogEntry field to group by
        count           required  â€” minimum events to trigger
        window_secs     required  â€” sliding window size in seconds
        filter          optional  â€” pre-filter dict
        count_distinct  optional  â€” count unique values of this field
                                    instead of raw event count
    """

    def __init__(self, group_by: str, count: int, window_secs: int,
                 filter_dict: dict | None = None,
                 count_distinct: str | None = None):
        self.group_by       = group_by
        self.threshold      = count
        self.window         = timedelta(seconds=window_secs)
        self.filter_dict    = filter_dict or {}
        self.count_distinct = count_distinct
        # group_key â†’ deque[(timestamp, LogEntry)]
        self._windows: dict[str, deque] = defaultdict(deque)

    def match(self, entry: LogEntry) -> tuple[bool, dict]:
        if not _entry_matches_filter(entry, self.filter_dict):
            return False, {}

        group_val = _get_field(entry, self.group_by)
        if not group_val:
            return False, {}

        ts           = entry.timestamp or datetime.now(timezone.utc)
        window_start = ts - self.window
        dq           = self._windows[group_val]

        # Expire entries outside the window
        while dq and dq[0][0] < window_start:
            dq.popleft()

        dq.append((ts, entry))

        # Count raw events or distinct field values
        if self.count_distinct:
            distinct_vals = {
                _get_field(e, self.count_distinct)
                for _, e in dq
                if _get_field(e, self.count_distinct) is not None
            }
            current_count = len(distinct_vals)
        else:
            current_count = len(dq)

        if current_count >= self.threshold:
            evidence = [e.raw_line for _, e in list(dq)[-10:]]
            context  = {
                "group_key":      group_val,
                "group_field":    self.group_by,
                "event_count":    current_count,
                "threshold":      self.threshold,
                "window_secs":    int(self.window.total_seconds()),
                "evidence_lines": evidence,
                "first_event":    dq[0][0].isoformat() if dq else None,
                "last_event":     ts.isoformat(),
            }
            # Reset after firing â€” prevents re-triggering on every subsequent line
            self._windows[group_val] = deque()
            return True, context

        return False, {}

    def reset(self) -> None:
        """Clear all state. Call between log files in the same session."""
        self._windows.clear()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SEQUENCE MATCHER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class SequenceMatcher:
    """
    Detects ordered sequences of events from the same group key.
    Advances through steps in order; resets if window expires.

    Supports per-step options (from YAML):
        match_field     â€” LogEntry field to check
        value           â€” exact equality
        value_contains  â€” case-insensitive substring
        match_field2    â€” second field (AND condition)
        value2          â€” exact equality for match_field2
        min_count       â€” how many times this step must match before advancing
                          (default 1). AUTH-002 uses this: 1+ failures first.
        must_follow     â€” bool; if True, this step must come AFTER the previous
                          step (enforces ordering). Default True â€” ordering is
                          already inherent but this documents the intent.
        window_secs     â€” per-step maximum time allowed (not yet enforced
                          beyond the global window; reserved for future use)

    YAML keys at the rule level:
        group_by        â€” field to group state by
        window_secs     â€” global window for the entire sequence
    """

    def __init__(self, steps: list[dict], group_by: str, window_secs: int):
        self.steps    = steps
        self.group_by = group_by
        self.window   = timedelta(seconds=window_secs)
        # group_key â†’ {"step_idx": int, "step_count": int,
        #               "first_ts": datetime, "evidence": list[str]}
        self._state: dict[str, dict] = {}

    def match(self, entry: LogEntry) -> tuple[bool, dict]:
        group_val = _get_field(entry, self.group_by)
        if not group_val:
            return False, {}

        ts = entry.timestamp or datetime.now(timezone.utc)
        st = self._state.setdefault(group_val, {
            "step_idx":   0,
            "step_count": 0,
            "first_ts":   ts,
            "evidence":   [],
        })

        # Reset if global window expired
        if ts - st["first_ts"] > self.window:
            st["step_idx"]   = 0
            st["step_count"] = 0
            st["first_ts"]   = ts
            st["evidence"]   = []

        current_step = self.steps[st["step_idx"]]
        min_count    = int(current_step.get("min_count", 1))

        if self._step_matches(entry, current_step):
            st["evidence"].append(entry.raw_line)
            st["step_count"] += 1

            # Advance only after min_count matches for this step
            if st["step_count"] >= min_count:
                st["step_idx"]   += 1
                st["step_count"]  = 0

                # All steps satisfied â†’ sequence complete
                if st["step_idx"] >= len(self.steps):
                    context = {
                        "group_key":         group_val,
                        "steps_matched":     len(self.steps),
                        "evidence_lines":    st["evidence"][-10:],
                        "sequence_duration": str(ts - st["first_ts"]),
                    }
                    self._state[group_val] = {
                        "step_idx":   0,
                        "step_count": 0,
                        "first_ts":   ts,
                        "evidence":   [],
                    }
                    return True, context

        return False, {}

    def _step_matches(self, entry: LogEntry, step: dict) -> bool:
        """
        Check whether an entry satisfies a single step definition.

        Handled keys:
            match_field + value           â€” exact equality
            match_field + value_contains  â€” substring (case-insensitive)
            match_field2 + value2         â€” second AND condition (exact)
            min_count / must_follow / window_secs â€” consumed by match(), not here
        """
        f1 = step.get("match_field")
        v1 = step.get("value")
        vc = step.get("value_contains")
        f2 = step.get("match_field2")
        v2 = step.get("value2")

        if f1:
            actual = _get_field(entry, f1) or ""
            if v1 is not None and actual != v1:
                return False
            if vc is not None and vc.lower() not in actual.lower():
                return False

        if f2 and v2:
            actual2 = _get_field(entry, f2)
            if actual2 != v2:
                return False

        return True

    def reset(self) -> None:
        """Clear all state. Call between log files."""
        self._state.clear()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# COMPOSITE RULE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class CompositeRule:
    """
    Combines multiple sub-matchers with AND or OR logic, all evaluated
    against the same group key (e.g. source_ip).

    This is what enterprise SIEMs call "correlation rules":
      - AND: ALL sub-matchers must have fired for the same group key
             within the composite window to trigger.
      - OR:  ANY sub-matcher firing triggers immediately (less useful
             but included for completeness).

    Architecture note:
      CompositeRule is NOT instantiated from YAML directly â€” it is
      assembled by rule_engine.py when it finds type: composite rules.
      Sub-matchers are passed in as already-constructed instances.

    Example (assembled by rule_engine for a cross-category correlation):
        sub1 = ThresholdMatcher("source_ip", 5, 60,
                                filter_dict={"auth_result": "failure"})
        sub2 = RegexMatcher("http_uri_decoded",
                            r"(?i)(upload|shell)")
        composite = CompositeRule(
            sub_matchers=[sub1, sub2],
            group_by="source_ip",
            window_secs=300,
            logic="AND",
        )

    When CompositeRule.match(entry) is called:
      - Each sub-matcher is evaluated.
      - Firing sub-matchers set a flag for the group key.
      - When all flagged (AND) or any flagged (OR), the composite fires.
    """

    def __init__(
        self,
        sub_matchers: list,
        group_by:     str,
        window_secs:  int,
        logic:        str = "AND",   # "AND" | "OR"
        name:         str = "CompositeRule",
    ):
        self.sub_matchers = sub_matchers
        self.group_by     = group_by
        self.window       = timedelta(seconds=window_secs)
        self.logic        = logic.upper()
        self.name         = name
        # group_key â†’ {matcher_idx: (fired_ts, context)}
        self._fired: dict[str, dict] = defaultdict(dict)

    def match(self, entry: LogEntry) -> tuple[bool, dict]:
        group_val = _get_field(entry, self.group_by)
        if not group_val:
            return False, {}

        ts           = entry.timestamp or datetime.now(timezone.utc)
        group_state  = self._fired[group_val]
        window_start = ts - self.window

        # Expire stale fired flags
        expired = [idx for idx, (fired_ts, _) in group_state.items()
                   if fired_ts < window_start]
        for idx in expired:
            del group_state[idx]

        # Evaluate each sub-matcher
        any_new_fire = False
        for idx, sub in enumerate(self.sub_matchers):
            if idx in group_state:
                continue   # already fired within window
            try:
                fired, ctx = sub.match(entry)
            except Exception:
                continue
            if fired:
                group_state[idx] = (ts, ctx)
                any_new_fire = True

        # Check completion condition
        n_matchers = len(self.sub_matchers)
        n_fired    = len(group_state)

        should_trigger = (
            (self.logic == "AND" and n_fired == n_matchers) or
            (self.logic == "OR"  and n_fired >= 1 and any_new_fire)
        )

        if should_trigger:
            all_contexts = {idx: ctx for idx, (_, ctx) in group_state.items()}
            context = {
                "group_key":        group_val,
                "logic":            self.logic,
                "sub_matchers_fired": n_fired,
                "sub_contexts":     all_contexts,
                "composite_name":   self.name,
                "evidence_lines":   [
                    line
                    for _, ctx in group_state.values()
                    for line in ctx.get("evidence_lines", [])
                ][-10:],
            }
            # Reset after firing
            self._fired[group_val] = {}
            return True, context

        return False, {}

    def reset(self) -> None:
        """Clear all state. Call between log files."""
        self._fired.clear()
        for sub in self.sub_matchers:
            if hasattr(sub, "reset"):
                sub.reset()

from __future__ import annotations


def report(stats: dict[str, float], duration_sec: float) -> None:
    """Print the end-of-run summary to stdout."""
    from .metrics import summarize

    print(summarize(stats, duration_sec))

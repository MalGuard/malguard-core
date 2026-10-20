"""Run the verified publisher with bounded, credential-free HTTP diagnostics.

The workflow must verify/unpack the source and install its locked dependencies
before invoking this entrypoint. Publication and signing remain in that source.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path
from urllib.error import HTTPError


def main() -> int:
    publisher = (
        Path(__file__).resolve().parents[2]
        / "cleanroom-source/packaging/online/publish_feed.py"
    )
    try:
        runpy.run_path(str(publisher), run_name="__main__")
    except HTTPError as error:
        # Do not log the exception, URL, reason, headers or response body: an
        # upstream error may echo credentials or contain workflow commands.
        if error.code in (401, 403):
            message = (
                "MalwareBazaar metadata access denied (HTTP 401/403). "
                "Check the repository's MALGUARD_ABUSECH_AUTH_KEY configuration "
                "and the provider's key/account access policy without exposing "
                "credentials. This response alone does not identify the cause."
            )
        elif error.code == 429:
            message = (
                "MalwareBazaar metadata request rate-limited (HTTP 429). "
                "Check the provider's usage policy before retrying."
            )
        elif 500 <= error.code <= 599:
            message = "MalwareBazaar metadata service returned an HTTP 5xx error."
        else:
            message = "MalwareBazaar metadata request failed with an HTTP error."
        print(
            "::error title=Authenticated metadata fetch failed::"
            + message
            + " No successful publication is reported; downstream publication "
            "must remain blocked.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

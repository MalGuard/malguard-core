# Release topology recovery

This change intentionally makes no runtime or product behavior change.

MalGuard release workflows require the current `main` tip to be a non-forced pull-request **merge commit** with at least two parents. PR #65 was squash-merged, so its code is present on `main`, but the release provenance gate correctly refused to build artifacts from that single-parent commit.

This PR exists only to restore the required merge topology. It must be merged with the normal **merge commit** method, not squash or rebase.

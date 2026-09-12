# Behavioral Sandbox Design Baseline

This is the target architecture for a future defensive analysis sandbox. It is not present in the 0.9.0-rc.1 scanner core.

## Core requirements

- Disposable analysis environment for every sample.
- No access to the user's real personal files or credentials.
- Restricted filesystem and process privileges.
- Network disabled by default or routed through controlled simulation/observation.
- Hard execution time, CPU and memory budgets.
- Process-tree termination and environment destruction at the end of analysis.
- Behavioral event logging sufficient to attribute actions to the analyzed mod/file.
- No trust in sample-provided names, paths, sizes or metadata.

## Result model

Behavioral observations should feed the existing verdict model rather than directly declaring a sample safe. Unknown or incomplete execution must remain distinguishable from clean behavior.

## Safety boundary

Sandbox escape resistance and host isolation are release blockers. The commercial product must use operating-system isolation primitives appropriate to the target platform rather than treating a browser Worker as a malware execution sandbox.

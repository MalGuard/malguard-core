'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const cpp = fs.readFileSync(path.join(__dirname, '..', 'native', 'appcontainer-isolation-probe', 'MalGuardAppContainerIsolationProbe.cpp'), 'utf8');
const cmake = fs.readFileSync(path.join(__dirname, '..', 'native', 'appcontainer-isolation-probe', 'CMakeLists.txt'), 'utf8');

assert.match(cpp, /CreateAppContainerProfile/);
assert.match(cpp, /PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES/);
assert.match(cpp, /CapabilityCount\s*=\s*0/);
assert.match(cpp, /PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY/);
assert.match(cpp, /PROCESS_CREATION_CHILD_PROCESS_RESTRICTED/);
assert.match(cpp, /JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE/);
assert.match(cpp, /JOB_OBJECT_LIMIT_PROCESS_MEMORY/);
assert.match(cpp, /JOB_OBJECT_LIMIT_ACTIVE_PROCESS/);
assert.match(cpp, /JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP/);
assert.match(cpp, /TokenIsAppContainer/);
assert.match(cpp, /hostWriteDenied/);
assert.match(cpp, /networkDenied/);
assert.match(cpp, /childProcessBlocked/);
assert.match(cpp, /DeleteAppContainerProfile/);
assert.doesNotMatch(cpp, /URLDownloadToFile|WinHttpOpen|InternetOpen|powershell\.exe/i, 'native probe must remain synthetic-only and self-contained');
assert.match(cmake, /Userenv/);
assert.match(cmake, /Ws2_32/);

console.log('✓ AppContainer native sandbox source: no-capability token, filesystem/network/child-process isolation and Job Object limits present');

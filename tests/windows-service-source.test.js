'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'native', 'windows-service', 'MalGuardService.cpp'), 'utf8');
const cmake = fs.readFileSync(path.join(root, 'native', 'windows-service', 'CMakeLists.txt'), 'utf8');
const server = fs.readFileSync(path.join(root, 'desktop-app', 'server.js'), 'utf8');

assert.match(source, /StartServiceCtrlDispatcherW/);
assert.match(source, /RegisterServiceCtrlHandlerExW/);
assert.match(source, /SERVICE_CONTROL_STOP/);
assert.match(source, /SERVICE_CONTROL_SHUTDOWN/);
assert.match(source, /JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE/);
assert.match(source, /CREATE_NO_WINDOW/);
assert.match(source, /CREATE_SUSPENDED/);
assert.match(source, /ResumeThread/);
assert.ok(source.indexOf('AssignProcessToJobObject') < source.indexOf('ResumeThread'), 'service child must be assigned to the Job before ResumeThread');
assert.doesNotMatch(source, /^#define\s+(?:UNICODE|_UNICODE)\b/m, 'UNICODE macros must be defined by CMake only to keep /WX builds warning-free');
assert.match(source, /SERVICE_AUTO_START/);
assert.match(source, /SERVICE_CONFIG_DELAYED_AUTO_START_INFO/);
assert.match(source, /exits\.size\(\) >= 5/);
assert.doesNotMatch(source, /ShellExecute/i);
assert.doesNotMatch(source, /WinExec\s*\(/i);
assert.match(cmake, /\/guard:cf/);
assert.match(cmake, /\/DYNAMICBASE/);
assert.match(cmake, /\/NXCOMPAT/);
assert.match(server, /MALGUARD_SERVICE_MODE/);
assert.match(server, /SERVICE_GUARD_START_FAILED/);

console.log('✓ Windows Service source: SCM lifecycle, kill-on-close child containment, crash-loop budget and hardening flags PASS');

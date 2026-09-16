'use strict';

const Base = require('./telemetry-validator-base.js');

function validateTelemetry(raw, expectedSessionId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return Base.validateTelemetry(raw, expectedSessionId);
  }
  if (raw.networkPolicy !== 'disabled-by-processcontainer') {
    return Base.validateTelemetry(raw, expectedSessionId);
  }
  const normalized = { ...raw, networkPolicy: 'disabled-by-wsb' };
  const result = Base.validateTelemetry(normalized, expectedSessionId);
  if (result && result.ok === true && result.telemetry) {
    result.telemetry.networkPolicy = 'disabled-by-processcontainer';
  }
  return result;
}

module.exports = {
  ...Base,
  validateTelemetry,
};

'use strict';

const Base = require('./sandbox-controller-base.js');
const { GtaProcessContainerRunner } = require('./gta-processcontainer-runner.js');

class SandboxController extends Base.SandboxController {
  constructor(options = {}) {
    super(options);
    this.processContainerRunner = options.processContainerRunner || new GtaProcessContainerRunner({
      gameRoot: process.env.MALGUARD_GTA_V_ROOT || '',
      gameExecutable: process.env.MALGUARD_GTA_V_EXE || 'GTA5.exe',
    });
  }

  async analyzeUntrustedSample(samplePath) {
    const preflight = await this.preflightSample(samplePath);
    if (!preflight.ok) {
      return {
        ok: false,
        sandboxVersion: Base.SANDBOX_VERSION,
        verdict: 'inconclusive',
        code: preflight.code,
        preflight,
        sandboxLaunched: false,
        sampleExecutionStarted: false,
      };
    }

    const [support, gameConfiguration] = await Promise.all([
      this.processContainerRunner.supportStatus(),
      this.processContainerRunner.configurationStatus(),
    ]);

    if (support.ok === true && gameConfiguration.ok === true) {
      const result = await this.processContainerRunner.analyze(preflight.path, preflight);
      if (result && typeof result === 'object') {
        result.preflight = preflight;
        result.gameContext = result.gameContext || gameConfiguration;
        const execution = result.telemetry && result.telemetry.execution;
        result.sampleExecutionStarted = !!(execution && execution.started === true);
        result.sandboxLaunched = result.ok === true && result.sampleExecutionStarted === true &&
          result.gameContext && result.gameContext.realGame === true && result.gameContext.proven === true;
        result.isolation = 'processcontainer';
        result.requiresNestedVirtualization = false;
        if (result.ok === true && result.sandboxLaunched !== true) {
          return {
            ok: false,
            sandboxVersion: Base.SANDBOX_VERSION,
            verdict: 'inconclusive',
            code: 'GTA_PROCESSCONTAINER_EXECUTION_NOT_PROVEN',
            preflight,
            backend: support,
            gameContext: result.gameContext,
            isolation: 'processcontainer',
            requiresNestedVirtualization: false,
            sandboxLaunched: false,
            sampleExecutionStarted: false,
          };
        }
      }
      return result;
    }

    const fallback = await super.analyzeUntrustedSample(samplePath);
    if (fallback && typeof fallback === 'object') {
      fallback.processContainer = {
        support: { ...support, sdk: undefined },
        gameConfiguration,
        fallbackUsed: true,
      };
    }
    return fallback;
  }
}

module.exports = {
  ...Base,
  SandboxController,
};

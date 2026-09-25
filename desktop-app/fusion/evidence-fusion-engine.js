'use strict';

const FUSION_ENGINE_VERSION = '1.0.0';
const VALID_VERDICTS = new Set(['safe', 'suspicious', 'malicious', 'inconclusive']);

function normalizeVerdict(value) {
  return VALID_VERDICTS.has(value) ? value : 'inconclusive';
}

function sandboxExecutionProven(result) {
  return !!(result
    && result.ok === true
    && result.sandboxLaunched === true
    && result.sampleExecutionStarted === true);
}

function localStaticCoverage(localResult) {
  const issues = [];
  const layers = [];
  if (!localResult || typeof localResult !== 'object') {
    return { fullCoverage: false, issues: ['scanner_result_missing'], primaryAnalyzersCompleted: 0, layers };
  }

  if (localResult.hardeningError) issues.push('hardening_error');
  if (!localResult.sourceIdentity || localResult.sourceIdentity.revalidated !== true) {
    issues.push('source_identity_not_revalidated');
  }

  let primaryAnalyzersCompleted = 0;

  const engine = localResult.engineResult;
  if (engine && typeof engine === 'object') {
    const engineIssues = [];
    if (engine.rulesStatus && engine.rulesStatus !== 'official') engineIssues.push('rules_not_official');
    if (engine.peValid !== true) engineIssues.push('pe_not_fully_validated');
    issues.push(...engineIssues);
    if (engineIssues.length === 0) primaryAnalyzersCompleted++;
    layers.push({ name: 'pe_engine', status: engineIssues.length ? 'degraded' : 'complete' });
  }

  const script = localResult.scriptAnalysis;
  if (script && typeof script === 'object') {
    const scriptIssues = [];
    if (script.supported !== true) scriptIssues.push('script_analysis_unsupported');
    if (script.errorCode) scriptIssues.push('script_analysis_error');
    issues.push(...scriptIssues);
    if (scriptIssues.length === 0) primaryAnalyzersCompleted++;
    layers.push({ name: 'script_analyzer', status: scriptIssues.length ? 'degraded' : 'complete' });
  }

  const archive = localResult.archiveInspection;
  if (archive && typeof archive === 'object') {
    const archiveIssues = [];
    if (archive.inspectionSucceeded !== true) archiveIssues.push('archive_analysis_incomplete');
    if (archive.inspectionStatus === 'completed_partial_timeout') archiveIssues.push('archive_analysis_partial_timeout');
    issues.push(...archiveIssues);
    if (archiveIssues.length === 0) primaryAnalyzersCompleted++;
    layers.push({ name: 'archive_analyzer', status: archiveIssues.length ? 'degraded' : 'complete' });
  }

  const multi = localResult.multiEngine;
  if (multi && multi.coverage && multi.coverage.requiredForSafe === true) {
    const complete = multi.coverage.complete === true;
    if (!complete) issues.push('independent_multi_engine_incomplete');
    else primaryAnalyzersCompleted++;
    layers.push({ name: 'independent_multi_engine', status: complete ? 'complete' : 'degraded' });
  }

  if (primaryAnalyzersCompleted === 0) issues.push('no_primary_static_analyzer_completed');

  return {
    fullCoverage: issues.length === 0,
    issues: [...new Set(issues)],
    primaryAnalyzersCompleted,
    layers,
  };
}

function fuseEvidence({
  localResult = null,
  sandboxResult = null,
  cloudInspectionResult = null,
  aiEvidenceResult = null,
  model = 'standard',
} = {}) {
  const localVerdict = normalizeVerdict(localResult && localResult.finalVerdict);
  const coverage = localStaticCoverage(localResult);
  const intel = localResult && localResult.threatIntel && typeof localResult.threatIntel === 'object'
    ? localResult.threatIntel
    : { status: 'disabled' };

  const behavioralProven = sandboxExecutionProven(sandboxResult);
  const behavioralVerdict = behavioralProven
    ? normalizeVerdict(sandboxResult && sandboxResult.verdict)
    : 'inconclusive';

  const intelMalicious = intel.status === 'known_malicious';
  const intelSuspicious = intel.status === 'known_suspicious' || intel.status === 'suspicious';
  const multi = localResult && localResult.multiEngine && typeof localResult.multiEngine === 'object' ? localResult.multiEngine : null;
  const multiVerdict = normalizeVerdict(multi && multi.verdict);
  const multiMalicious = multiVerdict === 'malicious';
  const multiSuspicious = multiVerdict === 'suspicious';

  let verdict = 'inconclusive';
  let basis = 'insufficient_evidence';

  if (intelMalicious || multiMalicious || localVerdict === 'malicious' || (behavioralProven && behavioralVerdict === 'malicious')) {
    verdict = 'malicious';
    basis = intelMalicious ? 'exact_reputation_or_threat_intel' : multiMalicious ? 'independent_engine_malicious_evidence' : behavioralVerdict === 'malicious' ? 'behavioral_malicious_evidence' : 'local_malicious_evidence';
  } else if (intelSuspicious || multiSuspicious || localVerdict === 'suspicious' || (behavioralProven && behavioralVerdict === 'suspicious')) {
    verdict = 'suspicious';
    basis = behavioralVerdict === 'suspicious' ? 'behavioral_suspicious_evidence' : multiSuspicious ? 'independent_engine_suspicious_evidence' : 'local_or_reputation_suspicious_evidence';
  } else if (behavioralProven && behavioralVerdict === 'safe' && sandboxResult.releaseGrade === true) {
    verdict = 'safe';
    basis = 'behavioral_release_grade';
  } else if (localVerdict === 'safe' && coverage.fullCoverage) {
    verdict = 'safe';
    basis = 'full_static_fusion_coverage';
  }

  const riskScore = verdict === 'malicious'
    ? (intelMalicious ? 100 : 95)
    : verdict === 'suspicious'
      ? 72
      : verdict === 'safe'
        ? (basis === 'behavioral_release_grade' ? 5 : 12)
        : 50;

  const confidence = verdict === 'inconclusive'
    ? 'low'
    : (intelMalicious || basis === 'behavioral_release_grade' || behavioralVerdict === 'malicious')
      ? 'high'
      : 'medium';

  const limitations = [];
  if (!behavioralProven) limitations.push('behavioral_execution_evidence_unavailable');
  if (['disabled', 'unavailable', 'unknown'].includes(String(intel.status || 'unknown'))) {
    limitations.push('threat_intelligence_not_confirmatory');
  }
  if (!coverage.fullCoverage && verdict !== 'malicious') limitations.push(...coverage.issues);

  return {
    schemaVersion: '1.0',
    engineVersion: FUSION_ENGINE_VERSION,
    model,
    verdict,
    riskScore,
    confidence,
    basis,
    assurance: basis === 'behavioral_release_grade'
      ? 'behavioral_verified'
      : verdict === 'safe'
        ? 'static_fusion_complete'
        : coverage.fullCoverage
          ? 'static_fusion_complete'
          : 'partial',
    coverage,
    layers: {
      localScanner: { verdict: localVerdict, present: !!localResult },
      threatIntelligence: { status: String(intel.status || 'unknown'), maliciousExactMatch: intelMalicious },
      independentMultiEngine: {
        present: !!multi,
        verdict: multiVerdict,
        coverageComplete: !!(multi && multi.coverage && multi.coverage.complete === true),
        requiredForSafe: !!(multi && multi.coverage && multi.coverage.requiredForSafe === true),
        engines: multi && multi.engines ? {
          yaraX: multi.engines.yaraX && { status: multi.engines.yaraX.status, verdict: multi.engines.yaraX.verdict },
          capa: multi.engines.capa && { status: multi.engines.capa.status, verdict: multi.engines.capa.verdict },
          floss: multi.engines.floss && { status: multi.engines.floss.status, verdict: multi.engines.floss.verdict },
          defender: multi.engines.defender && { status: multi.engines.defender.status, verdict: multi.engines.defender.verdict },
        } : {},
      },
      behavioral: {
        proven: behavioralProven,
        verdict: behavioralVerdict,
        releaseGrade: !!(behavioralProven && sandboxResult && sandboxResult.releaseGrade === true),
      },
      cloudInspection: {
        present: !!cloudInspectionResult,
        completed: !!(cloudInspectionResult && cloudInspectionResult.ok === true),
        verdictAuthority: false,
      },
      ai: {
        present: !!aiEvidenceResult,
        status: aiEvidenceResult && aiEvidenceResult.status || 'not_available',
        risk: aiEvidenceResult && aiEvidenceResult.risk || null,
        advisoryOnly: true,
        canPromoteSafe: false,
      },
    },
    safeClaim: {
      allowed: verdict === 'safe',
      bounded: true,
      absoluteGuarantee: false,
      basis: verdict === 'safe' ? basis : null,
    },
    limitations: [...new Set(limitations)],
  };
}

module.exports = {
  FUSION_ENGINE_VERSION,
  normalizeVerdict,
  sandboxExecutionProven,
  localStaticCoverage,
  fuseEvidence,
};

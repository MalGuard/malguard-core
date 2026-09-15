/* ============================================================
   MalGuard — multilayer.js  (Pro capability layer)
   ------------------------------------------------------------
   این فایل یک «موتور اسکن» جدید نیست. هیچ PE-parser، هیچ ارزیاب
   قانون، و هیچ منطق تشخیص جدیدی در این فایل وجود ندارد.

   ورودی این لایه همیشه خروجیِ از‌پیش‌محاسبه‌شدهٔ Engine v2.2.0
   (window.scanFile) است — یعنی همان آبجکتی که حالت رایگان (FREE)
   هم مستقیماً به کاربر نشان می‌دهد. این لایه فقط آن آبجکت را
   می‌خواند، آن را از چند «دروازهٔ» (Gate) مستقل عبور می‌دهد،
   ناسازگاری‌های احتمالی بین دروازه‌ها را شناسایی می‌کند، و یک
   حکم نهایی قابل‌توضیح تولید می‌کند.

   قانون امنیتی مطلق (بخش ۱۲ مشخصات): یک نتیجهٔ اعتبارِ «مخرب
   تأییدشده» از Engine هرگز توسط این لایه تنزل داده نمی‌شود، حتی
   اگر همهٔ دروازه‌های دیگر PASS بدهند. هیچ رأی‌گیری اکثریتی
   (majority voting) در این فایل وجود ندارد.

   این لایه هرگز:
     - فایل اسکن‌شده را اجرا/لود/کامپایل نمی‌کند
     - بایت‌های فایل را دوباره نمی‌خواند یا دوباره تجزیه نمی‌کند
     - rules.json را دوباره بارگذاری/ارزیابی نمی‌کند
     - چیزی را به سروری ارسال نمی‌کند
   ============================================================ */

'use strict';

const MULTILAYER_VERSION = '1.0.0';

/* ------------------------------------------------------------
   اولویت شواهد (Evidence Priority) — بخش ۱۲: شواهد اعتبارِ
   تأییدشده هرگز توسط دروازه‌های دیگر قابل نادیده‌گرفتن نیست.
   ------------------------------------------------------------ */
const EVIDENCE_PRIORITY = Object.freeze({
  CONFIRMED_REPUTATION: 100, // هش دقیقاً در URLhaus مخرب شناخته شده
  STATIC_MALICIOUS: 80,      // امتیازدهی/کف‌ریسک موتور به malicious رسیده (بدون اعتبار)
  STATIC_SUSPICIOUS: 50,
  STRUCTURAL_ANOMALY: 30,
  INFORMATIONAL: 10,
});

const GATE_RESULTS = Object.freeze({
  PASS: 'PASS',
  FAIL: 'FAIL',
  SUSPICIOUS: 'SUSPICIOUS',
  INCONCLUSIVE: 'INCONCLUSIVE',
});

const FINAL_VERDICTS = Object.freeze({
  SAFE: 'safe',
  SUSPICIOUS: 'suspicious',
  MALICIOUS: 'malicious',
  INCONCLUSIVE: 'inconclusive',
});

/* ============================================================
   EvidenceGraph — ساختار داده‌ای قابل‌ماشین‌خوانی از خروجی Engine
   (بخش «Evidence Graph» مشخصات). فقط بازآرایی داده‌های موجود در
   engineResult است؛ هیچ دادهٔ جدیدی «کشف» نمی‌کند.
   ============================================================ */
const EvidenceGraph = {
  /**
   * از evidence[] خروجی Engine + فیلدهای reputation/pe یک گراف
   * دسته‌بندی‌شده می‌سازد. خروجی صرفاً برای نمایش/تحلیل بعدی در UI
   * است و در تصمیم‌گیری مستقیماً استفاده نمی‌شود (تصمیم‌گیری از
   * روی خودِ engineResult و نتایج Gateها انجام می‌شود).
   */
  build(engineResult) {
    const nodes = { engine: {}, reputation: {}, structural: {} };
    const evidence = Array.isArray(engineResult.evidence) ? engineResult.evidence : [];

    for (const item of evidence) {
      const category = item.category || 'uncategorized';
      if (category === 'known_malicious_hash') {
        nodes.reputation[item.rule || 'reputation'] = {
          severity: item.severity, confidence: item.confidence,
          weight: item.weight, description: item.explanation,
          items: item.evidence || [],
        };
        continue;
      }
      if (category === 'metadata_anomaly') {
        nodes.structural[item.rule || category] = {
          severity: item.severity, confidence: item.confidence,
          weight: item.weight, description: item.explanation,
          items: item.evidence || [],
        };
        continue;
      }
      if (!nodes.engine[category]) nodes.engine[category] = [];
      nodes.engine[category].push({
        rule: item.rule, severity: item.severity, confidence: item.confidence,
        weight: item.weight, description: item.explanation, items: item.evidence || [],
      });
    }

    return {
      source: 'EngineV2_2_0',
      engineVersion: engineResult.engineVersion,
      rulesVersion: engineResult.rulesVersion,
      rulesStatus: engineResult.rulesStatus,
      nodes,
      riskFloorApplied: engineResult.riskFloorApplied || null,
    };
  },
};

/* ============================================================
   GateManager — شش دروازهٔ مستقل، هرکدام فقط از فیلدهای موجود در
   engineResult استفاده می‌کنند (بخش «Security Gates» مشخصات).
   ============================================================ */
const GateManager = {
  /** ۱) دروازهٔ صحت فایل: آیا هویت فایل (هش) قابل‌استقرار بود؟ */
  fileIntegrityGate(engineResult) {
    if (engineResult.errorCode === 'SCAN_ERROR') {
      return { gate: 'file_integrity', result: GATE_RESULTS.INCONCLUSIVE,
        reason: 'اسکن با خطای غیرمنتظره متوقف شد؛ هویت فایل قابل تأیید نیست.' };
    }
    if (typeof engineResult.hash === 'string' && engineResult.hash.length === 64) {
      return { gate: 'file_integrity', result: GATE_RESULTS.PASS,
        reason: 'هش SHA-256 با موفقیت محاسبه شد.' };
    }
    return { gate: 'file_integrity', result: GATE_RESULTS.SUSPICIOUS,
      reason: 'هش SHA-256 محاسبه نشد (مثلاً به‌دلیل نبود Web Crypto).' };
  },

  /** ۲) دروازهٔ ساختار PE: آیا Engine توانست ساختار PE را کامل تجزیه کند؟ */
  peStructureGate(engineResult) {
    if (engineResult.peValid === true) {
      return { gate: 'pe_structure', result: GATE_RESULTS.PASS, reason: 'ساختار PE کاملاً معتبر و قابل‌تجزیه بود.' };
    }
    if (engineResult.peValid === false) {
      // بدشکل بودن PE به‌تنهایی هرگز به‌معنای مخرب بودن نیست — طبق
      // طراحی Engine v2.2.0 (بخش ۲۷ مشخصات نسخهٔ قبلی). این دروازه
      // فقط می‌گوید تحلیل ساختاری محدود شد، نه اینکه فایل بد است.
      return { gate: 'pe_structure', result: GATE_RESULTS.SUSPICIOUS,
        reason: 'ساختار PE به‌طور کامل قابل‌اعتبارسنجی نبود (errorCode: ' + (engineResult.peErrorCode || engineResult.errorCode || 'نامشخص') + ').' };
    }
    return { gate: 'pe_structure', result: GATE_RESULTS.INCONCLUSIVE, reason: 'وضعیت اعتبار PE نامشخص است.' };
  },

  /**
   * ۳) دروازهٔ شواهد قانون‌محور: بر اساس شواهد ایستا (بدون احتساب
   * شاهد اعتبار/reputation که دروازهٔ جداگانهٔ خودش را دارد).
   */
  ruleEvidenceGate(engineResult) {
    const evidence = Array.isArray(engineResult.evidence) ? engineResult.evidence : [];
    const staticEvidence = evidence.filter(e => e.category !== 'known_malicious_hash');
    const hasHighOrCritical = staticEvidence.some(e => e.severity === 'high' || e.severity === 'critical');
    const reputationIsOnlyDriver = evidence.some(e => e.category === 'known_malicious_hash') && !hasHighOrCritical;

    // اگر verdict موتور malicious شده باشد اما تنها دلیلش reputation
    // بوده (نه شواهد ایستا)، این دروازه را PASS/SUSPICIOUS می‌گذاریم
    // چون قضاوت دربارهٔ reputation کار دروازهٔ بعدی است، نه این یکی.
    if (engineResult.verdict === 'malicious' && !reputationIsOnlyDriver) {
      return { gate: 'rule_evidence', result: GATE_RESULTS.FAIL,
        reason: 'شواهد ایستای وزن‌دار (رشته/ایمپورت/ترکیب رفتاری) به آستانهٔ مخرب رسید.' };
    }
    if (engineResult.verdict === 'suspicious' || hasHighOrCritical) {
      return { gate: 'rule_evidence', result: GATE_RESULTS.SUSPICIOUS,
        reason: 'شواهد ایستا در سطح مشکوک یا بالاتر یافت شد.' };
    }
    if (staticEvidence.length === 0) {
      return { gate: 'rule_evidence', result: GATE_RESULTS.PASS, reason: 'هیچ شاهد ایستای قابل‌توجهی یافت نشد.' };
    }
    return { gate: 'rule_evidence', result: GATE_RESULTS.PASS, reason: 'شواهد ایستای یافت‌شده در سطح پایین/اطلاعاتی بودند.' };
  },

  /** ۴) دروازهٔ اعتبار (Reputation): بالاترین اولویت در تصمیم‌گیری نهایی. */
  reputationGate(engineResult) {
    const blacklistEvidence = (engineResult.evidence || []).find(e => e.rule === 'URLHAUS-BLACKLIST');
    if (blacklistEvidence) {
      return { gate: 'reputation', result: GATE_RESULTS.FAIL,
        reason: 'هش این فایل در پایگاه دادهٔ URLhaus به‌عنوان مخرب ثبت شده است.',
        priority: EVIDENCE_PRIORITY.CONFIRMED_REPUTATION };
    }
    if (engineResult.reputationStatus === 'not_found') {
      return { gate: 'reputation', result: GATE_RESULTS.PASS, reason: 'هش فایل در پایگاه دادهٔ اعتبار شناخته‌شده نیست.' };
    }
    if (engineResult.reputationStatus === 'unavailable' || engineResult.reputationStatus === 'not_checked') {
      return { gate: 'reputation', result: GATE_RESULTS.INCONCLUSIVE,
        reason: 'بررسی اعتبار آنلاین در دسترس نبود؛ این دروازه نظری نمی‌دهد (نه تأیید و نه رد).' };
    }
    return { gate: 'reputation', result: GATE_RESULTS.INCONCLUSIVE, reason: 'وضعیت اعتبار نامشخص است.' };
  },

  /**
   * ۵) دروازهٔ همبستگی رفتار ایستا: آیا موتور یک «ترکیب» مستقل و
   * از‌پیش‌تعریف‌شده از چند شاهد را شناسایی کرده (risk-floor)؟
   */
  staticCorrelationGate(engineResult) {
    if (engineResult.riskFloorApplied) {
      if (engineResult.verdict === 'malicious') {
        return { gate: 'static_correlation', result: GATE_RESULTS.FAIL,
          reason: 'ترکیب مستقلی از چند شاهد رفتاری قوی (کف ریسک: ' + engineResult.riskFloorApplied + ') شناسایی شد.' };
      }
      return { gate: 'static_correlation', result: GATE_RESULTS.SUSPICIOUS,
        reason: 'ترکیب شاهد رفتاری (کف ریسک: ' + engineResult.riskFloorApplied + ') حکم را حداقل به مشکوک ارتقا داد.' };
    }
    return { gate: 'static_correlation', result: GATE_RESULTS.PASS, reason: 'هیچ ترکیب رفتاری از‌پیش‌تعریف‌شده‌ای فعال نشد.' };
  },

  /**
   * ۶) دروازهٔ ناهنجاری/عدم‌قطعیت: کیفیت خودِ اسکن (اطمینان موتور و
   * وضعیت مجموعهٔ قوانین استفاده‌شده) را می‌سنجد، نه محتوای فایل را.
   */
  anomalyUncertaintyGate(engineResult) {
    if (engineResult.rulesStatus && engineResult.rulesStatus !== 'official') {
      return { gate: 'anomaly_uncertainty', result: GATE_RESULTS.INCONCLUSIVE,
        reason: 'این اسکن با مجموعه‌قوانین رسمی انجام نشد (rulesStatus: ' + engineResult.rulesStatus + ')؛ پوشش تشخیص ممکن است ناقص باشد.' };
    }
    if (engineResult.confidence === 'low' && engineResult.verdict !== 'safe') {
      // اطمینان پایین در کنار یک حکم safe عادی است (چون اصلاً شاهدی
      // برای اندازه‌گیری اطمینان وجود ندارد) — این نشانهٔ ناهنجاری
      // نیست. اما اطمینان پایین در کنار یک حکم suspicious/malicious
      // یعنی خودِ Engine هم به قضاوتش کاملاً مطمئن نیست.
      return { gate: 'anomaly_uncertainty', result: GATE_RESULTS.SUSPICIOUS,
        reason: 'سطح اطمینان موتور به یک حکم غیرایمن پایین است.' };
    }
    return { gate: 'anomaly_uncertainty', result: GATE_RESULTS.PASS, reason: 'اطمینان موتور و وضعیت قوانین در سطح قابل‌قبول است.' };
  },

  /** اجرای هر شش دروازه و بازگرداندن آرایهٔ نتایج. */
  runAll(engineResult) {
    return [
      this.fileIntegrityGate(engineResult),
      this.peStructureGate(engineResult),
      this.ruleEvidenceGate(engineResult),
      this.reputationGate(engineResult),
      this.staticCorrelationGate(engineResult),
      this.anomalyUncertaintyGate(engineResult),
    ];
  },
};

/* ============================================================
   ConflictDetector — ناسازگاری بین دروازه‌ها را شناسایی می‌کند.
   FAIL دروازهٔ اعتبار هرگز به‌عنوان «تعارض» با PASSهای دیگر در
   نظر گرفته نمی‌شود؛ طبق بخش ۱۲، اولویت مطلق دارد و رأی‌گیری
   اکثریتی هرگز استفاده نمی‌شود.
   ============================================================ */
const ConflictDetector = {
  detect(gateResults) {
    const reputationGate = gateResults.find(g => g.gate === 'reputation');
    const reputationConfirmedMalicious = reputationGate && reputationGate.result === GATE_RESULTS.FAIL;

    if (reputationConfirmedMalicious) {
      // این یک «تعارض» نیست — این اولویت شاهد است. صراحتاً ثبت می‌کنیم
      // که رد شده و توسط reputation override می‌شود.
      return {
        hasConflict: false,
        conflicts: [],
        resolution: 'reputation_priority_override',
        note: 'دروازهٔ اعتبار FAIL داده؛ سایر دروازه‌ها صرف‌نظر از نتیجه‌شان نمی‌توانند این حکم را تنزل دهند.',
      };
    }

    const distinctResults = new Set(gateResults.map(g => g.result));
    // اگر همهٔ دروازه‌ها هم‌رأی باشند (یا فقط شامل PASS/INCONCLUSIVE
    // بدون FAIL/SUSPICIOUS باشند)، تعارض معناداری وجود ندارد.
    const hasFail = gateResults.some(g => g.result === GATE_RESULTS.FAIL);
    const hasSuspicious = gateResults.some(g => g.result === GATE_RESULTS.SUSPICIOUS);
    const hasInconclusive = gateResults.some(g => g.result === GATE_RESULTS.INCONCLUSIVE);
    const hasPass = gateResults.some(g => g.result === GATE_RESULTS.PASS);

    if (hasFail && (hasPass || hasSuspicious)) {
      return {
        hasConflict: true,
        conflicts: gateResults.filter(g => g.result === GATE_RESULTS.FAIL || g.result === GATE_RESULTS.PASS),
        resolution: 'evidence_priority_recheck',
        note: 'حداقل یک دروازه FAIL داده در حالی که دروازه‌های دیگر PASS/SUSPICIOUS داده‌اند. طبق اولویت شواهد، FAIL برنده می‌شود، اما جهت شفافیت به‌عنوان تعارض ثبت می‌شود.',
      };
    }

    if (!hasFail && hasSuspicious && hasInconclusive) {
      return {
        hasConflict: true,
        conflicts: gateResults.filter(g => g.result === GATE_RESULTS.SUSPICIOUS || g.result === GATE_RESULTS.INCONCLUSIVE),
        resolution: 'recheck_required',
        note: 'ترکیبی از SUSPICIOUS و INCONCLUSIVE بدون هیچ FAIL قطعی‌ای وجود دارد؛ نیازمند بازبینی قطعی است.',
      };
    }

    return { hasConflict: false, conflicts: [], resolution: 'none', note: 'دروازه‌ها سازگار بودند.' };
  },
};

/* ============================================================
   RecheckManager — یک بازبینی «قطعی» (deterministic) روی همان
   نتیجهٔ از‌پیش‌محاسبه‌شدهٔ Engine. این هرگز فایل را دوباره
   نمی‌خواند، دوباره تجزیه نمی‌کند، یا دوباره اجرا نمی‌کند — فقط
   قوانین تصمیم‌گیری را یک‌بار دیگر و با احتیاط بیشتر روی همان
   داده اعمال می‌کند.
   ============================================================ */
const RecheckManager = {
  /**
   * اگر تعارض «recheck_required» باشد، تلاش می‌کند با نگاه دقیق‌تر
   * به شدت (severity) و اطمینان (confidence) شواهد ایستا تصمیم
   * بگیرد. اگر باز هم روشن نبود، صادقانه INCONCLUSIVE برمی‌گرداند.
   */
  recheck(engineResult, gateResults, conflict) {
    if (conflict.resolution !== 'recheck_required') {
      return { performed: false, outcome: null, note: 'بازبینی لازم نبود.' };
    }

    const staticEvidence = (engineResult.evidence || []).filter(e => e.category !== 'known_malicious_hash');
    const highConfidenceHighSeverity = staticEvidence.filter(
      e => e.confidence === 'high' && (e.severity === 'high' || e.severity === 'critical')
    );

    if (highConfidenceHighSeverity.length >= 1 && engineResult.confidence !== 'low') {
      return {
        performed: true,
        outcome: 'lean_suspicious',
        note: 'حداقل یک شاهد با شدت بالا و اطمینان بالا یافت شد؛ بازبینی به‌سمت SUSPICIOUS متمایل می‌شود.',
      };
    }

    return {
      performed: true,
      outcome: 'unresolved',
      note: 'پس از بازبینی، شواهد به‌اندازهٔ کافی روشن/سازگار نبودند تا با اطمینان بین ایمن و مشکوک تمایز داده شود.',
    };
  },
};

/* ============================================================
   DecisionCoordinator — تصمیم نهایی را طبق اولویت شواهد (نه
   رأی‌گیری اکثریتی) تعیین می‌کند.
   ============================================================ */
const DecisionCoordinator = {
  decide(engineResult, gateResults, conflict, recheckOutcome) {
    const reputationGate = gateResults.find(g => g.gate === 'reputation');
    const ruleEvidenceGate = gateResults.find(g => g.gate === 'rule_evidence');
    const correlationGate = gateResults.find(g => g.gate === 'static_correlation');

    // اولویت ۱ (مطلق): اعتبار تأییدشدهٔ مخرب — بخش ۱۲ مشخصات.
    if (reputationGate.result === GATE_RESULTS.FAIL) {
      return { verdict: FINAL_VERDICTS.MALICIOUS, primaryReason: 'reputation_confirmed', decidedBy: 'reputation_gate' };
    }

    // اولویت ۲: شواهد ایستا/ترکیبی به‌خودی‌خود به مخرب رسیده‌اند.
    if (ruleEvidenceGate.result === GATE_RESULTS.FAIL || correlationGate.result === GATE_RESULTS.FAIL) {
      return { verdict: FINAL_VERDICTS.MALICIOUS, primaryReason: 'static_evidence_threshold', decidedBy: 'rule_evidence_or_correlation_gate' };
    }

    // اولویت ۳: تعارض حل‌نشده بین دروازه‌ها -> صادقانه INCONCLUSIVE.
    if (conflict.hasConflict && conflict.resolution === 'recheck_required') {
      if (recheckOutcome && recheckOutcome.outcome === 'lean_suspicious') {
        return { verdict: FINAL_VERDICTS.SUSPICIOUS, primaryReason: 'recheck_resolved_suspicious', decidedBy: 'recheck_manager' };
      }
      return { verdict: FINAL_VERDICTS.INCONCLUSIVE, primaryReason: 'unresolved_gate_conflict', decidedBy: 'conflict_detector' };
    }

    // اولویت ۴: هر نوع سیگنال مشکوک (بدون FAIL قطعی).
    const anySuspicious = gateResults.some(g => g.result === GATE_RESULTS.SUSPICIOUS);
    if (anySuspicious || engineResult.verdict === 'suspicious') {
      return { verdict: FINAL_VERDICTS.SUSPICIOUS, primaryReason: 'suspicious_signal_present', decidedBy: 'gate_manager' };
    }

    // اولویت ۵: اگر پایهٔ Engine خودش safe نیست ولی تا اینجا به هیچ
    // مسیر بالا نخورد (حالت غیرمنتظره)، برای احتیاط INCONCLUSIVE.
    if (engineResult.verdict !== 'safe') {
      return { verdict: FINAL_VERDICTS.INCONCLUSIVE, primaryReason: 'unexpected_engine_verdict_mismatch', decidedBy: 'decision_coordinator_safety_net' };
    }

    // اولویت ۶: اگر پوشش قوانین استفاده‌شده رسمی/کامل نبوده (fallback
    // یا incompatible)، حتی وقتی هیچ دروازه‌ای FAIL/SUSPICIOUS ندهد،
    // ادعای «امن» را با اطمینان کامل مطرح نمی‌کنیم — چون خودِ ابزار
    // تشخیصِ ناقص را داشته. صادقانه INCONCLUSIVE برمی‌گردانیم.
    const anomalyGate = gateResults.find(g => g.gate === 'anomaly_uncertainty');
    if (anomalyGate && anomalyGate.result === GATE_RESULTS.INCONCLUSIVE) {
      return { verdict: FINAL_VERDICTS.INCONCLUSIVE, primaryReason: 'degraded_rules_coverage', decidedBy: 'anomaly_uncertainty_gate' };
    }

    return { verdict: FINAL_VERDICTS.SAFE, primaryReason: 'all_gates_clear', decidedBy: 'gate_manager' };
  },
};

/* ============================================================
   MultiLayerSecurity — نقطهٔ ورود عمومی لایهٔ Pro.
   ============================================================ */
const MultiLayerSecurity = {
  version: MULTILAYER_VERSION,

  /**
   * engineResult: همان آبجکتی که window.scanFile(file) برمی‌گرداند
   * (بدون هیچ تغییری). این تابع هرگز فایل را دوباره لمس نمی‌کند.
   */
  analyze(engineResult) {
    if (!engineResult || typeof engineResult !== 'object') {
      throw new Error('MultiLayerSecurity.analyze requires a valid Engine v2.2.0 result object');
    }

    const gateResults = GateManager.runAll(engineResult);
    const conflict = ConflictDetector.detect(gateResults);
    const recheckOutcome = RecheckManager.recheck(engineResult, gateResults, conflict);
    const decision = DecisionCoordinator.decide(engineResult, gateResults, conflict, recheckOutcome);
    const evidenceGraph = EvidenceGraph.build(engineResult);

    return {
      // نتیجهٔ اصلی Engine بدون هیچ تغییری، برای شفافیت کامل حفظ می‌شود.
      engineResult,
      mode: 'pro',
      multiLayerVersion: MULTILAYER_VERSION,
      finalVerdict: decision.verdict,
      decision,
      gates: gateResults,
      conflict,
      recheck: recheckOutcome,
      evidenceGraph,
    };
  },
};

window.MultiLayerSecurity = MultiLayerSecurity;
window.GateManager = GateManager;
window.ConflictDetector = ConflictDetector;
window.RecheckManager = RecheckManager;
window.DecisionCoordinator = DecisionCoordinator;
window.EvidenceGraph = EvidenceGraph;

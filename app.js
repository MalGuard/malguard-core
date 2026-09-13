/* ============================================================
   MalGuard — app.js  (integration layer v1.4.0)
   ------------------------------------------------------------
   این فایل خودش موتور تشخیص بدافزار یا Rules-engine نیست. فقط جریان
   FREE / PRO را میان مؤلفه‌های موجود هماهنگ می‌کند.

     FREE  → Engine v2.2.0

     PRO   → GtaModDetector
               ├─ ENGINE → Engine → MultiLayerSecurity
               ├─ ARCHIVE_INSPECTION
               │    → ArchiveInspector
               │    → برای ZIPهای واجد شرایط: ArchiveEntryReader
               │    → هر پلاگین .asi/.dll استخراج‌شده: Engine → MultiLayer
               │    → هر اسکریپت .lua/.cs استخراج‌شده: ScriptAnalyzer
               │    → تجمیع محافظه‌کارانهٔ نتیجهٔ کل بسته
               ├─ SCRIPT (.lua/.cs) → ScriptAnalyzer v1.0.0
               ├─ REJECT → خارج از محدوده
               └─ INCONCLUSIVE → فعلاً لایهٔ تحلیل ایمن ندارد

   اصل مهم: هیچ ورودی اجرا/لود/کامپایل نمی‌شود. مسیر آرشیو فقط روی ZIP
   و فقط روی targetDescriptorهای صریح ArchiveInspector کار می‌کند. مسیر Script
   نیز فقط تحلیل ایستا انجام می‌دهد و هرگز کد کاربر را اجرا/کامپایل نمی‌کند.
   ============================================================ */

'use strict';

const APP_INTEGRATION_VERSION = '1.5.1';

// ArchiveEntryReader برای هر target کل ZIP را مستقل بازاعتبارسنجی می‌کند.
// بنابراین تعداد هدف‌ها عمداً محدود است تا یک آرشیو خصمانه نتواند هزینهٔ
// زمانی/حافظه را به شکل نامحدود ضرب کند. اگر از سقف عبور کنیم نتیجه SAFE
// تولید نمی‌کنیم؛ به‌صورت صادقانه INCONCLUSIVE برمی‌گردیم.

function runtimeContractStatus(mode) {
  const c = window.MalGuardContract;
  if (!c || typeof c !== 'object' || !c.expectedModules || !Array.isArray(c.verdicts)) {
    return { ok: false, code: 'runtime_contract_missing' };
  }
  const requiredChecks = [
    ['engine', window.MalGuardEngine && window.MalGuardEngine.version],
    ['appIntegration', APP_INTEGRATION_VERSION],
  ];
  if (mode === 'pro') requiredChecks.push(['gtaModDetector', window.GtaModDetector && window.GtaModDetector.version]);
  for (const [name, actual] of requiredChecks) {
    if (!actual || c.expectedModules[name] !== actual) {
      return { ok: false, code: 'runtime_module_version_mismatch', module: name, expected: c.expectedModules[name] || null, actual: actual || null };
    }
  }
  // Secondary analyzers may be absent in a damaged/partial build; each route already
  // fails closed when its module is missing. But if a secondary module is present,
  // its version must match the immutable runtime contract before it can be trusted.
  if (mode === 'pro') {
    const optionalChecks = [
      ['multiLayer', window.MultiLayerSecurity && window.MultiLayerSecurity.version],
      ['archiveInspector', window.ArchiveInspector && window.ArchiveInspector.version],
      ['archiveEntryReader', window.ArchiveEntryReader && window.ArchiveEntryReader.version],
      ['scriptAnalyzer', window.ScriptAnalyzer && window.ScriptAnalyzer.version]
    ];
    for (const [name, actual] of optionalChecks) {
      if (actual && c.expectedModules[name] !== actual) {
        return { ok: false, code: 'runtime_module_version_mismatch', module: name, expected: c.expectedModules[name] || null, actual };
      }
    }
  }
  return { ok: true };
}

function runtimeFailureResult(mode, status) {
  return finalizeTopLevelResult({
    appIntegrationVersion: APP_INTEGRATION_VERSION,
    mode,
    finalVerdict: 'inconclusive',
    engineResult: null,
    hardeningError: status && status.code ? status.code : 'runtime_attestation_failed',
    note: 'یکپارچگی/نسخهٔ مؤلفه‌های Runtime تأیید نشد؛ برای جلوگیری از SAFE ناقص، اسکن متوقف شد.',
    runtimeAttestation: status || { ok: false },
  }, mode);
}

function validateEngineResultForIntegration(engineResult) {
  const c = window.MalGuardContract;
  if (!engineResult || typeof engineResult !== 'object') return { ok: false, code: 'engine_result_missing' };
  if (!c || !c.expectedModules || engineResult.engineVersion !== c.expectedModules.engine) {
    return { ok: false, code: 'engine_result_version_mismatch' };
  }
  if (!['safe','suspicious','malicious','invalid'].includes(engineResult.verdict)) {
    return { ok: false, code: 'engine_result_verdict_invalid' };
  }
  if (!['official','fallback','incompatible'].includes(engineResult.rulesStatus)) {
    return { ok: false, code: 'engine_result_rules_status_invalid' };
  }
  if (engineResult.verdict !== 'invalid' && !/^[a-f0-9]{64}$/.test(String(engineResult.hash || ''))) {
    return { ok: false, code: 'engine_result_hash_invalid' };
  }
  return { ok: true };
}

const ARCHIVE_PIPELINE_LIMITS = Object.freeze({
  MAX_PLUGIN_TARGETS: 4,
  MAX_SCRIPT_TARGETS: 8,
  MAX_TOTAL_PLUGIN_UNCOMPRESSED: 64 * 1024 * 1024,
  MAX_TOTAL_SCRIPT_UNCOMPRESSED: 16 * 1024 * 1024,
  MAX_PIPELINE_TIME_MS: 25000,
});

/**
 * scanFileWithMode(file, mode)
 *   mode: "free" | "pro"
 */
async function scanFileWithMode(file, mode) {
  if (mode !== 'free' && mode !== 'pro') {
    const err = new Error('Mode must be free or pro.');
    err.code = 'INVALID_MODE';
    throw err;
  }
  const normalizedMode = mode;
  let result;

  const runtimeStatus = runtimeContractStatus(normalizedMode);
  if (!runtimeStatus.ok) return runtimeFailureResult(normalizedMode, runtimeStatus);

  if (normalizedMode === 'free') {
    const engineResult = await window.scanFile(file);
    const engineStatus = validateEngineResultForIntegration(engineResult);
    if (!engineStatus.ok) {
      return runtimeFailureResult(normalizedMode, engineStatus);
    }
    const degradedRules = engineResult && engineResult.rulesStatus && engineResult.rulesStatus !== 'official';
    const freeVerdict = degradedRules && engineResult.verdict === 'safe' ? 'inconclusive' : engineResult.verdict;
    result = {
      appIntegrationVersion: APP_INTEGRATION_VERSION,
      mode: 'free',
      finalVerdict: freeVerdict,
      engineResult,
      hardeningError: degradedRules && engineResult.verdict === 'safe' ? 'degraded_rules_coverage' : undefined,
      note: degradedRules && engineResult.verdict === 'safe'
        ? 'مجموعه‌قوانین رسمی کامل در دسترس نبود؛ نتیجهٔ SAFE موتور به INCONCLUSIVE کاهش داده شد.'
        : undefined,
    };
    return finalizeTopLevelResult(result, normalizedMode);
  }

  // ================= حالت PRO =================
  if (typeof window.GtaModDetector === 'undefined') {
    // Hardening v1: نبودن Router یک نقص ساختاری build است. دیگر فایل را
    // بی‌صدا مستقیم به Engine نمی‌فرستیم، چون ممکن است نوع ورودی برای PE
    // مناسب نباشد و fallback پوشش را بیش از واقع نشان دهد.
    result = {
      appIntegrationVersion: APP_INTEGRATION_VERSION,
      mode: 'pro',
      finalVerdict: 'inconclusive',
      detectorResult: null,
      engineResult: null,
      note: 'GtaModDetector در دسترس نیست؛ اسکن Pro برای جلوگیری از نتیجهٔ ناقص متوقف شد.',
      hardeningError: 'detector_unavailable',
    };
    return finalizeTopLevelResult(result, normalizedMode);
  }

  const detectorResult = await window.GtaModDetector.analyze(file);

  if (detectorResult.route === 'ENGINE') {
    result = await runEngineThenMultiLayer(file, { detectorResult });
    return finalizeTopLevelResult(result, normalizedMode);
  }

  if (detectorResult.route === 'ARCHIVE_INSPECTION') {
    result = await runArchivePipeline(file, detectorResult);
    return finalizeTopLevelResult(result, normalizedMode);
  }

  // GtaModDetector v1.0.0 هنوز برای scriptها route جداگانه ندارد و آن‌ها
  // را INCONCLUSIVE می‌گذارد. app.js بر اساس modType شناخته‌شده، فقط .lua/.cs
  // را به ScriptAnalyzer اختصاصی می‌فرستد؛ هیچ script دیگری حدس زده نمی‌شود.
  if (detectorResult.modType === 'script') {
    result = await runScriptPipeline(file, detectorResult);
    return finalizeTopLevelResult(result, normalizedMode);
  }

  if (detectorResult.route === 'REJECT') {
    result = {
      appIntegrationVersion: APP_INTEGRATION_VERSION,
      mode: 'pro',
      finalVerdict: 'invalid',
      detectorResult,
      engineResult: null,
      note: 'این ورودی خارج از محدودهٔ مود GTA یا پشتیبانی‌نشده تشخیص داده شد؛ اسکن انجام نشد.',
    };
    return finalizeTopLevelResult(result, normalizedMode);
  }

  // route === 'INCONCLUSIVE'
  result = {
    appIntegrationVersion: APP_INTEGRATION_VERSION,
    mode: 'pro',
    finalVerdict: 'inconclusive',
    detectorResult,
    engineResult: null,
    note: 'نوع این ورودی مشخص شد اما در حال حاضر هیچ لایهٔ اسکن ایمنی برای آن در دسترس نیست؛ فایل اسکن نشد.',
  };
  return finalizeTopLevelResult(result, normalizedMode);
}

function finalizeTopLevelResult(result, normalizedMode) {
  const schemaVersion = window.MalGuardContract && window.MalGuardContract.resultSchemaVersion
    ? window.MalGuardContract.resultSchemaVersion
    : '1.0.0';
  const allowedVerdicts = window.MalGuardContract && Array.isArray(window.MalGuardContract.verdicts)
    ? window.MalGuardContract.verdicts
    : ['safe', 'suspicious', 'malicious', 'inconclusive', 'invalid'];

  if (!result || typeof result !== 'object') {
    return {
      resultSchemaVersion: schemaVersion,
      appIntegrationVersion: APP_INTEGRATION_VERSION,
      mode: normalizedMode,
      finalVerdict: 'inconclusive',
      note: 'پایپ‌لاین نتیجهٔ ساختاریافته برنگرداند؛ برای ایمنی هیچ حکم SAFE صادر نشد.',
      hardeningError: 'invalid_pipeline_result',
    };
  }

  result.resultSchemaVersion = schemaVersion;
  result.appIntegrationVersion = APP_INTEGRATION_VERSION;
  result.mode = normalizedMode;

  if (!allowedVerdicts.includes(result.finalVerdict)) {
    result.finalVerdict = 'inconclusive';
    result.hardeningError = 'unknown_final_verdict';
    result.note = 'حکم نهایی پایپ‌لاین معتبر نبود؛ به INCONCLUSIVE کاهش داده شد.';
  }

  return result;
}

/**
 * مسیر Pro برای یک فایل PE مستقیم یا یک entry استخراج‌شده از ZIP:
 * Engine v2.2.0 → MultiLayerSecurity.
 */
async function runEngineThenMultiLayer(file, extra) {
  const engineResult = await window.scanFile(file);
  const engineStatus = validateEngineResultForIntegration(engineResult);
  if (!engineStatus.ok) {
    const preserved = engineResult && (engineResult.verdict === 'malicious' || engineResult.verdict === 'suspicious')
      ? engineResult.verdict : 'inconclusive';
    return Object.assign({
      appIntegrationVersion: APP_INTEGRATION_VERSION,
      mode: 'pro',
      finalVerdict: preserved,
      engineResult,
      hardeningError: engineStatus.code,
      note: 'ساختار/نسخهٔ نتیجهٔ Engine معتبر نبود؛ SAFE پذیرفته نشد.',
    }, extra || {});
  }

  if (typeof window.MultiLayerSecurity === 'undefined') {
    console.error('MultiLayerSecurity در دسترس نیست؛ نتیجهٔ پایه با سیاست fail-closed محدود شد.');
    const preservedVerdict = engineResult && (engineResult.verdict === 'malicious' || engineResult.verdict === 'suspicious')
      ? engineResult.verdict : 'inconclusive';
    return Object.assign({
      appIntegrationVersion: APP_INTEGRATION_VERSION,
      mode: 'pro',
      finalVerdict: preservedVerdict,
      engineResult,
      multiLayerUnavailable: true,
      hardeningError: 'multilayer_unavailable',
      note: 'MultiLayerSecurity در دسترس نیست؛ نتیجهٔ SAFE/INVALID پایه به‌عنوان SAFE پذیرفته نشد.',
    }, extra || {});
  }

  const PRE_PARSE_ERROR_CODES = new Set([
    'INVALID_EXTENSION', 'EMPTY_FILE', 'TOO_LARGE', 'READ_FAILED', 'CRYPTO_UNAVAILABLE',
  ]);
  if (PRE_PARSE_ERROR_CODES.has(engineResult.errorCode)) {
    return Object.assign({
      appIntegrationVersion: APP_INTEGRATION_VERSION,
      mode: 'pro',
      finalVerdict: 'invalid',
      engineResult,
      multiLayerSkipped: 'engine_rejected_before_analysis',
    }, extra || {});
  }

  const multiLayerResult = window.MultiLayerSecurity.analyze(engineResult);
  return Object.assign({
    appIntegrationVersion: APP_INTEGRATION_VERSION,
    mode: 'pro',
    finalVerdict: multiLayerResult.finalVerdict,
    engineResult,
    multiLayer: multiLayerResult,
  }, extra || {});
}


/* ============================================================
   Script pipeline (.lua / .cs)
   ============================================================ */

async function runScriptPipeline(file, detectorResult) {
  const base = {
    appIntegrationVersion: APP_INTEGRATION_VERSION,
    mode: 'pro',
    detectorResult,
    engineResult: null,
    scriptAnalysis: null,
    reasons: [],
  };

  if (typeof window.ScriptAnalyzer === 'undefined') {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'ScriptAnalyzer بارگذاری نشده است؛ برای جلوگیری از نتیجهٔ جعلی SAFE اسکریپت تحلیل نشد.',
    });
  }

  const analysis = await window.ScriptAnalyzer.analyze(file);
  base.scriptAnalysis = analysis;

  if (!analysis || analysis.supported !== true) {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'این فایل توسط ScriptAnalyzer v1.0.0 پشتیبانی نمی‌شود.',
      reasons: analysis && Array.isArray(analysis.reasons) ? analysis.reasons.slice() : [],
    });
  }

  base.reasons = Array.isArray(analysis.reasons) ? analysis.reasons.slice() : [];

  if (analysis.errorCode) {
    // اگر Detector هم بسته‌بندی/تغییرنوع مشکوک دیده باشد، یک فایل غیرمتنی
    // که خودش را .lua/.cs معرفی می‌کند حداقل SUSPICIOUS است، نه SAFE.
    const packagingSuspicious = detectorResult && detectorResult.suspiciousPackaging === true;
    return Object.assign(base, {
      finalVerdict: packagingSuspicious ? 'suspicious' : (analysis.verdict || 'invalid'),
      note: packagingSuspicious
        ? 'نوع/بسته‌بندی فایل با ادعای اسکریپت سازگار نیست و ScriptAnalyzer نتوانست آن را به‌عنوان متن معتبر تحلیل کند.'
        : 'ScriptAnalyzer نتوانست تحلیل کامل و معتبر انجام دهد؛ هیچ حکم SAFE صادر نشد.',
    });
  }

  let finalVerdict = analysis.verdict || 'inconclusive';
  let note = 'اسکریپت به‌صورت کاملاً ایستا و بدون اجرا توسط ScriptAnalyzer v1.0.0 تحلیل شد.';

  // بسته‌بندی مشکوک مستقل از متن اسکریپت است. اگر Analyzer متن را SAFE بداند
  // ولی Detector پسوند دوگانه/magic mismatch دیده باشد، SAFE را به suspicious
  // ارتقا می‌دهیم. حکم malicious هرگز پایین آورده نمی‌شود.
  if (detectorResult && detectorResult.suspiciousPackaging === true && finalVerdict === 'safe') {
    finalVerdict = 'suspicious';
    base.reasons.push('GtaModDetector بسته‌بندی/پسوند فایل را مشکوک تشخیص داد؛ نتیجهٔ SAFE متنی به SUSPICIOUS ارتقا یافت.');
    note = 'تحلیل متن اسکریپت نشانهٔ قوی پیدا نکرد، اما بسته‌بندی فایل مشکوک است.';
  }

  return Object.assign(base, { finalVerdict, note });
}

/* ============================================================
   Archive pipeline
   ============================================================ */

async function runArchivePipeline(file, detectorResult) {
  const base = {
    appIntegrationVersion: APP_INTEGRATION_VERSION,
    mode: 'pro',
    detectorResult,
    engineResult: null,
    archiveInspection: null,
    archivePluginResults: [],
    archiveScriptResults: [],
    reasons: [],
  };

  if (typeof window.ArchiveInspector === 'undefined') {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'ArchiveInspector بارگذاری نشده است؛ بسته برای جلوگیری از نتیجهٔ جعلی SAFE اسکن نشد.',
    });
  }

  const startedAt = Date.now();
  const inspection = await window.ArchiveInspector.inspect(file);
  base.archiveInspection = inspection;
  base.reasons.push(...buildArchiveInspectionReasons(inspection));

  // ورودی واقعاً نامعتبر است، نه صرفاً unsupported.
  if (inspection.inspectionStatus === 'invalid_input') {
    return Object.assign(base, {
      finalVerdict: 'invalid',
      note: 'ورودی آرشیو نامعتبر است.',
    });
  }

  // ساختار ZIP خراب/مبهم می‌تواند یک بستهٔ خصمانه یا فاسد باشد؛
  // آن را MALICIOUS قطعی نمی‌نامیم، اما SAFE هم نیست.
  if (inspection.inspectionStatus === 'malformed_archive') {
    return Object.assign(base, {
      finalVerdict: 'suspicious',
      note: 'ساختار آرشیو به‌طور ایمن قابل‌اعتبارسنجی نبود؛ نتیجهٔ بسته مشکوک است، نه اثبات قطعی بدافزار.',
    });
  }

  // فرمت پشتیبانی‌نشده، ZIP64/multi-disk، اندازهٔ بیش از سقف، یا timeout
  // یعنی پوشش کافی نداریم. هرگز از این مسیر SAFE تولید نمی‌شود.
  if (!inspection.inspectionSucceeded || inspection.inspectionStatus === 'completed_partial_timeout') {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'بازرسی آرشیو کامل نشد؛ برای صدور حکم امن پوشش کافی وجود ندارد.',
    });
  }

  if (inspection.inspectionStatus === 'completed_non_gta' || inspection.gtaRelevant === false) {
    return Object.assign(base, {
      finalVerdict: 'invalid',
      note: 'محتوای این بسته با اطمینان کافی به مود GTA مربوط شناخته نشد؛ GTA Guard آن را خارج از محدوده در نظر می‌گیرد.',
    });
  }

  if (inspection.archiveType !== 'zip') {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'در این نسخه فقط ZIP می‌تواند تا مرحلهٔ خواندن امن entry و اسکن پلاگین ادامه پیدا کند.',
    });
  }

  const pluginDescriptors = Array.isArray(inspection.pluginTargetDescriptors)
    ? inspection.pluginTargetDescriptors
    : [];
  const scriptDescriptors = Array.isArray(inspection.scriptTargetDescriptors)
    ? inspection.scriptTargetDescriptors
    : [];

  // اگر Inspector محتوای فعال دیده ولی descriptor بدون‌ابهام تولید نکرده،
  // علت معمولاً مسیر مشکوک/تکراری یا بسته‌بندی مبهم است. چنین بسته‌ای SAFE نیست.
  if (pluginDescriptors.length === 0 && scriptDescriptors.length === 0) {
    const activeWasPresent = Number(inspection.pluginCount || 0) > 0 || Number(inspection.scriptCount || 0) > 0;
    return Object.assign(base, {
      finalVerdict: activeWasPresent ? 'suspicious' : 'inconclusive',
      note: activeWasPresent
        ? 'محتوای فعال .asi/.dll/.lua/.cs در بسته دیده شد، اما هیچ هدف بدون‌ابهام و مجاز برای خواندن امن تولید نشد.'
        : 'هیچ پلاگین یا اسکریپت پشتیبانی‌شدهٔ قابل‌اسکن در این بسته پیدا نشد.',
    });
  }

  if (pluginDescriptors.length > ARCHIVE_PIPELINE_LIMITS.MAX_PLUGIN_TARGETS) {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'تعداد پلاگین‌های قابل‌اسکن (' + pluginDescriptors.length + ') از سقف امن این مرحله (' + ARCHIVE_PIPELINE_LIMITS.MAX_PLUGIN_TARGETS + ') بیشتر است؛ اسکن جزئی به‌اشتباه SAFE اعلام نمی‌شود.',
    });
  }
  if (scriptDescriptors.length > ARCHIVE_PIPELINE_LIMITS.MAX_SCRIPT_TARGETS) {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'تعداد اسکریپت‌های قابل‌اسکن (' + scriptDescriptors.length + ') از سقف امن این مرحله (' + ARCHIVE_PIPELINE_LIMITS.MAX_SCRIPT_TARGETS + ') بیشتر است؛ اسکن جزئی به‌اشتباه SAFE اعلام نمی‌شود.',
    });
  }

  const totalDeclaredPluginBytes = pluginDescriptors.reduce((sum, d) => sum + Number(d.uncompressedSize || 0), 0);
  if (!Number.isFinite(totalDeclaredPluginBytes) || totalDeclaredPluginBytes > ARCHIVE_PIPELINE_LIMITS.MAX_TOTAL_PLUGIN_UNCOMPRESSED) {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'مجموع اندازهٔ اعلام‌شدهٔ پلاگین‌های بسته از بودجهٔ امن اسکن آرشیو بیشتر است.',
    });
  }
  const totalDeclaredScriptBytes = scriptDescriptors.reduce((sum, d) => sum + Number(d.uncompressedSize || 0), 0);
  if (!Number.isFinite(totalDeclaredScriptBytes) || totalDeclaredScriptBytes > ARCHIVE_PIPELINE_LIMITS.MAX_TOTAL_SCRIPT_UNCOMPRESSED) {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'مجموع اندازهٔ اعلام‌شدهٔ اسکریپت‌های بسته از بودجهٔ امن تحلیل اسکریپت بیشتر است.',
    });
  }

  if (typeof window.ArchiveEntryReader === 'undefined') {
    return Object.assign(base, {
      finalVerdict: 'inconclusive',
      note: 'ArchiveEntryReader بارگذاری نشده است؛ متادیتای ZIP بررسی شد اما بایت واقعی پلاگین‌ها اسکن نشد.',
    });
  }

  let sawSuspicious = false;
  let sawInconclusive = false;
  let sawMalicious = false;

  for (let i = 0; i < pluginDescriptors.length; i++) {
    if (Date.now() - startedAt > ARCHIVE_PIPELINE_LIMITS.MAX_PIPELINE_TIME_MS) {
      sawInconclusive = true;
      base.reasons.push('بودجهٔ زمانی کل پایپ‌لاین آرشیو پیش از اسکن همهٔ پلاگین‌ها به پایان رسید.');
      break;
    }

    const descriptor = pluginDescriptors[i];
    const readResult = await window.ArchiveEntryReader.readEntry(file, descriptor);

    if (!readResult || readResult.ok !== true || !readResult.file) {
      sawInconclusive = true;
      base.archivePluginResults.push({
        name: descriptor.canonicalPath,
        finalVerdict: 'inconclusive',
        readerError: readResult ? (readResult.errorCode || 'unknown_reader_error') : 'reader_failed',
        score: null,
        hash: null,
      });
      base.reasons.push(
        'خواندن امن «' + descriptor.canonicalPath + '» ناموفق بود (' +
        (readResult && readResult.errorCode ? readResult.errorCode : 'reader_failed') + ').'
      );
      // Reader کل Central Directory را fail-closed اعتبارسنجی می‌کند؛ اگر
      // همین آرشیو در این مرحله رد شد، ادامه‌دادن به target بعدی ارزش ندارد.
      break;
    }

    const wrapped = await runEngineThenMultiLayer(readResult.file, {
      archiveEntry: {
        name: descriptor.canonicalPath,
        bytesExtracted: readResult.bytesExtracted,
        crc32Verified: readResult.crc32Verified === true,
      },
    });

    const pluginVerdict = wrapped.finalVerdict || 'inconclusive';
    const pluginEngine = wrapped.engineResult || null;
    base.archivePluginResults.push({
      name: descriptor.canonicalPath,
      finalVerdict: pluginVerdict,
      score: pluginEngine && typeof pluginEngine.score === 'number' ? pluginEngine.score : null,
      hash: pluginEngine ? (pluginEngine.hash || null) : null,
      crc32Verified: readResult.crc32Verified === true,
      engineResult: pluginEngine,
      multiLayer: wrapped.multiLayer || null,
    });

    base.reasons.push(
      'پلاگین «' + descriptor.canonicalPath + '»: ' + verdictLabelFa(pluginVerdict) +
      (pluginEngine && typeof pluginEngine.score === 'number' ? ' (' + pluginEngine.score + '%)' : '') + '.'
    );

    if (pluginVerdict === 'malicious') {
      sawMalicious = true;
      // بالاتر از malicious حکم دیگری نداریم؛ برای کاهش هزینه ادامه نمی‌دهیم.
      break;
    }
    if (pluginVerdict === 'suspicious' || pluginVerdict === 'invalid') sawSuspicious = true;
    if (pluginVerdict === 'inconclusive') sawInconclusive = true;
  }

  // اسکریپت‌های .lua/.cs داخل ZIP نیز فقط پس از بازاعتبارسنجی کامل Reader
  // خوانده می‌شوند و سپس بدون اجرا به ScriptAnalyzer تحویل داده می‌شوند.
  for (let i = 0; i < scriptDescriptors.length; i++) {
    if (Date.now() - startedAt > ARCHIVE_PIPELINE_LIMITS.MAX_PIPELINE_TIME_MS) {
      sawInconclusive = true;
      base.reasons.push('بودجهٔ زمانی کل پایپ‌لاین آرشیو پیش از تحلیل همهٔ اسکریپت‌ها به پایان رسید.');
      break;
    }

    const descriptor = scriptDescriptors[i];
    // ScriptAnalyzer سقف 4 MiB دارد؛ فایل بزرگ‌تر را اصلاً decompress نمی‌کنیم.
    const analyzerLimit = (window.ScriptAnalyzer && window.ScriptAnalyzer.limits && Number(window.ScriptAnalyzer.limits.MAX_SCRIPT_SIZE)) || (4 * 1024 * 1024);
    if (Number(descriptor.uncompressedSize || 0) > analyzerLimit) {
      sawInconclusive = true;
      base.archiveScriptResults.push({
        name: descriptor.canonicalPath, finalVerdict: 'inconclusive', score: null, hash: null,
        readerError: 'script_too_large_for_analyzer',
      });
      base.reasons.push('اسکریپت «' + descriptor.canonicalPath + '» از سقف ScriptAnalyzer بزرگ‌تر است و برای جلوگیری از مصرف حافظه استخراج نشد.');
      continue;
    }

    const readResult = await window.ArchiveEntryReader.readEntry(file, descriptor);
    if (!readResult || readResult.ok !== true || !readResult.file) {
      sawInconclusive = true;
      base.archiveScriptResults.push({
        name: descriptor.canonicalPath, finalVerdict: 'inconclusive', score: null, hash: null,
        readerError: readResult ? (readResult.errorCode || 'unknown_reader_error') : 'reader_failed',
      });
      base.reasons.push('خواندن امن اسکریپت «' + descriptor.canonicalPath + '» ناموفق بود (' +
        (readResult && readResult.errorCode ? readResult.errorCode : 'reader_failed') + ').');
      break;
    }

    const wrappedScript = await runScriptPipeline(readResult.file, null);
    const scriptVerdict = wrappedScript.finalVerdict || 'inconclusive';
    const analysis = wrappedScript.scriptAnalysis || null;
    base.archiveScriptResults.push({
      name: descriptor.canonicalPath,
      finalVerdict: scriptVerdict,
      score: analysis && typeof analysis.score === 'number' ? analysis.score : null,
      hash: analysis ? (analysis.hash || null) : null,
      crc32Verified: readResult.crc32Verified === true,
      scriptAnalysis: analysis,
    });
    base.reasons.push('اسکریپت «' + descriptor.canonicalPath + '»: ' + verdictLabelFa(scriptVerdict) +
      (analysis && typeof analysis.score === 'number' ? ' (' + analysis.score + '%)' : '') + '.');

    if (scriptVerdict === 'malicious') { sawMalicious = true; break; }
    if (scriptVerdict === 'suspicious' || scriptVerdict === 'invalid') sawSuspicious = true;
    if (scriptVerdict === 'inconclusive') sawInconclusive = true;
  }

  // شواهد بسته‌بندی‌ای که مستقل از حکم پلاگین‌ها/اسکریپت‌ها باید جلوی SAFE را بگیرند.
  const structuralSuspicious = Boolean(
    inspection.possibleDecompressionBomb ||
    Number(inspection.suspiciousPathCount || 0) > 0 ||
    Number(inspection.doubleExtensionCount || 0) > 0 ||
    Number(inspection.duplicatePathCount || 0) > 0 ||
    Number(inspection.malformedEntryCount || 0) > 0
  );

  // محتوای فعال/تودرتویی که هنوز Analyzer مناسب ندارد، باعث می‌شود حتی
  // با پلاگین‌های سالم نتوان کل بسته را SAFE اعلام کرد.
  const unscannedActiveContent = Boolean(
    Number(inspection.executableEntryCount || 0) > 0 ||
    Number(inspection.nestedArchiveCount || 0) > 0 ||
    Number(inspection.unknownCount || 0) > 0 ||
    Number(inspection.pluginCount || 0) !== pluginDescriptors.length ||
    Number(inspection.scriptCount || 0) !== scriptDescriptors.length
  );

  let finalVerdict = 'safe';
  let note = 'همهٔ پلاگین‌ها و اسکریپت‌های واجد شرایط ZIP با CRC تأییدشده خوانده و با Analyzer مناسب خود بررسی شدند؛ نشانهٔ بسته‌بندی حل‌نشده‌ای باقی نماند.';

  if (sawMalicious) {
    finalVerdict = 'malicious';
    note = 'حداقل یک پلاگین یا اسکریپت داخل بسته توسط پایپ‌لاین موجود مخرب ارزیابی شد.';
  } else if (structuralSuspicious || sawSuspicious) {
    finalVerdict = 'suspicious';
    note = 'حداقل یک نشانهٔ مشکوک در ساختار بسته یا یکی از فایل‌های فعال آن وجود دارد.';
  } else if (sawInconclusive || unscannedActiveContent || base.archivePluginResults.length !== pluginDescriptors.length || base.archiveScriptResults.length !== scriptDescriptors.length) {
    finalVerdict = 'inconclusive';
    note = 'بخشی از محتوای بالقوه‌فعال بسته هنوز تحلیل کامل ندارد یا همهٔ اهداف قابل‌اسکن با موفقیت تمام نشدند؛ بنابراین SAFE صادر نمی‌شود.';
  }

  if (unscannedActiveContent) {
    base.reasons.push('بسته شامل محتوای اجرایی/ناشناخته/تودرتویی است که در این نسخه Analyzer کامل مخصوص خود را ندارد.');
  }

  return Object.assign(base, { finalVerdict, note });
}

function buildArchiveInspectionReasons(inspection) {
  if (!inspection || typeof inspection !== 'object') return ['ArchiveInspector نتیجهٔ معتبری برنگرداند.'];

  const out = [];
  const type = String(inspection.archiveType || 'unknown').toUpperCase();
  out.push(
    'بازرسی ' + type + ': ' + Number(inspection.entryCount || 0) + ' ورودی، ' +
    Number(inspection.pluginCount || 0) + ' پلاگین، ' +
    Number(inspection.scriptCount || 0) + ' اسکریپت، ' +
    Number(inspection.nestedArchiveCount || 0) + ' آرشیو/بستهٔ تودرتو.'
  );

  if (inspection.possibleDecompressionBomb) out.push('متادیتای آرشیو نسبت غیرعادی/حجم فشرده‌نشدهٔ بسیار بالا را نشان می‌دهد.');
  if (Number(inspection.suspiciousPathCount || 0) > 0) out.push('مسیر مشکوک داخل آرشیو یافت شد.');
  if (Number(inspection.doubleExtensionCount || 0) > 0) out.push('نام فایل با الگوی پسوند دوگانه در آرشیو دیده شد.');
  if (Number(inspection.duplicatePathCount || 0) > 0) out.push('مسیر تکراری/متعارض داخل آرشیو یافت شد.');
  if (Number(inspection.malformedEntryCount || 0) > 0) out.push('یک یا چند entry آرشیو به‌طور ایمن قابل‌تجزیه نبود.');

  const warnings = Array.isArray(inspection.warnings) ? inspection.warnings : [];
  const errors = Array.isArray(inspection.errors) ? inspection.errors : [];
  for (const w of warnings.slice(0, 6)) out.push(String(w));
  for (const e of errors.slice(0, 4)) out.push(String(e));
  return out;
}

function verdictLabelFa(verdict) {
  switch (verdict) {
    case 'safe': return 'امن';
    case 'suspicious': return 'مشکوک';
    case 'malicious': return 'مخرب';
    case 'invalid': return 'نامعتبر';
    default: return 'نامشخص';
  }
}

window.scanFileWithMode = scanFileWithMode;
window.MalGuardApp = Object.freeze({
  version: APP_INTEGRATION_VERSION,
  resultSchemaVersion: (window.MalGuardContract && window.MalGuardContract.resultSchemaVersion) || '1.0.0',
  archivePipelineLimits: ARCHIVE_PIPELINE_LIMITS,
});

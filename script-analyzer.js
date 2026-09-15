(function () {
/* ============================================================
   MalGuard — script-analyzer.js  (Script Analyzer v1.0.0)
   ------------------------------------------------------------
   تحلیل ایستای محدود و قابل‌توضیح برای اسکریپت‌های مود GTA:
     - Lua (.lua)
     - C#  (.cs)

   این ماژول هرگز کد ورودی را اجرا، eval، import، compile یا load نمی‌کند.
   فقط بایت‌های فایل را با سقف‌های صریح می‌خواند، UTF-8 را سخت‌گیرانه decode
   می‌کند، commentها را برای کاهش false-positive حذف می‌کند و روی متن باقی‌مانده
   الگوهای امنیتی محدود/ازپیش‌تعریف‌شده را بررسی می‌کند.

   نکتهٔ امتیاز: score مانند Engine اصلی «امتیاز ایمنی» است؛ 100 بهتر است.
   یک keyword/API منفرد هرگز به‌تنهایی حکم MALICIOUS نمی‌سازد. حکم‌های شدید
   فقط از ترکیب چند دستهٔ مستقل و شواهد قوی به دست می‌آیند.
   ============================================================ */

'use strict';

const SCRIPT_ANALYZER_VERSION = '1.0.0';

const SCRIPT_LIMITS = Object.freeze({
  MAX_SCRIPT_SIZE: 4 * 1024 * 1024,          // 4 MiB
  MAX_TEXT_LENGTH: 4 * 1024 * 1024,          // chars after UTF-8 decode
  MAX_FINDINGS: 128,
  MAX_MATCHES_PER_RULE: 4,
  MAX_PATTERN_LENGTH: 256,
  MAX_ANALYSIS_TIME_MS: 1800,
  MAX_URLS: 64,
  MAX_LINE_LENGTH_FOR_METRICS: 20000,
});

const ERROR_CODES = Object.freeze({
  INVALID_INPUT: 'invalid_input',
  EMPTY_FILE: 'empty_file',
  UNSUPPORTED_EXTENSION: 'unsupported_extension',
  TOO_LARGE: 'too_large',
  READ_FAILED: 'read_failed',
  INVALID_UTF8: 'invalid_utf8',
  BINARY_LIKE_INPUT: 'binary_like_input',
  ANALYSIS_TIMEOUT: 'analysis_timeout',
});

const SEVERITY_WEIGHT = Object.freeze({ info: 0, low: 4, medium: 10, high: 18, critical: 28 });
const VERDICT_RANK = Object.freeze({ safe: 0, suspicious: 1, malicious: 2 });

function rule(id, languages, category, severity, confidence, description, regex, maxMatches) {
  const source = regex && regex.source ? regex.source : '';
  if (source.length > SCRIPT_LIMITS.MAX_PATTERN_LENGTH) {
    throw new Error('ScriptAnalyzer rule pattern exceeds MAX_PATTERN_LENGTH: ' + id);
  }
  return Object.freeze({
    id, languages, category, severity, confidence, description, regex,
    maxMatches: Math.min(maxMatches || SCRIPT_LIMITS.MAX_MATCHES_PER_RULE, SCRIPT_LIMITS.MAX_MATCHES_PER_RULE),
  });
}

/*
 * قواعد عمداً روی primitiveهای نسبتاً مشخص تمرکز دارند. موارد عمومی مثل
 * HttpClient/File.ReadAllText/io.open فقط low/medium هستند و به‌تنهایی حکم
 * شدید نمی‌سازند. دسته‌ها با واژگان rules.json اصلی همسو نگه داشته شده‌اند.
 */
const RULES = Object.freeze([
  // ---------- Lua: command/dynamic execution ----------
  rule('LUA-CMD-001', ['lua'], 'command_execution', 'high', 'high', 'اجرای فرمان سیستم از Lua با os.execute.', /\bos\s*\.\s*execute\s*\(/gi),
  rule('LUA-CMD-002', ['lua'], 'command_execution', 'high', 'high', 'بازکردن process/pipe از Lua با io.popen.', /\bio\s*\.\s*popen\s*\(/gi),
  rule('LUA-DYN-001', ['lua'], 'dynamic_execution', 'high', 'high', 'اجرای کد پویا با loadstring.', /\bloadstring\s*\(/gi),
  rule('LUA-DYN-002', ['lua'], 'dynamic_execution', 'medium', 'medium', 'بارگذاری کد پویا با load.', /\bload\s*\(/gi),
  rule('LUA-DYN-003', ['lua'], 'dynamic_execution', 'medium', 'medium', 'اجرای فایل Lua دیگر با dofile.', /\bdofile\s*\(/gi),

  // ---------- Lua: network / file ----------
  rule('LUA-NET-001', ['lua'], 'c2_networking', 'medium', 'medium', 'استفاده از socket.http برای ارتباط HTTP.', /\bsocket\s*\.\s*http\b/gi),
  rule('LUA-NET-002', ['lua'], 'c2_networking', 'medium', 'medium', 'استفاده از ssl.https برای ارتباط HTTPS.', /\bssl\s*\.\s*https\b/gi),
  rule('LUA-NET-003', ['lua'], 'c2_networking', 'medium', 'medium', 'فراخوانی درخواست شبکه در APIهای رایج Lua.', /\b(?:http|https)\s*\.\s*request\s*\(/gi),
  rule('LUA-FS-001', ['lua'], 'filesystem_access', 'low', 'low', 'دسترسی عمومی فایل با io.open؛ به‌تنهایی عادی است.', /\bio\s*\.\s*open\s*\(/gi),
  rule('LUA-FS-002', ['lua'], 'file_destruction', 'medium', 'medium', 'حذف فایل با os.remove.', /\bos\s*\.\s*remove\s*\(/gi),

  // ---------- C#: command/dynamic execution ----------
  rule('CS-CMD-001', ['csharp'], 'command_execution', 'medium', 'medium', 'شروع process با Process.Start؛ کاربرد مشروع هم دارد.', /\bProcess\s*\.\s*Start\s*\(/gi),
  rule('CS-CMD-002', ['csharp'], 'command_execution', 'medium', 'medium', 'ساخت ProcessStartInfo برای اجرای process.', /\bProcessStartInfo\b/gi),
  rule('CS-CMD-003', ['csharp'], 'command_execution', 'high', 'high', 'ارجاع مستقیم به PowerShell.', /\b(?:powershell(?:\.exe)?|System\.Management\.Automation)\b/gi),
  rule('CS-CMD-004', ['csharp'], 'command_execution', 'medium', 'medium', 'ارجاع مستقیم به cmd.exe.', /\bcmd\.exe\b/gi),
  rule('CS-DYN-001', ['csharp'], 'dynamic_execution', 'high', 'high', 'بارگذاری assembly از بایت/منبع در زمان اجرا.', /\bAssembly\s*\.\s*Load(?:From|File)?\s*\(/gi),
  rule('CS-DYN-002', ['csharp'], 'dynamic_execution', 'medium', 'medium', 'Reflection Invoke برای فراخوانی پویا.', /\b(?:MethodInfo|Delegate)\b[\s\S]{0,120}?\bInvoke\s*\(/gi),
  rule('CS-DYN-003', ['csharp'], 'dynamic_execution', 'medium', 'medium', 'ساخت نمونهٔ پویا با Activator.CreateInstance.', /\bActivator\s*\.\s*CreateInstance\s*\(/gi),

  // ---------- C#: network / download ----------
  rule('CS-NET-001', ['csharp'], 'c2_networking', 'low', 'low', 'HttpClient برای ارتباط شبکه؛ بسیار رایج و ضعیف است.', /\bHttpClient\b/gi),
  rule('CS-NET-002', ['csharp'], 'c2_networking', 'medium', 'medium', 'WebClient برای ارتباط/دانلود شبکه.', /\bWebClient\b/gi),
  rule('CS-DL-001', ['csharp'], 'network_download', 'high', 'high', 'دانلود مستقیم داده/فایل با WebClient.', /\bDownload(?:String|Data|File)(?:TaskAsync|Async)?\s*\(/gi),
  rule('CS-DL-002', ['csharp'], 'network_download', 'medium', 'medium', 'دریافت بایت/رشته از شبکه با HttpClient.', /\bGet(?:ByteArray|String|Stream)Async\s*\(/gi),

  // ---------- C#: filesystem / registry ----------
  rule('CS-FS-001', ['csharp'], 'filesystem_access', 'low', 'low', 'خواندن فایل با File.Read*؛ به‌تنهایی نشانهٔ بدافزار نیست.', /\bFile\s*\.\s*Read(?:AllText|AllBytes|AllLines|Lines)\s*\(/gi),
  rule('CS-FS-002', ['csharp'], 'filesystem_access', 'low', 'low', 'نوشتن فایل با File.Write*؛ به‌تنهایی نشانهٔ بدافزار نیست.', /\bFile\s*\.\s*Write(?:AllText|AllBytes|AllLines)\s*\(/gi),
  rule('CS-PER-001', ['csharp'], 'persistence', 'high', 'high', 'ارجاع به Windows Run/RunOnce registry key.', /CurrentVersion\\(?:Run|RunOnce)\b/gi),
  rule('CS-PER-002', ['csharp'], 'persistence', 'medium', 'medium', 'دستکاری Registry از کد C#.', /\bRegistry(?:Key)?\b[\s\S]{0,100}?\b(?:SetValue|CreateSubKey)\s*\(/gi),

  // ---------- Shared: credential theft / exfil / destructive ----------
  rule('SH-CRED-001', ['lua', 'csharp'], 'credential_theft', 'high', 'high', 'ارجاع به دیتابیس Login Data مرورگرهای Chromium.', /(?:^|[\\/\s"'])Login Data(?:$|[\\/\s"'])/gi),
  rule('SH-CRED-002', ['lua', 'csharp'], 'credential_theft', 'medium', 'medium', 'ارجاع هم‌زمان به Local State مرورگر Chromium.', /(?:^|[\\/\s"'])Local State(?:$|[\\/\s"'])/gi),
  rule('SH-CRED-003', ['lua', 'csharp'], 'credential_theft', 'high', 'high', 'ارجاع به cookies.sqlite.', /\bcookies\.sqlite\b/gi),
  rule('SH-CRED-004', ['lua', 'csharp'], 'credential_theft', 'high', 'high', 'ارجاع به wallet.dat.', /\bwallet\.dat\b/gi),
  rule('SH-CRED-005', ['lua', 'csharp'], 'credential_theft', 'high', 'high', 'نشانهٔ صریح جمع‌آوری Discord token.', /\bdiscord[_\s-]?token\b/gi),
  rule('SH-CRED-006', ['lua', 'csharp'], 'credential_theft', 'medium', 'medium', 'ارجاع به LevelDB در بافت ذخیره‌سازی مرورگر/Discord.', /(?:Local Storage[\\/]leveldb|\\leveldb|\/leveldb)/gi),
  rule('SH-EXF-001', ['lua', 'csharp'], 'data_exfiltration', 'high', 'high', 'Discord webhook endpoint؛ در stealers زیاد سوءاستفاده می‌شود.', /https?:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\//gi),
  rule('SH-EXF-002', ['lua', 'csharp'], 'data_exfiltration', 'high', 'high', 'Telegram Bot API endpoint؛ می‌تواند برای exfiltration استفاده شود.', /https?:\/\/api\.telegram\.org\/bot/gi),
  rule('SH-C2-001', ['lua', 'csharp'], 'c2_networking', 'medium', 'medium', 'Raw Pastebin URL؛ گاهی برای payload/config از راه دور استفاده می‌شود.', /https?:\/\/(?:www\.)?pastebin\.com\/raw\//gi),
  rule('SH-EXF-003', ['lua', 'csharp'], 'data_exfiltration', 'medium', 'medium', 'واژهٔ صریح exfiltration.', /\bexfil(?:trate|tration)?\b/gi),
  rule('SH-DEST-001', ['lua', 'csharp'], 'file_destruction', 'critical', 'high', 'حذف Volume Shadow Copies.', /\bvssadmin\s+delete\s+shadows\b/gi),
  rule('SH-DEST-002', ['lua', 'csharp'], 'file_destruction', 'critical', 'high', 'حذف backup با wbadmin.', /\bwbadmin\s+delete\b/gi),

  // ---------- Shared: obfuscation / encoded execution ----------
  rule('SH-OBF-001', ['lua', 'csharp'], 'obfuscation', 'low', 'low', 'Base64 decode؛ به‌تنهایی بسیار ضعیف است.', /\b(?:FromBase64String|base64\.decode|decode64)\b/gi),
  rule('SH-OBF-002', ['lua', 'csharp'], 'obfuscation', 'high', 'high', 'PowerShell encoded-command flag.', /(?:^|\s)-(?:enc|encodedcommand)\b/gi),
  rule('SH-ANTI-001', ['lua', 'csharp'], 'anti_analysis', 'low', 'low', 'بررسی حضور debugger.', /\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent)\b/gi),
  rule('SH-ANTI-002', ['lua', 'csharp'], 'anti_analysis', 'low', 'low', 'نشانهٔ بررسی VMware/VirtualBox/Sandboxie.', /\b(?:vmware|virtualbox|sandboxie|sbiedll)\b/gi),

  // ---------- Shared: reconnaissance ----------
  rule('SH-REC-001', ['lua', 'csharp'], 'system_recon', 'low', 'low', 'جمع‌آوری نام کاربر/ماشین؛ سیگنال ضعیف.', /\b(?:Environment\.(?:UserName|MachineName)|whoami|hostname)\b/gi),
  rule('SH-REC-002', ['lua', 'csharp'], 'system_recon', 'low', 'low', 'فهرست‌کردن processها؛ سیگنال ضعیف.', /\b(?:Process\.GetProcesses|tasklist)\b/gi),
]);

const COMBINATION_RULES = Object.freeze([
  {
    id: 'SC-COMBO-001', categories: ['credential_theft', 'data_exfiltration'],
    bonus: 34, riskFloor: 'malicious', confidence: 'high',
    description: 'شواهد مستقل سرقت اطلاعات + کانال خروج داده هم‌زمان دیده شد.',
  },
  {
    id: 'SC-COMBO-002', categories: ['credential_theft', 'c2_networking'],
    bonus: 26, riskFloor: 'suspicious', confidence: 'high',
    description: 'شواهد دسترسی به اطلاعات حساس همراه ارتباط شبکه/C2 دیده شد.',
  },
  {
    id: 'SC-COMBO-003', categories: ['network_download', 'command_execution'],
    bonus: 24, riskFloor: 'suspicious', confidence: 'high',
    description: 'دانلود محتوا و اجرای process/command در یک اسکریپت هم‌زمان دیده شد.',
  },
  {
    id: 'SC-COMBO-004', categories: ['dynamic_execution', 'obfuscation'],
    bonus: 16, riskFloor: 'suspicious', confidence: 'high',
    description: 'اجرای پویا همراه با پنهان‌سازی/رمزگذاری محتوا دیده شد.',
  },
  {
    id: 'SC-COMBO-005', categories: ['dynamic_execution', 'obfuscation', 'network_download'],
    bonus: 38, riskFloor: 'malicious', confidence: 'high',
    description: 'دانلود + پنهان‌سازی + اجرای پویا یک زنجیرهٔ رفتاری بسیار پرریسک می‌سازد.',
  },
  {
    id: 'SC-COMBO-006', categories: ['persistence', 'command_execution'],
    bonus: 20, riskFloor: 'suspicious', confidence: 'medium',
    description: 'اجرای process/command همراه persistence دیده شد.',
  },
  {
    id: 'SC-COMBO-007', categories: ['file_destruction', 'command_execution'],
    bonus: 38, riskFloor: 'malicious', confidence: 'high',
    description: 'فرمان‌های تخریبی همراه قابلیت اجرای command دیده شد.',
  },
]);

function nowMs() {
  return (typeof performance !== 'undefined' && performance && typeof performance.now === 'function')
    ? performance.now()
    : Date.now();
}

function getExtension(name) {
  const lower = String(name || '').toLowerCase();
  const i = lower.lastIndexOf('.');
  return i >= 0 ? lower.slice(i) : '';
}

function languageForExtension(ext) {
  if (ext === '.lua') return 'lua';
  if (ext === '.cs') return 'csharp';
  return null;
}

function buildBase(overrides) {
  return Object.assign({
    analyzerVersion: SCRIPT_ANALYZER_VERSION,
    supported: false,
    language: null,
    verdict: 'invalid',
    confidence: 'low',
    score: null,
    hash: null,
    evidence: [],
    reasons: [],
    limits: SCRIPT_LIMITS,
    warnings: [],
    errorCode: null,
    metrics: null,
    urls: [],
    combinationRulesFired: [],
  }, overrides || {});
}

function detectBinaryLike(bytes) {
  if (!bytes || bytes.length === 0) return { binary: false, nulCount: 0, controlRatio: 0 };
  const sampleLen = Math.min(bytes.length, 65536);
  let nulCount = 0;
  let controlCount = 0;
  for (let i = 0; i < sampleLen; i++) {
    const b = bytes[i];
    if (b === 0) nulCount++;
    if ((b < 0x09) || (b > 0x0d && b < 0x20)) controlCount++;
  }
  const controlRatio = controlCount / sampleLen;
  return {
    binary: nulCount > 0 || controlRatio > 0.02,
    nulCount,
    controlRatio,
  };
}

function stripComments(text, language) {
  return language === 'lua' ? stripLuaComments(text) : stripCSharpComments(text);
}

function stripLuaComments(text) {
  const out = text.split('');
  let quote = null;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];
    if (quote) {
      if (escaped) { escaped = false; continue; }
      if (c === '\\') { escaped = true; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '-' && n === '-') {
      // long comment --[[ ... ]]
      if (text[i + 2] === '[' && text[i + 3] === '[') {
        out[i] = out[i + 1] = out[i + 2] = out[i + 3] = ' ';
        i += 4;
        while (i < text.length - 1 && !(text[i] === ']' && text[i + 1] === ']')) {
          if (text[i] !== '\n' && text[i] !== '\r') out[i] = ' ';
          i++;
        }
        if (i < text.length - 1) { out[i] = out[i + 1] = ' '; i++; }
      } else {
        out[i] = out[i + 1] = ' ';
        i += 2;
        while (i < text.length && text[i] !== '\n') { if (text[i] !== '\r') out[i] = ' '; i++; }
        i--;
      }
    }
  }
  return out.join('');
}

function stripCSharpComments(text) {
  const out = text.split('');
  let quote = null;
  let escaped = false;
  let verbatim = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];

    if (quote) {
      if (verbatim && quote === '"') {
        if (c === '"' && n === '"') { i++; continue; }
        if (c === '"') { quote = null; verbatim = false; }
        continue;
      }
      if (escaped) { escaped = false; continue; }
      if (c === '\\') { escaped = true; continue; }
      if (c === quote) quote = null;
      continue;
    }

    if (c === '@' && n === '"') { quote = '"'; verbatim = true; i++; continue; }
    if (c === '"' || c === "'") { quote = c; continue; }

    if (c === '/' && n === '/') {
      out[i] = out[i + 1] = ' ';
      i += 2;
      while (i < text.length && text[i] !== '\n') { if (text[i] !== '\r') out[i] = ' '; i++; }
      i--;
      continue;
    }
    if (c === '/' && n === '*') {
      out[i] = out[i + 1] = ' ';
      i += 2;
      while (i < text.length - 1 && !(text[i] === '*' && text[i + 1] === '/')) {
        if (text[i] !== '\n' && text[i] !== '\r') out[i] = ' ';
        i++;
      }
      if (i < text.length - 1) { out[i] = out[i + 1] = ' '; i++; }
    }
  }
  return out.join('');
}

function buildLineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineForIndex(lineStarts, index) {
  let lo = 0, hi = lineStarts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (lineStarts[mid] <= index) lo = mid + 1;
    else hi = mid - 1;
  }
  return Math.max(1, hi + 1);
}

function sanitizeSnippet(value) {
  return String(value || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .slice(0, 180);
}

function addFinding(findings, seen, item) {
  if (findings.length >= SCRIPT_LIMITS.MAX_FINDINGS) return false;
  const key = item.rule + ':' + item.line + ':' + item.match.toLowerCase();
  if (seen.has(key)) return true;
  seen.add(key);
  findings.push(item);
  return true;
}

function scanRules(text, language, lineStarts, deadline) {
  const findings = [];
  const seen = new Set();
  let timedOut = false;

  for (const r of RULES) {
    if (nowMs() > deadline) { timedOut = true; break; }
    if (!r.languages.includes(language)) continue;
    r.regex.lastIndex = 0;
    let count = 0;
    let match;
    while ((match = r.regex.exec(text)) !== null) {
      if (nowMs() > deadline) { timedOut = true; break; }
      const matchedText = match[0] || '';
      addFinding(findings, seen, {
        rule: r.id,
        category: r.category,
        severity: r.severity,
        confidence: r.confidence,
        weight: SEVERITY_WEIGHT[r.severity] || 0,
        line: lineForIndex(lineStarts, match.index),
        match: sanitizeSnippet(matchedText),
        explanation: r.description,
      });
      count++;
      if (count >= r.maxMatches || findings.length >= SCRIPT_LIMITS.MAX_FINDINGS) break;
      // Safety guard for a zero-length regex even though current rules don't use one.
      if (matchedText.length === 0) r.regex.lastIndex++;
    }
    if (timedOut || findings.length >= SCRIPT_LIMITS.MAX_FINDINGS) break;
  }

  return { findings, timedOut, truncated: findings.length >= SCRIPT_LIMITS.MAX_FINDINGS };
}

function scanLongBase64(text, lineStarts, deadline, findings) {
  if (nowMs() > deadline || findings.length >= SCRIPT_LIMITS.MAX_FINDINGS) return;
  const re = /(?:[A-Za-z0-9+\/]{4}){40,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/g;
  const seen = new Set(findings.map(f => f.rule + ':' + f.line + ':' + f.match.toLowerCase()));
  let count = 0;
  let m;
  while ((m = re.exec(text)) !== null && count < 3 && findings.length < SCRIPT_LIMITS.MAX_FINDINGS) {
    if (nowMs() > deadline) break;
    addFinding(findings, seen, {
      rule: 'SH-OBF-BASE64-BLOB', category: 'obfuscation', severity: 'medium', confidence: 'medium', weight: 10,
      line: lineForIndex(lineStarts, m.index), match: '[base64-like blob ' + m[0].length + ' chars]',
      explanation: 'رشتهٔ Base64-like طولانی؛ به‌تنهایی بدافزار نیست اما همراه اجرای پویا اهمیت بیشتری دارد.',
    });
    count++;
  }
}

function extractUrls(text, deadline) {
  const urls = [];
  const re = /https?:\/\/[^\s"'<>\]\[(){}]{4,512}/gi;
  let m;
  while ((m = re.exec(text)) !== null && urls.length < SCRIPT_LIMITS.MAX_URLS) {
    if (nowMs() > deadline) break;
    urls.push(m[0].slice(0, 512));
  }
  return urls;
}

function calculateMetrics(text) {
  const lines = text.split('\n');
  let maxLineLength = 0;
  let veryLongLines = 0;
  for (const line of lines) {
    const len = Math.min(line.length, SCRIPT_LIMITS.MAX_LINE_LENGTH_FOR_METRICS + 1);
    if (len > maxLineLength) maxLineLength = len;
    if (len > 2000) veryLongLines++;
  }
  return {
    charCount: text.length,
    lineCount: lines.length,
    maxLineLength,
    veryLongLineCount: veryLongLines,
  };
}

function summarizeCategoryScore(items) {
  if (!items || items.length === 0) return 0;
  const weights = items.map(i => i.weight || 0).sort((a, b) => b - a);
  let total = weights[0] || 0;
  for (let i = 1; i < weights.length; i++) total += weights[i] * (i === 1 ? 0.35 : 0.15);
  return Math.min(40, total);
}

function scoreFindings(findings) {
  const byCategory = new Map();
  for (const f of findings) {
    if ((f.weight || 0) <= 0) continue;
    if (!byCategory.has(f.category)) byCategory.set(f.category, []);
    byCategory.get(f.category).push(f);
  }

  let penalty = 0;
  for (const items of byCategory.values()) penalty += summarizeCategoryScore(items);

  const categories = new Set(byCategory.keys());
  const fired = [];
  for (const combo of COMBINATION_RULES) {
    if (combo.categories.every(c => categories.has(c))) {
      penalty += combo.bonus;
      fired.push(combo);
    }
  }

  // Strong obfuscation metric is deliberately not an automatic verdict.
  let score = Math.round(Math.max(0, Math.min(100, 100 - penalty)));
  // Hardening v1: یک شاهد high-confidence/high-severity منفرد باید دست‌کم SUSPICIOUS شود،
  // نه SAFE. این هنوز هرگز یک API منفرد را MALICIOUS نمی‌کند.
  let verdict = score >= 85 ? 'safe' : score >= 50 ? 'suspicious' : 'malicious';

  for (const combo of fired) {
    if (combo.riskFloor && VERDICT_RANK[combo.riskFloor] > VERDICT_RANK[verdict]) verdict = combo.riskFloor;
  }

  const highCount = findings.filter(f => f.severity === 'high' || f.severity === 'critical').length;
  let confidence = 'low';
  if (fired.length > 0 || categories.size >= 3) confidence = 'high';
  else if (categories.size >= 2 || highCount > 0) confidence = 'medium';

  return { score, verdict, confidence, fired, categories };
}

async function sha256Hex(bytes) {
  try {
    if (typeof crypto === 'undefined' || !crypto.subtle || typeof crypto.subtle.digest !== 'function') return null;
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    return null;
  }
}

function verdictReason(verdict) {
  if (verdict === 'safe') return 'نشانهٔ مخرب قابل‌توجهی در تحلیل ایستای اسکریپت شناسایی نشد.';
  if (verdict === 'suspicious') return 'چند نشانهٔ امنیتی قابل‌توجه در اسکریپت دیده شد و بررسی بیشتر توصیه می‌شود.';
  if (verdict === 'malicious') return 'ترکیب چند شاهد مستقل و قوی، رفتار اسکریپت را بسیار پرریسک نشان می‌دهد.';
  return 'تحلیل اسکریپت کامل نشد.';
}

const ScriptAnalyzer = {
  version: SCRIPT_ANALYZER_VERSION,
  limits: SCRIPT_LIMITS,

  async analyze(file) {
    const startedAt = nowMs();
    const deadline = startedAt + SCRIPT_LIMITS.MAX_ANALYSIS_TIME_MS;

    if (!file || typeof file !== 'object' || typeof file.name !== 'string' || typeof file.arrayBuffer !== 'function') {
      return buildBase({ errorCode: ERROR_CODES.INVALID_INPUT, reasons: ['ورودی ScriptAnalyzer یک File-like معتبر نیست.'] });
    }

    const ext = getExtension(file.name);
    const language = languageForExtension(ext);
    if (!language) {
      return buildBase({
        errorCode: ERROR_CODES.UNSUPPORTED_EXTENSION,
        reasons: ['ScriptAnalyzer v1.0.0 فقط فایل‌های .lua و .cs را پشتیبانی می‌کند.'],
      });
    }

    if (!Number.isFinite(file.size) || file.size <= 0) {
      return buildBase({ supported: true, language, errorCode: ERROR_CODES.EMPTY_FILE, reasons: ['فایل اسکریپت خالی یا اندازهٔ آن نامعتبر است.'] });
    }
    if (file.size > SCRIPT_LIMITS.MAX_SCRIPT_SIZE) {
      return buildBase({
        supported: true, language, errorCode: ERROR_CODES.TOO_LARGE,
        reasons: ['اندازهٔ اسکریپت از سقف ' + SCRIPT_LIMITS.MAX_SCRIPT_SIZE + ' بایت بیشتر است؛ برای جلوگیری از مصرف بی‌رویه تحلیل نشد.'],
      });
    }

    let buffer;
    try {
      buffer = await file.arrayBuffer();
    } catch (e) {
      return buildBase({ supported: true, language, errorCode: ERROR_CODES.READ_FAILED, reasons: ['خواندن بایت‌های اسکریپت ناموفق بود.'] });
    }

    const bytes = new Uint8Array(buffer);
    if (bytes.byteLength === 0) {
      return buildBase({ supported: true, language, errorCode: ERROR_CODES.EMPTY_FILE, reasons: ['فایل اسکریپت خالی است.'] });
    }
    if (bytes.byteLength > SCRIPT_LIMITS.MAX_SCRIPT_SIZE) {
      return buildBase({ supported: true, language, errorCode: ERROR_CODES.TOO_LARGE, reasons: ['اندازهٔ واقعی بایت‌های فایل از سقف ScriptAnalyzer بیشتر است.'] });
    }

    const binary = detectBinaryLike(bytes);
    if (binary.binary) {
      return buildBase({
        supported: true, language, errorCode: ERROR_CODES.BINARY_LIKE_INPUT,
        reasons: ['محتوای فایل شبیه متن منبع Lua/C# نیست (NUL/control-byte غیرعادی دیده شد)؛ فایل اجرا یا به‌زور decode نشد.'],
        metrics: { nulCount: binary.nulCount, controlRatio: binary.controlRatio },
      });
    }

    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (e) {
      return buildBase({
        supported: true, language, errorCode: ERROR_CODES.INVALID_UTF8,
        reasons: ['اسکریپت UTF-8 معتبر نیست؛ برای جلوگیری از تفسیر مبهم تحلیل متنی متوقف شد.'],
      });
    }

    // UTF-8 BOM را فقط از ابتدای فایل حذف می‌کنیم.
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    if (text.length === 0 || text.trim().length === 0) {
      return buildBase({ supported: true, language, errorCode: ERROR_CODES.EMPTY_FILE, reasons: ['اسکریپت پس از decode خالی است.'] });
    }
    if (text.length > SCRIPT_LIMITS.MAX_TEXT_LENGTH) {
      return buildBase({ supported: true, language, errorCode: ERROR_CODES.TOO_LARGE, reasons: ['متن decode‌شده از سقف ScriptAnalyzer بیشتر است.'] });
    }

    const hashPromise = sha256Hex(bytes);
    const cleaned = stripComments(text, language);
    const lineStarts = buildLineStarts(cleaned);
    const metrics = calculateMetrics(cleaned);

    const ruleScan = scanRules(cleaned, language, lineStarts, deadline);
    const findings = ruleScan.findings;
    scanLongBase64(cleaned, lineStarts, deadline, findings);

    // یک خط بسیار طولانی به‌تنهایی malicious نیست؛ فقط یک شاهد low برای
    // obfuscation می‌سازد تا در ترکیب با dynamic execution معنی پیدا کند.
    if (metrics.veryLongLineCount > 0 && findings.length < SCRIPT_LIMITS.MAX_FINDINGS) {
      findings.push({
        rule: 'SH-OBF-LONG-LINE', category: 'obfuscation', severity: 'low', confidence: 'low', weight: 4,
        line: null, match: metrics.veryLongLineCount + ' very-long line(s)',
        explanation: 'خط‌های بسیار طولانی می‌توانند حاصل minify/obfuscation باشند؛ این شاهد به‌تنهایی ضعیف است.',
      });
    }

    if (ruleScan.timedOut || nowMs() > deadline) {
      return buildBase({
        supported: true, language, verdict: 'inconclusive', confidence: 'low', score: null,
        hash: await hashPromise, evidence: findings,
        reasons: ['بودجهٔ زمانی ScriptAnalyzer تمام شد؛ برای جلوگیری از نتیجهٔ ناقص SAFE صادر نشد.'],
        warnings: ruleScan.truncated ? ['فهرست یافته‌ها به سقف MAX_FINDINGS رسید.'] : [],
        errorCode: ERROR_CODES.ANALYSIS_TIMEOUT, metrics,
      });
    }

    const urls = extractUrls(cleaned, deadline);
    const scored = scoreFindings(findings);
    const reasons = [verdictReason(scored.verdict)];

    // فقط یافته‌های مهم‌تر را به دلایل انسانی تبدیل می‌کنیم؛ evidence کامل‌تر است.
    const important = findings.filter(f => f.severity === 'high' || f.severity === 'critical').slice(0, 6);
    for (const f of important) {
      reasons.push((f.line ? 'خط ' + f.line + ': ' : '') + f.explanation);
    }
    for (const combo of scored.fired) reasons.push('ترکیب رفتاری: ' + combo.description);

    const warnings = [];
    if (ruleScan.truncated) warnings.push('تعداد یافته‌ها به سقف MAX_FINDINGS رسید؛ خروجی evidence کوتاه شده است.');
    if (metrics.veryLongLineCount > 0) warnings.push('یک یا چند خط بسیار طولانی دیده شد؛ ممکن است minified/obfuscated یا صرفاً دادهٔ تعبیه‌شده باشد.');

    return buildBase({
      supported: true,
      language,
      verdict: scored.verdict,
      confidence: scored.confidence,
      score: scored.score,
      hash: await hashPromise,
      evidence: findings,
      reasons,
      warnings,
      errorCode: null,
      metrics,
      urls,
      combinationRulesFired: scored.fired.map(c => ({
        id: c.id, categories: c.categories.slice(), riskFloor: c.riskFloor, description: c.description,
      })),
    });
  },
};

window.ScriptAnalyzer = ScriptAnalyzer;

})();

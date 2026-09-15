(function () {
/* ============================================================
   GTA Guard — archive-inspector.js  (Archive Inspection v1.0.3)
   ------------------------------------------------------------
   این فایل یک بازکنندهٔ آرشیو (extractor) یا sandbox اجرا نیست.

   کارش فقط این است: بستهٔ آرشیو را ایمن و فقط-خواندنی (read-only)
   بازرسی کند و محتوای آن را «شناسایی» کند — بدون اینکه هرگز چیزی
   استخراج، اجرا، بارگذاری، یا به فایل‌سیستم واقعی کاربر نوشته شود.

   محدودیت طراحی v1.0.0 (آگاهانه و مستند):
     فقط ZIP پشتیبانی می‌شود، و فقط در سطح متادیتا — یعنی فقط
     Central Directory آن خوانده می‌شود (نام فایل‌ها، اندازه‌های
     اعلام‌شده، روش فشرده‌سازی). هیچ داده‌ای هرگز decompress نمی‌شود.

     چرا؟ چون هیچ کتابخانهٔ فشرده‌سازی‌ای از قبل در این پروژهٔ کاملاً
     vanilla وجود ندارد، و نوشتن یک inflate/LZMA از صفر دقیقاً همان
     کاری است که این پروژه صراحتاً از آن پرهیز می‌کند. مزیت جانبی
     مهم: چون هرگز decompress نمی‌کنیم، بمب فشرده‌سازی (zip bomb) به
     شکل کلاسیک آن اصلاً امکان‌پذیر نیست — نمی‌توان با decompression
     غیرواقعی حافظه را پر کرد.

     7z / RAR / RPF: این فرمت‌ها یا الگوریتم فشرده‌سازی اختصاصی/
     پیچیده دارند (7z/RAR) یا اصلاً مستند رسمی عمومی ندارند (RPF).
     به‌جای نوشتن یک پارسر ناایمن و ناقص، صادقانه:
       UNSUPPORTED_7Z / UNSUPPORTED_RAR / UNSUPPORTED_RPF
     برمی‌گردانیم.

   وابستگی‌ها:
     - از window.GtaModDetector (نسخهٔ منجمد ۱.۰.۰) برای طبقه‌بندی
       هر entry استفاده می‌کند — یک تشخیص‌دهندهٔ GTA دوم ساخته نشده.
     - به engine.js / rules.json / multilayer.js وابسته نیست و
       آن‌ها را در خود صدا نمی‌زند. مسیریابی entryهای .asi/.dll به
       Engine، کار یک مرحلهٔ یکپارچه‌سازی جداگانه در آینده است.

   امنیت مطلق:
     - هرگز چیزی را استخراج/باز/اجرا/کامپایل/eval نمی‌کند.
     - هرگز به فایل‌سیستم واقعی نمی‌نویسد.
     - هرگز چیزی به هیچ سروری ارسال نمی‌کند.
     - فقط بایت‌های خام آرشیو را در حافظه می‌خواند و تفسیر می‌کند.

   قرارداد امنیتی با ArchiveEntryReader (صریح‌شده در v1.0.3):
     مقادیر pluginTargetDescriptors / scriptTargetDescriptors (شامل canonicalPath، lfhOffset،
     compressedSize، uncompressedSize، crc32، compressionMethod) صرفاً
     «کاندیدهای نامعتبرشدهٔ متادیتایی» هستند — نه اثبات ایمن یا آماده
     بودن یک entry برای خواندن/استخراج. این مقادیر مستقیماً از
     Central Directory خوانده شده‌اند و ArchiveInspector هرگز آن‌ها را
     در برابر Local File Header واقعی متناظرشان تطبیق نمی‌دهد (این کار
     عمداً اینجا انجام نمی‌شود تا از تکرار پارسر ArchiveEntryReader
     پرهیز شود). مصرف‌کننده (ArchiveEntryReader) موظف است پیش از هر
     دسترسی به داده‌های واقعی entry، ساختار Local File Header و
     محدودهٔ واقعی آن را کاملاً و مستقل بازاعتبارسنجی کند.
   ============================================================ */

'use strict';

const ARCHIVE_INSPECTOR_VERSION = '1.1.0'; // v1.1.0: افزوده‌شدن scriptTargetDescriptors برای .lua/.cs با همان سیاست fail-closed مسیر/تکرار

/* ------------------------------------------------------------
   محدودیت‌های صریح و مستند — هیچ‌کدام نامحدود نیستند (طبق الزام
   سند: «Do NOT choose unlimited values»).
   ------------------------------------------------------------ */
const LIMITS = Object.freeze({
  MAX_ARCHIVE_SIZE: 150 * 1024 * 1024,      // ۱۵۰ مگابایت — بزرگ‌تر از سقف تک‌فایل Engine چون یک بسته می‌تواند شامل چند دارایی حجیم باشد
  MAX_ENTRIES: 20000,                        // سقف تعداد ورودی‌های Central Directory که پردازش می‌شوند
  MAX_EOCD_SEARCH_WINDOW: 22 + 65535,        // حداکثر طول رکورد EOCD + حداکثر طول comment مجاز طبق مشخصات ZIP
  MAX_PATH_LENGTH: 512,                      // طول مسیر هر entry
  MAX_INSPECTION_TIME_MS: 8000,              // بودجهٔ زمانی نرم برای کل بازرسی
  CENTRAL_DIR_HEADER_MIN_SIZE: 46,           // اندازهٔ ثابت هدر هر ورودی Central Directory (بدون نام/extra/comment)
  EOCD_MIN_SIZE: 22,
  SUSPICIOUS_COMPRESSION_RATIO: 1000,        // نسبت uncompressed/compressed که به‌عنوان شاهد ضعیفِ «بمب احتمالی» علامت‌گذاری می‌شود
  MAX_TOTAL_DECLARED_UNCOMPRESSED: 5 * 1024 * 1024 * 1024, // ۵ گیگابایت — فقط یک بررسی معقولیت روی مجموع اعداد اعلام‌شده، نه واقعیت
  MAX_NESTING_DEPTH_SUPPORTED: 0,            // v1.0.0 هرگز وارد آرشیوهای تودرتو نمی‌شود؛ فقط شناسایی‌شان می‌کند
});

const INSPECTION_STATUS = Object.freeze({
  COMPLETED: 'completed',
  COMPLETED_PARTIAL_TIMEOUT: 'completed_partial_timeout',
  COMPLETED_NON_GTA: 'completed_non_gta',
  UNSUPPORTED_7Z: 'unsupported_7z',
  UNSUPPORTED_RAR: 'unsupported_rar',
  UNSUPPORTED_RPF: 'unsupported_rpf',
  UNSUPPORTED_FORMAT: 'unsupported_format',
  MALFORMED_ARCHIVE: 'malformed_archive',
  TOO_LARGE: 'too_large',
  INVALID_INPUT: 'invalid_input',
});

/* ============================================================
   ابزارهای امن بایت/رشته (همان الگوی bounds-checking در engine.js)
   ============================================================ */

/**
 * v1.0.3: یک ساعت مشترک برای کل جریان بازرسی. قبلاً این fallback
 * (performance.now در برابر Date.now) در چند نقطهٔ مختلف تکرار شده بود؛
 * یکی‌کردن آن هم رفع تکرار است و هم پیش‌نیاز رفع ایراد ۲ (بودجهٔ زمانی
 * مشترک و صادقانه در کل inspect()، نه فقط داخل حلقهٔ classifyEntries).
 * توجه: این صرفاً یک ساعت برای بررسی مشارکتی (cooperative) بودجه است؛
 * هیچ توانایی واقعی برای متوقف‌کردن اجباری یک Promise در حال اجرا در
 * جاوااسکریپت مرورگر وجود ندارد و این کد چنین ادعایی نمی‌کند.
 */
function nowMs() {
  return (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
}

function inBounds(totalLength, offset, size) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size)) return false;
  if (offset < 0 || size < 0) return false;
  if (offset > totalLength) return false;
  return size <= totalLength - offset;
}

function decodeUtf8Safe(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch (e) {
    return '';
  }
}

/* ============================================================
   تشخیص مسیرهای مشکوک — فقط بررسی رشته، هرگز فایل‌سیستم را لمس
   نمی‌کند (چون اصلاً چیزی استخراج نمی‌شود).
   ============================================================ */
const PATH_TRAVERSAL_RE = /(^|[\\/])\.\.([\\/]|$)/;
const ABSOLUTE_PATH_RE = /^[\\/]/;
const DRIVE_LETTER_RE = /^[A-Za-z]:[\\/]/;
const UNC_PATH_RE = /^\\\\|^\/\//;
// کاراکترهای کنترلی جهت‌دهی دوسویهٔ یونیکد — روش شناخته‌شده برای
// فریب‌دادن نمایش پسوند فایل (مثل حملهٔ RTLO: gnp.exe به‌صورت
// exe.png نمایش داده می‌شود).
const BIDI_CONTROL_RE = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/;

function analyzeSuspiciousPath(path) {
  const issues = [];
  if (path.length > LIMITS.MAX_PATH_LENGTH) issues.push('path_too_long');
  if (PATH_TRAVERSAL_RE.test(path)) issues.push('path_traversal');
  if (ABSOLUTE_PATH_RE.test(path)) issues.push('absolute_path');
  if (DRIVE_LETTER_RE.test(path)) issues.push('drive_letter_path');
  if (UNC_PATH_RE.test(path)) issues.push('unc_path');
  if (BIDI_CONTROL_RE.test(path)) issues.push('bidi_control_characters');
  return issues;
}

/* ============================================================
   شناسایی نوع container بر اساس امضای بایت (magic bytes) — فقط
   برای انتخاب مسیر پردازش، نه یک ابزار طبقه‌بندی GTA (آن کار
   gta-mod-detector.js است و اینجا تکرار نمی‌شود).
   ============================================================ */
function bytesStartWith(bytes, expected) {
  if (!bytes || bytes.length < expected.length) return false;
  for (let i = 0; i < expected.length; i++) if (bytes[i] !== expected[i]) return false;
  return true;
}

async function sniffArchiveFormat(file) {
  try {
    const head = new Uint8Array(await file.slice(0, 8).arrayBuffer());
    if (bytesStartWith(head, [0x50, 0x4b, 0x03, 0x04])) return 'zip';
    if (bytesStartWith(head, [0x50, 0x4b, 0x05, 0x06])) return 'zip'; // آرشیو خالی
    if (bytesStartWith(head, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
    if (bytesStartWith(head, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return 'rar';
    const ascii4 = String.fromCharCode(head[0] || 0, head[1] || 0, head[2] || 0, head[3] || 0);
    if (ascii4 === 'RPF7' || ascii4 === 'RPF8') return 'rpf';
    return 'unknown';
  } catch (e) {
    return 'unknown';
  }
}

/* ============================================================
   یک «فایل مجازی» بدون بایت واقعی — برای دادن هر entry به
   GtaModDetector.analyze() بدون هیچ decompression ای. slice()/
   arrayBuffer() همیشه آرایهٔ خالی برمی‌گردانند (صادقانه: ما هیچ
   محتوایی نداریم، فقط متادیتا)؛ .name و .size واقعی و از Central
   Directory هستند.
   ============================================================ */
class VirtualArchiveEntryFile {
  constructor(name, declaredSize) {
    this.name = name;
    this.size = typeof declaredSize === 'number' && declaredSize >= 0 ? declaredSize : 0;
  }
  slice() { return new VirtualArchiveEntryFile(this.name, 0); }
  async arrayBuffer() { return new ArrayBuffer(0); }
}

/* ============================================================
   پارسر متادیتای ZIP — فقط Central Directory + EOCD. هرگز داده‌ای
   decompress نمی‌شود. هر آفست قبل از خواندن bounds-checked است.
   ============================================================ */

/** جست‌وجوی EOCD از انتهای فایل (طبق الگوریتم استاندارد ابزارهای zip) */
function findEndOfCentralDirectory(bytes) {
  const total = bytes.length;
  if (total < LIMITS.EOCD_MIN_SIZE) return null;

  const searchStart = Math.max(0, total - LIMITS.MAX_EOCD_SEARCH_WINDOW);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // جست‌وجو از انتها به ابتدا برای امضای EOCD (0x06054b50)
  for (let i = total - LIMITS.EOCD_MIN_SIZE; i >= searchStart; i--) {
    if (!inBounds(total, i, 4)) continue;
    if (view.getUint32(i, true) === 0x06054b50) {
      const commentLength = view.getUint16(i + 20, true);
      // اعتبارسنجی: طول comment ادعاشده باید دقیقاً تا انتهای فایل برسد
      if (i + LIMITS.EOCD_MIN_SIZE + commentLength === total) {
        return { offset: i, commentLength };
      }
      // اگر مطابقت نداشت، احتمالاً این یک تصادف بایتی است؛ ادامهٔ جست‌وجو
    }
  }
  return null;
}

/**
 * متادیتای Central Directory را می‌خواند. هرگز استثنای کنترل‌نشده
 * پرتاب نمی‌کند — در صورت هر ناهنجاری، وضعیت malformed برمی‌گرداند.
 */
function parseZipCentralDirectory(bytes) {
  const total = bytes.length;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const eocd = findEndOfCentralDirectory(bytes);
  if (!eocd) return { ok: false, reason: 'eocd_not_found' };

  if (!inBounds(total, eocd.offset, LIMITS.EOCD_MIN_SIZE)) return { ok: false, reason: 'eocd_out_of_bounds' };

  const totalEntriesThisDisk = view.getUint16(eocd.offset + 8, true);
  const totalEntries = view.getUint16(eocd.offset + 10, true);
  const centralDirSize = view.getUint32(eocd.offset + 12, true);
  const centralDirOffset = view.getUint32(eocd.offset + 16, true);

  // شناسایی صریح ZIP64 (مقادیر سنتینل 0xFFFF/0xFFFFFFFF) — به‌جای
  // تلاش برای پارس ناایمن رکورد ZIP64، صادقانه آن را unsupported
  // اعلام می‌کنیم (آرشیوهای مود GTA معمولی هرگز به ZIP64 نیاز ندارند).
  if (totalEntries === 0xffff || centralDirSize === 0xffffffff || centralDirOffset === 0xffffffff) {
    return { ok: false, reason: 'zip64_not_supported' };
  }

  if (totalEntries !== totalEntriesThisDisk) {
    // آرشیو چند-دیسکی — خارج از محدودهٔ این نسخه
    return { ok: false, reason: 'multi_disk_not_supported' };
  }
  if (totalEntries > LIMITS.MAX_ENTRIES) {
    return { ok: false, reason: 'too_many_entries' };
  }
  if (!inBounds(total, centralDirOffset, centralDirSize)) {
    return { ok: false, reason: 'central_directory_out_of_bounds' };
  }

  const entries = [];
  let malformedEntryCount = 0;
  let offset = centralDirOffset;
  let loopBrokeEarly = false;
  const centralDirEnd = centralDirOffset + centralDirSize;

  for (let i = 0; i < totalEntries; i++) {
    if (offset + LIMITS.CENTRAL_DIR_HEADER_MIN_SIZE > centralDirEnd) { malformedEntryCount++; loopBrokeEarly = true; break; }
    if (!inBounds(total, offset, LIMITS.CENTRAL_DIR_HEADER_MIN_SIZE)) { malformedEntryCount++; loopBrokeEarly = true; break; }

    const sig = view.getUint32(offset, true);
    if (sig !== 0x02014b50) { malformedEntryCount++; loopBrokeEarly = true; break; }

    const compressionMethod = view.getUint16(offset + 10, true);
    const crc32 = view.getUint32(offset + 16, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const fileNameLength = view.getUint16(offset + 28, true);
    const extraFieldLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const lfhOffset = view.getUint32(offset + 42, true); // v1.0.1: مورد نیاز برای targetDescriptor مصرفی ArchiveEntryReader

    const headerEnd = offset + LIMITS.CENTRAL_DIR_HEADER_MIN_SIZE;
    const nameEnd = headerEnd + fileNameLength;

    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff) {
      // این entry از ZIP64 extra field استفاده می‌کند — رد می‌شود، نه حدس زده می‌شود
      malformedEntryCount++;
    } else if (!inBounds(total, headerEnd, fileNameLength)) {
      malformedEntryCount++;
    } else {
      const nameBytes = bytes.subarray(headerEnd, nameEnd);
      const name = decodeUtf8Safe(nameBytes);
      entries.push({ name, compressionMethod, crc32, compressedSize, uncompressedSize, lfhOffset });
    }

    offset = headerEnd + fileNameLength + extraFieldLength + commentLength;
  }

  // --- v1.0.2 (سخت‌سازی ۱): اعتبارسنجی دقیق پایان Central Directory ---
  // اگر آفست نهایی پارسر دقیقاً برابر با centralDirEnd نباشد — چه به‌خاطر
  // بایت‌های اضافه/باقی‌مانده داخل محدودهٔ اعلام‌شدهٔ CD، و چه به‌خاطر
  // توقف زودهنگام حلقه به‌دلیل یک ورودی بدشکل — دیگر به‌صورت نرم و با
  // صرفاً یک هشدار (truncated) پذیرفته نمی‌شود؛ کل تجزیه fail-closed
  // رد می‌شود. هرگز نباید بایت‌های داخل محدودهٔ اعلام‌شدهٔ CD که تفسیر
  // نشده‌اند را نادیده گرفت.
  if (offset !== centralDirEnd || loopBrokeEarly) {
    return { ok: false, reason: 'central_directory_size_mismatch' };
  }

  return {
    ok: true,
    entries,
    malformedEntryCount,
    declaredTotalEntries: totalEntries,
    truncated: entries.length + malformedEntryCount < totalEntries,
  };
}

/* ============================================================
   طبقه‌بندی entryها با استفادهٔ مجدد از GtaModDetector (نه یک
   تشخیص‌دهندهٔ دوم) + تحلیل مسیر مشکوک + بودجهٔ زمانی
   ============================================================ */
async function classifyEntries(entries, inspectionStartTime) {
  const result = {
    entryDetails: [],
    pluginCount: 0,
    scriptCount: 0,
    assetCount: 0,
    executableEntryCount: 0,
    nestedArchiveCount: 0,
    unknownCount: 0,
    suspiciousPathCount: 0,
    doubleExtensionCount: 0,
    duplicatePathCount: 0,
    gtaClassifiedEntryCount: 0,
    timedOut: false,
    // v1.0.1: فهرست کاندیدهای قابل‌استخراج (.asi/.dll) — فقط یک
    // فهرست است، هیچ انتخاب خودکاری انجام نمی‌شود. مصرف‌کننده (یا
    // کاربر) باید صراحتاً یکی از این‌ها را به‌عنوان targetDescriptor
    // به ArchiveEntryReader.readEntry() بدهد.
    pluginTargetDescriptors: [],
    // v1.1.0: کاندیدهای .lua/.cs برای ScriptAnalyzer. همانند pluginها،
    // فقط متادیتای تأییدنشده‌اند و ArchiveEntryReader باید قبل از خواندن
    // بایت واقعی، Central Directory/LFH/CRC را مستقلاً بازاعتبارسنجی کند.
    scriptTargetDescriptors: [],
  };

  // برای شناسایی مسیرهای تکراری/متعارض — طبیعی‌سازی به کوچک‌حرف چون
  // بسیاری از فایل‌سیستم‌ها (از جمله ویندوز) به حروف بزرگ/کوچک حساس
  // نیستند و دو ورودی با نام‌های متفاوت فقط در بزرگی حروف می‌توانند
  // در عمل با هم تعارض داشته باشند (یک روش شناخته‌شده برای فریب
  // ابزارهای استخراج). این‌جا هیچ استخراجی رخ نمی‌دهد؛ فقط شناسایی.
  const seenNormalizedPaths = new Map(); // normalizedPath -> count seen so far (drives existing isDuplicatePath/duplicatePathCount reporting, unchanged)

  // v1.0.2 (سخت‌سازی ۲): پیش‌محاسبهٔ تعداد کل تکرار هر مسیر نرمال‌شده
  // در کل آرشیو (نه فقط «تاکنون دیده‌شده»). این صرفاً برای تصمیم
  // واجد-شرایط‌بودن یک entry جهت ورود به pluginTargetDescriptors
  // استفاده می‌شود — اگر یک مسیر بیش از یک‌بار در آرشیو ظاهر شود،
  // حتی وقوع اول آن هم دیگر یک هدف بدون‌ابهام نیست (همان منطقی که
  // ArchiveEntryReader را وادار می‌کند duplicate_target_entry را رد
  // کند، نه فقط دومین رخداد را). گزارش‌دهی موجود entries/isDuplicatePath
  // دست‌نخورده باقی می‌ماند.
  const totalPathOccurrences = new Map();
  for (const e of entries) {
    if (e.name.endsWith('/') && e.uncompressedSize === 0) continue;
    const np = e.name.toLowerCase().replace(/\\/g, '/');
    totalPathOccurrences.set(np, (totalPathOccurrences.get(np) || 0) + 1);
  }

  // v1.0.3 (رفع ایراد ۲): از ساعت مشترکِ شروعِ کل بازرسی استفاده می‌کنیم
  // (که از inspect()/inspectZip() پاس داده شده)، نه یک ساعت محلی که فقط
  // از همین‌جا شروع می‌شد. با این تغییر، بودجهٔ ۸۰۰۰ میلی‌ثانیه واقعاً
  // کل جریان (خواندن فایل + تجزیهٔ CD + این حلقه) را می‌سنجد، نه فقط
  // بخشی از آن — یعنی «۸۰۰۰ میلی‌ثانیه» دیگر گمراه‌کننده نیست.
  for (let i = 0; i < entries.length; i++) {
    if (i % 100 === 0 && (nowMs() - inspectionStartTime) > LIMITS.MAX_INSPECTION_TIME_MS) {
      result.timedOut = true;
      break;
    }

    const entry = entries[i];
    // فایل‌های پوشه (نام با / پایان می‌یابد و اندازهٔ صفر) صرفاً نادیده گرفته می‌شوند
    if (entry.name.endsWith('/') && entry.uncompressedSize === 0) continue;

    const pathIssues = analyzeSuspiciousPath(entry.name);
    const suspiciousPath = pathIssues.length > 0;
    if (suspiciousPath) result.suspiciousPathCount++;

    const normalizedPath = entry.name.toLowerCase().replace(/\\/g, '/');
    const priorCount = seenNormalizedPaths.get(normalizedPath) || 0;
    const isDuplicate = priorCount > 0;
    if (isDuplicate) result.duplicatePathCount++;
    seenNormalizedPaths.set(normalizedPath, priorCount + 1);

    let detectorResult = null;
    try {
      const virtualFile = new VirtualArchiveEntryFile(entry.name, entry.uncompressedSize);
      detectorResult = await window.GtaModDetector.analyze(virtualFile);
    } catch (e) {
      detectorResult = null;
    }

    const modType = detectorResult ? detectorResult.modType : 'unknown';
    if (detectorResult && detectorResult.suspiciousPackaging) result.doubleExtensionCount++;
    if (detectorResult && detectorResult.isGtaMod) result.gtaClassifiedEntryCount++;

    switch (modType) {
      case 'plugin': result.pluginCount++; break;
      case 'script': result.scriptCount++; break;
      case 'asset':
      case 'metadata': result.assetCount++; break;
      case 'archive':
      case 'package': result.nestedArchiveCount++; break;
      case 'executable': result.executableEntryCount++; result.unknownCount++; break;
      default: result.unknownCount++; break;
    }

    // v1.0.2 (سخت‌سازی ۲): یک targetDescriptor فقط وقتی ساخته می‌شود که
    // ALL این شروط برقرار باشند: پلاگین واقعی (.asi/.dll مؤثر، نه پوشه)،
    // مسیر مشکوک نباشد، و مسیر تکراری/متعارض نباشد. توجه: این هرگز به
    // این معنا نیست که چنین entryهایی از entries/entryDetails پنهان
    // می‌شوند — آن‌ها همچنان با پرچم‌های suspiciousPath/isDuplicatePath
    // خودشان گزارش می‌شوند؛ فقط از فهرست کاندیدهای قابل‌استخراج حذف می‌شوند.
    //
    // v1.0.3 (رفع ایراد ۴ — یادآوری قرارداد امنیتی): حتی وقتی همهٔ این
    // شرط‌ها برقرار باشند، آبجکت زیر یک «کاندید متادیتایی نامعتبرشده»
    // است، نه گواهی امن‌بودن. این فایل عمداً LFH واقعی را نمی‌خواند و
    // با CD تطبیق نمی‌دهد — آن مسئولیت مستقل و اجباری ArchiveEntryReader
    // است، پیش از هرگونه دسترسی به داده‌های واقعی entry.
    const lowerName = entry.name.toLowerCase();
    const isRealPluginExtension = !lowerName.endsWith('/') &&
      (lowerName.endsWith('.asi') || lowerName.endsWith('.dll'));
    if (modType === 'plugin' && isRealPluginExtension && !suspiciousPath && !isDuplicate &&
        totalPathOccurrences.get(normalizedPath) === 1) {
      result.pluginTargetDescriptors.push({
        targetType: 'plugin',
        canonicalPath: entry.name,
        lfhOffset: entry.lfhOffset,
        compressedSize: entry.compressedSize,
        uncompressedSize: entry.uncompressedSize,
        crc32: entry.crc32,
        compressionMethod: entry.compressionMethod,
      });
    }

    // v1.1.0: Script target فقط برای پسوند مؤثر .lua/.cs ساخته می‌شود.
    // مسیر مشکوک، duplicate path و پسوند دوگانه/بسته‌بندی مشکوک هدف را
    // از فهرست قابل‌خواندن حذف می‌کند تا محتوای مبهم وارد Analyzer نشود.
    const isRealScriptExtension = !lowerName.endsWith('/') &&
      (lowerName.endsWith('.lua') || lowerName.endsWith('.cs'));
    const scriptPackagingSuspicious = Boolean(detectorResult && detectorResult.suspiciousPackaging);
    if (modType === 'script' && isRealScriptExtension && !suspiciousPath && !isDuplicate &&
        !scriptPackagingSuspicious && totalPathOccurrences.get(normalizedPath) === 1) {
      result.scriptTargetDescriptors.push({
        targetType: 'script',
        canonicalPath: entry.name,
        lfhOffset: entry.lfhOffset,
        compressedSize: entry.compressedSize,
        uncompressedSize: entry.uncompressedSize,
        crc32: entry.crc32,
        compressionMethod: entry.compressionMethod,
      });
    }

    const compressionRatio = entry.compressedSize > 0
      ? entry.uncompressedSize / entry.compressedSize
      : (entry.uncompressedSize > 0 ? Infinity : 0);

    result.entryDetails.push({
      name: entry.name,
      compressedSize: entry.compressedSize,
      uncompressedSize: entry.uncompressedSize,
      compressionMethod: entry.compressionMethod,
      modType,
      isDuplicatePath: isDuplicate,
      isGtaMod: detectorResult ? detectorResult.isGtaMod : false,
      confidence: detectorResult ? detectorResult.confidence : 'low',
      suspiciousPackaging: detectorResult ? detectorResult.suspiciousPackaging : false,
      suspiciousPath: suspiciousPath ? pathIssues : [],
      suspiciousCompressionRatio: compressionRatio > LIMITS.SUSPICIOUS_COMPRESSION_RATIO,
    });
  }

  return result;
}

/* ============================================================
   بازرسی یک آرشیو ZIP (تنها فرمتی که واقعاً پشتیبانی می‌شود)
   ============================================================ */
async function inspectZip(file, outerDetectorResult, inspectionStartTime) {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);

  // --- v1.0.3 (رفع ایراد ۱): اعتبارسنجی اندازهٔ واقعی بافر بارگذاری‌شده ---
  // file.size یک مقدار اعلام‌شده توسط لایهٔ File API است، نه یک تضمین.
  // بعد از دریافت واقعیِ بایت‌ها، باید طول واقعی هم دوباره بررسی شود —
  // هم برای صحت امنیتی و هم برای جلوگیری از هدررفت پردازش (رفع ایراد ۳)
  // روی بافری که در نهایت رد خواهد شد: این بررسی عمداً بلافاصله بعد از
  // ساخت bytes و پیش از هرگونه تجزیهٔ CD/EOCD انجام می‌شود.
  if (bytes.byteLength > LIMITS.MAX_ARCHIVE_SIZE) {
    return buildResult({
      inspectionStatus: INSPECTION_STATUS.TOO_LARGE,
      archiveType: 'zip',
      inspectionSucceeded: false,
      outerDetectorResult,
      errors: ['اندازهٔ واقعی بافر بارگذاری‌شده (' + bytes.byteLength + ' بایت) از سقف مجاز (' + LIMITS.MAX_ARCHIVE_SIZE + ' بایت) بیشتر است.'],
    });
  }

  // --- v1.0.3 (رفع ایراد ۲): بررسی بودجهٔ زمانی بلافاصله بعد از یک await
  // بالقوه‌کند (خواندن کل فایل به حافظه). این بررسی «قطع اجباری» یک
  // Promise در حال اجرا نیست — جاوااسکریپت مرورگر چنین قابلیتی ندارد و
  // این کد هرگز چنین ادعایی نمی‌کند؛ صرفاً یک بررسی مشارکتی (cooperative)
  // بلافاصله بعد از هر await سنگین است تا زمان صرف‌شده در آن await هم در
  // بودجهٔ کل بازرسی محسوب شود، نه فقط زمان حلقهٔ classifyEntries.
  if (nowMs() - inspectionStartTime > LIMITS.MAX_INSPECTION_TIME_MS) {
    return buildResult({
      inspectionStatus: INSPECTION_STATUS.COMPLETED_PARTIAL_TIMEOUT,
      archiveType: 'zip',
      inspectionSucceeded: true,
      outerDetectorResult,
      warnings: ['بودجهٔ زمانی بازرسی پیش از رسیدن به تجزیهٔ Central Directory به پایان رسید؛ نتیجه جزئی و ناقص است.'],
    });
  }

  const parsed = parseZipCentralDirectory(bytes);
  if (!parsed.ok) {
    const reasonStatusMap = {
      zip64_not_supported: INSPECTION_STATUS.UNSUPPORTED_FORMAT,
      multi_disk_not_supported: INSPECTION_STATUS.UNSUPPORTED_FORMAT,
    };
    return buildResult({
      inspectionStatus: reasonStatusMap[parsed.reason] || INSPECTION_STATUS.MALFORMED_ARCHIVE,
      archiveType: 'zip',
      inspectionSucceeded: false,
      warnings: ['تجزیهٔ متادیتای ZIP ناموفق بود: ' + parsed.reason],
      outerDetectorResult,
    });
  }

  const classification = await classifyEntries(parsed.entries, inspectionStartTime);

  let totalDeclaredUncompressed = 0;
  for (const e of parsed.entries) totalDeclaredUncompressed += e.uncompressedSize;
  const possibleDecompressionBomb = totalDeclaredUncompressed > LIMITS.MAX_TOTAL_DECLARED_UNCOMPRESSED;

  const gtaRelevant = Boolean(
    (outerDetectorResult && outerDetectorResult.isGtaMod) ||
    classification.gtaClassifiedEntryCount > 0
  );

  let inspectionStatus = INSPECTION_STATUS.COMPLETED;
  if (classification.timedOut) inspectionStatus = INSPECTION_STATUS.COMPLETED_PARTIAL_TIMEOUT;
  else if (!gtaRelevant) inspectionStatus = INSPECTION_STATUS.COMPLETED_NON_GTA;

  const warnings = [];
  if (parsed.malformedEntryCount > 0) {
    warnings.push(parsed.malformedEntryCount + ' ورودی از Central Directory قابل‌تجزیهٔ ایمن نبودند و رد شدند.');
  }
  if (parsed.truncated) {
    warnings.push('تعداد ورودی‌های واقعی کمتر از تعداد اعلام‌شده در EOCD بود؛ آرشیو ممکن است ناقص/دستکاری‌شده باشد.');
  }
  if (possibleDecompressionBomb) {
    warnings.push('مجموع اندازهٔ اعلام‌شدهٔ (نه واقعی) محتوای فشرده‌نشده بسیار بزرگ است — این فقط یک بررسی معقولیت روی متادیتاست، نه اثبات واقعی، چون این نسخه هرگز چیزی را decompress نمی‌کند.');
  }
  if (classification.nestedArchiveCount > 0) {
    warnings.push('آرشیو حاوی ' + classification.nestedArchiveCount + ' آرشیو/بستهٔ تودرتو است؛ این نسخه هرگز وارد آرشیوهای تودرتو نمی‌شود (حداکثر عمق پشتیبانی‌شده: ' + LIMITS.MAX_NESTING_DEPTH_SUPPORTED + ').');
  }
  if (classification.suspiciousPathCount > 0) {
    warnings.push(classification.suspiciousPathCount + ' مسیر مشکوک (traversal/absolute/UNC/…) در نام ورودی‌ها یافت شد.');
  }
  if (classification.duplicatePathCount > 0) {
    warnings.push(classification.duplicatePathCount + ' مسیر تکراری/متعارض (با نادیده‌گرفتن بزرگی/کوچکی حروف) یافت شد — می‌تواند برای فریب ابزارهای استخراج استفاده شود.');
  }

  return buildResult({
    inspectionStatus,
    archiveType: 'zip',
    inspectionSucceeded: true,
    gtaRelevant,
    confidence: gtaRelevant
      ? (classification.gtaClassifiedEntryCount >= 2 || (outerDetectorResult && outerDetectorResult.confidence === 'high') ? 'high' : 'medium')
      : 'low',
    entryCount: parsed.entries.length,
    declaredEntryCount: parsed.declaredTotalEntries,
    totalDeclaredCompressedSize: parsed.entries.reduce((s, e) => s + e.compressedSize, 0),
    totalDeclaredUncompressedSize: totalDeclaredUncompressed,
    possibleDecompressionBomb,
    pluginCount: classification.pluginCount,
    scriptCount: classification.scriptCount,
    assetCount: classification.assetCount,
    executableEntryCount: classification.executableEntryCount,
    nestedArchiveCount: classification.nestedArchiveCount,
    unknownCount: classification.unknownCount,
    suspiciousPathCount: classification.suspiciousPathCount,
    doubleExtensionCount: classification.doubleExtensionCount,
    duplicatePathCount: classification.duplicatePathCount,
    malformedEntryCount: parsed.malformedEntryCount,
    entries: classification.entryDetails,
    pluginTargetDescriptors: classification.pluginTargetDescriptors,
    scriptTargetDescriptors: classification.scriptTargetDescriptors,
    unsupportedFeatures: ['content_decompression', 'nested_archive_recursion'],
    warnings,
    outerDetectorResult,
  });
}

/* ============================================================
   ساخت یک آبجکت نتیجهٔ ساختاریافته و پیش‌فرض — تضمین می‌کند همهٔ
   فیلدهای الزامی همیشه حاضرند حتی در مسیرهای خطا.
   ============================================================ */
function buildResult(overrides) {
  const base = {
    inspectorVersion: ARCHIVE_INSPECTOR_VERSION,
    archiveType: 'unknown',
    inspectionStatus: INSPECTION_STATUS.INVALID_INPUT,
    inspectionSucceeded: false,
    gtaRelevant: false,
    confidence: 'low',
    limits: LIMITS,
    entryCount: 0,
    declaredEntryCount: 0,
    totalDeclaredCompressedSize: 0,
    totalDeclaredUncompressedSize: 0,
    possibleDecompressionBomb: false,
    nestedArchiveCount: 0,
    pluginCount: 0,
    scriptCount: 0,
    assetCount: 0,
    executableEntryCount: 0,
    unknownCount: 0,
    suspiciousPathCount: 0,
    doubleExtensionCount: 0,
    duplicatePathCount: 0,
    malformedEntryCount: 0,
    entries: [],
    // v1.0.3: کاندیدهای متادیتایی نامعتبرشده برای ArchiveEntryReader —
    // نه گواهی امن‌بودن. مصرف‌کننده باید مستقلاً LFH را بازاعتبارسنجی کند.
    pluginTargetDescriptors: [],
    scriptTargetDescriptors: [],
    unsupportedFeatures: [],
    warnings: [],
    errors: [],
    outerDetectorResult: null,
  };
  return Object.assign(base, overrides || {});
}

/* ============================================================
   نقطهٔ ورود عمومی
   ============================================================ */
const ArchiveInspector = {
  version: ARCHIVE_INSPECTOR_VERSION,

  /**
   * بازرسی یک فایل آرشیو. هرگز استثنای کنترل‌نشده پرتاب نمی‌کند.
   */
  async inspect(file) {
    const inspectionStartTime = nowMs(); // v1.0.3: مبدأ مشترک بودجهٔ زمانی برای کل جریان بازرسی
    try {
      if (!file || typeof file !== 'object' || typeof file.name !== 'string') {
        return buildResult({ inspectionStatus: INSPECTION_STATUS.INVALID_INPUT, errors: ['ورودی نامعتبر است.'] });
      }
      if (!Number.isFinite(file.size) || file.size <= 0) {
        return buildResult({ inspectionStatus: INSPECTION_STATUS.INVALID_INPUT, errors: ['فایل خالی یا اندازهٔ آن نامعتبر است.'] });
      }
      if (file.size > LIMITS.MAX_ARCHIVE_SIZE) {
        return buildResult({ inspectionStatus: INSPECTION_STATUS.TOO_LARGE, errors: ['اندازهٔ آرشیو از سقف مجاز (' + LIMITS.MAX_ARCHIVE_SIZE + ' بایت) بیشتر است.'] });
      }
      if (typeof window === 'undefined' || typeof window.GtaModDetector === 'undefined') {
        return buildResult({ inspectionStatus: INSPECTION_STATUS.INVALID_INPUT, errors: ['GtaModDetector در دسترس نیست؛ Archive Inspector بدون آن نمی‌تواند کار کند.'] });
      }

      // ابتدا خودِ فایل آرشیو را از طریق تشخیص‌دهندهٔ موجود عبور می‌دهیم
      // (استفادهٔ مجدد صریح، نه بازسازی منطق آن).
      const outerDetectorResult = await window.GtaModDetector.analyze(file);

      // v1.0.3 (رفع ایراد ۲): این await هم می‌تواند زمان‌بر باشد؛ بلافاصله
      // بعد از آن بودجهٔ زمانی را بررسی می‌کنیم تا زمان صرف‌شدهٔ آن هم در
      // مجموع محاسبه شود، نه اینکه نادیده گرفته شود.
      if (nowMs() - inspectionStartTime > LIMITS.MAX_INSPECTION_TIME_MS) {
        return buildResult({
          inspectionStatus: INSPECTION_STATUS.COMPLETED_PARTIAL_TIMEOUT,
          inspectionSucceeded: true,
          outerDetectorResult,
          warnings: ['بودجهٔ زمانی بازرسی پیش از شناسایی نوع آرشیو به پایان رسید؛ نتیجه جزئی و ناقص است.'],
        });
      }

      const format = await sniffArchiveFormat(file);

      if (format === 'zip') {
        return await inspectZip(file, outerDetectorResult, inspectionStartTime);
      }
      if (format === '7z') {
        return buildResult({
          archiveType: '7z', inspectionStatus: INSPECTION_STATUS.UNSUPPORTED_7Z,
          outerDetectorResult, warnings: ['فرمت 7z در این نسخه پشتیبانی نمی‌شود (نیازمند رمزگشایی LZMA که در این پروژه پیاده‌سازی نشده است).'],
        });
      }
      if (format === 'rar') {
        return buildResult({
          archiveType: 'rar', inspectionStatus: INSPECTION_STATUS.UNSUPPORTED_RAR,
          outerDetectorResult, warnings: ['فرمت RAR در این نسخه پشتیبانی نمی‌شود.'],
        });
      }
      if (format === 'rpf') {
        return buildResult({
          archiveType: 'rpf', inspectionStatus: INSPECTION_STATUS.UNSUPPORTED_RPF,
          outerDetectorResult, warnings: ['فرمت RPF (اختصاصی RAGE) در این نسخه پشتیبانی نمی‌شود؛ مستندسازی رسمی عمومی برای آن وجود ندارد.'],
        });
      }

      return buildResult({
        archiveType: 'unknown', inspectionStatus: INSPECTION_STATUS.UNSUPPORTED_FORMAT,
        outerDetectorResult, warnings: ['امضای فایل با هیچ فرمت آرشیو شناخته‌شده‌ای مطابقت ندارد.'],
      });
    } catch (err) {
      console.error('ArchiveInspector: خطای غیرمنتظره', err);
      return buildResult({
        inspectionStatus: INSPECTION_STATUS.MALFORMED_ARCHIVE,
        errors: ['خطای غیرمنتظره در طول بازرسی رخ داد؛ به‌صورت ایمن متوقف شد.'],
      });
    }
  },
};

window.ArchiveInspector = ArchiveInspector;

})();

(function () {
/* ============================================================
   GTA Guard — archive-entry-reader.js  (ArchiveEntryReader v1.0.0)
   ------------------------------------------------------------
   این فایل یک extractor عمومی یا یک آرشیو-باز-کن نیست.

   کارش دقیقاً و فقط این است: با گرفتن یک فایل ZIP و یک
   targetDescriptor دقیق (از pluginTargetDescriptors یا scriptTargetDescriptors
   تولیدشده توسط ArchiveInspector)، آن یک entry مشخص را استخراج کند و
   به‌صورت یک File-like object آماده برای تحویل به Engine v2.2.0 یا
   ScriptAnalyzer برگرداند.

   این فایل هرگز:
     - خودش هدف را انتخاب نمی‌کند (no first-match/auto-selection)
     - تشخیص بدافزار انجام نمی‌دهد
     - verdict یا score تولید نمی‌کند
     - چیزی را اجرا/لود/کامپایل می‌کند
     - به فایل‌سیستم واقعی می‌نویسد
     - از هیچ کتابخانهٔ فشرده‌سازی خارجی استفاده می‌کند

   طراحی امنیتی: این ماژول به تجزیهٔ قبلی ArchiveInspector اعتماد
   نمی‌کند — کل Central Directory را مستقل و از صفر دوباره
   اعتبارسنجی می‌کند (دفاع در عمق). اگر حتی یک entry نامرتبط با
   target، در هر نقطه از آرشیو، مشکل ساختاری یا سیاستی داشته باشد
   (رمزگذاری‌شده، فشرده‌سازی پشتیبانی‌نشده، مسیر خطرناک، و...) کل
   عملیات خواندن رد می‌شود — حتی اگر target خودش کاملاً سالم باشد.
   این انتخاب آگاهانه (fail-closed در سطح کل آرشیو) از حملات مبتنی
   بر ابهام تجزیهٔ ZIP (که در آن ابزارهای مختلف دربارهٔ محتوای «واقعی»
   یک مسیر با هم اختلاف پیدا می‌کنند) جلوگیری می‌کند.

   محدودیت صادقانه: در جاوااسکریپت مرورگر هیچ راهی برای واقعاً
   preempt کردن یک عملیات CPU-bound در حال اجرا وجود ندارد. بودجهٔ
   زمانی این‌جا cooperative است — یعنی فقط بین گام‌های async/chunk
   بررسی می‌شود، نه یک garantee سخت‌افزاری.
   ============================================================ */

'use strict';

const ARCHIVE_ENTRY_READER_VERSION = '1.1.1';

/* ------------------------------------------------------------
   محدودیت‌های صریح (طبق مشخصات؛ چیزی نامحدود نیست)
   ------------------------------------------------------------ */
const LIMITS = Object.freeze({
  MAX_ARCHIVE_SIZE: 150 * 1024 * 1024,
  MAX_ENTRY_COMPRESSED_SIZE: 32 * 1024 * 1024,
  MAX_ENTRY_UNCOMPRESSED_SIZE: 48 * 1024 * 1024,
  MAX_OUTPUT_BYTES: 48 * 1024 * 1024,
  MAX_PATH_LENGTH: 512,
  MAX_ENTRIES: 20000,
  MAX_READ_TIME_MS: 8000,
  MAX_EOCD_SEARCH_WINDOW: 22 + 65535,
  EOCD_MIN_SIZE: 22,
  CD_HEADER_MIN_SIZE: 46,
  LFH_MIN_SIZE: 30,
});

const ERROR_CODES = Object.freeze({
  INVALID_INPUT: 'invalid_input',
  EMPTY_ARCHIVE: 'empty_archive',
  ARCHIVE_TOO_LARGE: 'archive_too_large',
  MALFORMED_ARCHIVE: 'malformed_archive',
  UNSUPPORTED_FORMAT: 'unsupported_format',
  UNSUPPORTED_COMPRESSION: 'unsupported_compression',
  BROWSER_UNSUPPORTED: 'browser_unsupported',
  TARGET_NOT_FOUND: 'target_not_found',
  DUPLICATE_TARGET_ENTRY: 'duplicate_target_entry',
  ENCRYPTED_ENTRY: 'encrypted_entry',
  DATA_DESCRIPTOR_USED: 'data_descriptor_used',
  CRC_MISMATCH: 'crc_mismatch',
  TIMEOUT: 'timeout',
  PATH_REJECTED: 'path_rejected',
  SIZE_LIMIT_EXCEEDED: 'size_limit_exceeded',
  LFH_CD_MISMATCH: 'lfh_cd_mismatch',
  OUTPUT_LIMIT_EXCEEDED: 'output_limit_exceeded',
});

/* ============================================================
   بخش ۱: حساب امن محدوده (Safe Range Arithmetic) — یک هستهٔ
   مرکزی که تمام بررسی‌های مرزی از آن استفاده می‌کنند.
   ============================================================ */
function isRangeValid(offset, length, limit) {
  if (!Number.isInteger(offset) || !Number.isInteger(length) || !Number.isInteger(limit)) return false;
  if (offset < 0 || length < 0 || limit < 0) return false;
  if (offset > limit) return false;
  return length <= limit - offset;
}

/* ============================================================
   بخش ۲: CRC-32 (استاندارد IEEE 802.3 / zlib) — پیاده‌سازی محلی،
   بدون هیچ وابستگی خارجی.
   ============================================================ */
const CRC32_TABLE = (function buildCrc32Table() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function computeCrc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/* ============================================================
   بخش ۳: امنیت مسیر و decode سخت‌گیرانهٔ UTF-8
   ============================================================ */
const BIDI_CONTROL_RE = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const DRIVE_LETTER_RE = /^[A-Za-z]:[\\/]/;
const UNC_PATH_RE = /^\\\\|^\/\//;

/**
 * decode سخت‌گیرانهٔ UTF-8. برخلاف ArchiveInspector (که برای
 * نمایش/طبقه‌بندی محافظه‌کارانه lossy decode می‌کند)، این‌جا هر
 * دنبالهٔ نامعتبر UTF-8 باعث رد شدن کامل می‌شود — هرگز replacement
 * character تولید نمی‌شود که بتواند دو مسیر متفاوت را «یکسان»
 * نشان دهد.
 */
function decodeUtf8Strict(bytes) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  return decoder.decode(bytes); // در صورت نامعتبر بودن، استثنا پرتاب می‌کند
}

/** بررسی کامل امنیت مسیر بر اساس segmentهای مسیر، نه فقط substring. */
function validatePathSecurity(path) {
  if (typeof path !== 'string' || path.length === 0) return ['empty_or_invalid'];
  if (path.length > LIMITS.MAX_PATH_LENGTH) return ['path_too_long'];
  if (path.indexOf('\u0000') !== -1) return ['nul_byte'];
  if (BIDI_CONTROL_RE.test(path)) return ['bidi_control_characters'];
  if (DRIVE_LETTER_RE.test(path)) return ['drive_letter_path'];
  if (UNC_PATH_RE.test(path)) return ['unc_path'];
  if (path.startsWith('/') || path.startsWith('\\')) return ['absolute_path'];

  const issues = [];
  // تفکیک بر اساس segment برای گرفتن "." و ".." حتی در وسط مسیر،
  // و همچنین segmentهای خالی ناشی از جداکنندهٔ مضاعف (//) که ابهام
  // ایجاد می‌کنند.
  const segments = path.split(/[\\/]/);
  for (const seg of segments) {
    if (seg === '.' || seg === '..') { issues.push('dot_segment'); break; }
  }
  // segment خالی در وسط مسیر (نه در انتها برای علامت پوشه) مبهم است
  for (let i = 0; i < segments.length - 1; i++) {
    if (segments[i] === '') { issues.push('ambiguous_separator'); break; }
  }
  return issues;
}

/* ============================================================
   بخش ۴: File-like خروجی — دقیقاً همان قرارداد ورودی مورد انتظار
   Engine v2.2.0 (name/size/arrayBuffer/slice).
   ============================================================ */
class ExtractedEntryFile {
  constructor(name, bytes) {
    this.name = name;
    this._bytes = bytes;
    this.size = bytes.length;
  }
  slice(start, end) {
    return new ExtractedEntryFile(this.name, this._bytes.subarray(start || 0, end == null ? this._bytes.length : end));
  }
  async arrayBuffer() {
    return this._bytes.buffer.slice(this._bytes.byteOffset, this._bytes.byteOffset + this._bytes.byteLength);
  }
}

/* ============================================================
   بخش ۵: اعتبارسنجی targetDescriptor
   ============================================================ */
function validateTargetDescriptor(td) {
  if (!td || typeof td !== 'object') return 'targetDescriptor نامعتبر است.';
  if (typeof td.canonicalPath !== 'string' || td.canonicalPath.length === 0) return 'canonicalPath نامعتبر است.';
  if (td.canonicalPath.length > LIMITS.MAX_PATH_LENGTH) return 'canonicalPath بیش‌ازحد طولانی است.';
  const lower = td.canonicalPath.toLowerCase();
  const allowed = lower.endsWith('.asi') || lower.endsWith('.dll') || lower.endsWith('.lua') || lower.endsWith('.cs');
  if (lower.endsWith('/') || !allowed) {
    return 'canonicalPath باید دقیقاً به یکی از پسوندهای مجاز .asi/.dll/.lua/.cs ختم شود (نه یک پوشه و نه نوع پشتیبانی‌نشده).';
  }
  if (td.targetType != null && td.targetType !== 'plugin' && td.targetType !== 'script') {
    return 'targetType نامعتبر است.';
  }
  if (td.targetType === 'plugin' && !lower.endsWith('.asi') && !lower.endsWith('.dll')) {
    return 'targetType=plugin با پسوند هدف سازگار نیست.';
  }
  if (td.targetType === 'script' && !lower.endsWith('.lua') && !lower.endsWith('.cs')) {
    return 'targetType=script با پسوند هدف سازگار نیست.';
  }
  for (const field of ['lfhOffset', 'compressedSize', 'uncompressedSize', 'crc32']) {
    if (!Number.isInteger(td[field]) || td[field] < 0) return field + ' باید یک عدد صحیح نامنفی باشد.';
  }
  if (td.compressionMethod !== 0 && td.compressionMethod !== 8) {
    return 'compressionMethod باید 0 (Stored) یا 8 (Deflate) باشد.';
  }
  return null; // معتبر
}

/* ============================================================
   بخش ۶: اعتبارسنجی کامل و مستقل EOCD
   ============================================================ */
function findAndValidateEocd(bytes) {
  const total = bytes.length;
  if (total < LIMITS.EOCD_MIN_SIZE) return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE };

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const searchStart = Math.max(0, total - LIMITS.MAX_EOCD_SEARCH_WINDOW);

  let eocdOffset = -1;
  for (let i = total - LIMITS.EOCD_MIN_SIZE; i >= searchStart; i--) {
    if (!isRangeValid(i, 4, total)) continue;
    if (view.getUint32(i, true) === 0x06054b50) {
      const commentLength = view.getUint16(i + 20, true);
      if (i + LIMITS.EOCD_MIN_SIZE + commentLength === total) { eocdOffset = i; break; }
    }
  }
  if (eocdOffset === -1) return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE };
  if (!isRangeValid(eocdOffset, LIMITS.EOCD_MIN_SIZE, total)) return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE };

  const diskNumber = view.getUint16(eocdOffset + 4, true);
  const cdStartDisk = view.getUint16(eocdOffset + 6, true);
  const entriesThisDisk = view.getUint16(eocdOffset + 8, true);
  const totalEntries = view.getUint16(eocdOffset + 10, true);
  const cdSize = view.getUint32(eocdOffset + 12, true);
  const cdOffset = view.getUint32(eocdOffset + 16, true);

  // ZIP64 sentinel — صراحتاً fail-closed رد می‌شود، هرگز حدس زده نمی‌شود
  if (totalEntries === 0xffff || entriesThisDisk === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    return { ok: false, reason: ERROR_CODES.UNSUPPORTED_FORMAT, detail: 'zip64_sentinel' };
  }
  // آرشیو چند-دیسکی / split — پشتیبانی نمی‌شود
  if (diskNumber !== 0 || cdStartDisk !== 0 || entriesThisDisk !== totalEntries) {
    return { ok: false, reason: ERROR_CODES.UNSUPPORTED_FORMAT, detail: 'multi_disk' };
  }
  if (totalEntries > LIMITS.MAX_ENTRIES) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'too_many_entries' };
  }
  if (!isRangeValid(cdOffset, cdSize, total)) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'cd_out_of_bounds' };
  }
  // Central Directory باید کاملاً قبل از EOCD قرار داشته باشد
  if (cdOffset + cdSize > eocdOffset) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'cd_overlaps_eocd' };
  }

  return { ok: true, eocdOffset, cdOffset, cdSize, totalEntries };
}

/* ============================================================
   بخش ۷: پویش کامل و مستقل Central Directory
   ------------------------------------------------------------
   قانون حیاتی: هرگز پس از پیدا کردن target متوقف نمی‌شود. تمام
   entryها بررسی می‌شوند. هر ناهنجاری (ساختاری یا سیاستی) در هر
   entry — حتی وقتی target خودش سالم است — کل نتیجه را باطل می‌کند.
   ============================================================ */
function scanCentralDirectory(bytes, cdOffset, cdSize, totalEntries, targetDescriptor, deadline) {
  const total = bytes.length;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const cdEnd = cdOffset + cdSize;

  let offset = cdOffset;
  let matchCount = 0;
  let matchedEntry = null;
  let policyFailure = null; // اولین کد خطای سیاستی یافت‌شده (غیر ساختاری)
  let entriesProcessed = 0;

  for (let i = 0; i < totalEntries; i++) {
    if ((i & 63) === 0 && Date.now() > deadline) {
      return { ok: false, reason: ERROR_CODES.TIMEOUT };
    }

    if (!isRangeValid(offset, LIMITS.CD_HEADER_MIN_SIZE, cdEnd)) {
      // نمی‌توانیم به‌طور امن ادامه دهیم — طول واقعی این entry نامشخص است
      return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'cd_header_out_of_bounds' };
    }
    const sig = view.getUint32(offset, true);
    if (sig !== 0x02014b50) {
      return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'bad_cd_signature' };
    }

    const flags = view.getUint16(offset + 8, true);
    const compressionMethod = view.getUint16(offset + 10, true);
    const crc32 = view.getUint32(offset + 16, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const fileNameLength = view.getUint16(offset + 28, true);
    const extraFieldLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const lfhOffset = view.getUint32(offset + 42, true);

    const nameStart = offset + LIMITS.CD_HEADER_MIN_SIZE;
    const entryTotalLength = LIMITS.CD_HEADER_MIN_SIZE + fileNameLength + extraFieldLength + commentLength;

    // طول کامل entry (شامل نام/extra/comment) باید در محدودهٔ CD جا شود
    if (!isRangeValid(offset, entryTotalLength, cdEnd)) {
      return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'cd_entry_out_of_bounds' };
    }
    if (!isRangeValid(nameStart, fileNameLength, total)) {
      return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'cd_name_out_of_bounds' };
    }

    // decode سخت‌گیر — شکست در decode یک ناهنجاری سیاستی است (نه
    // ساختاری)، چون طول بایت‌ها را همچنان می‌دانیم و می‌توانیم امن
    // ادامه دهیم.
    let name = null;
    try {
      name = decodeUtf8Strict(bytes.subarray(nameStart, nameStart + fileNameLength));
    } catch (e) {
      if (!policyFailure) policyFailure = ERROR_CODES.MALFORMED_ARCHIVE;
    }

    if (name !== null) {
      const pathIssues = validatePathSecurity(name);
      if (pathIssues.length > 0 && !policyFailure) policyFailure = ERROR_CODES.PATH_REJECTED;

      // ویژگی‌های پشتیبانی‌نشده — سیاستی، نه ساختاری
      if ((flags & 0x0001) !== 0 && !policyFailure) policyFailure = ERROR_CODES.ENCRYPTED_ENTRY;
      if ((flags & 0x0008) !== 0 && !policyFailure) policyFailure = ERROR_CODES.DATA_DESCRIPTOR_USED;
      if (compressionMethod !== 0 && compressionMethod !== 8 && !policyFailure) policyFailure = ERROR_CODES.UNSUPPORTED_COMPRESSION;
      if ((compressedSize === 0xffffffff || uncompressedSize === 0xffffffff) && !policyFailure) {
        policyFailure = ERROR_CODES.UNSUPPORTED_FORMAT; // ZIP64 در سطح entry
      }

      // بررسی تطابق دقیق با target — تمام فیلدهای هویتی باید یکسان باشند
      if (
        name === targetDescriptor.canonicalPath &&
        lfhOffset === targetDescriptor.lfhOffset &&
        compressedSize === targetDescriptor.compressedSize &&
        uncompressedSize === targetDescriptor.uncompressedSize &&
        crc32 === targetDescriptor.crc32 &&
        compressionMethod === targetDescriptor.compressionMethod
      ) {
        matchCount++;
        if (!matchedEntry) {
          matchedEntry = { name, flags, compressionMethod, crc32, compressedSize, uncompressedSize, lfhOffset };
        }
      }
    }

    offset += entryTotalLength;
    entriesProcessed++;
  }

  if (offset !== cdEnd) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'cd_size_mismatch' };
  }
  if (entriesProcessed !== totalEntries) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'entry_count_mismatch' };
  }
  if (policyFailure) {
    return { ok: false, reason: policyFailure };
  }
  if (matchCount === 0) {
    return { ok: false, reason: ERROR_CODES.TARGET_NOT_FOUND };
  }
  if (matchCount > 1) {
    return { ok: false, reason: ERROR_CODES.DUPLICATE_TARGET_ENTRY };
  }

  return { ok: true, matchedEntry };
}

/* ============================================================
   بخش ۸: اعتبارسنجی Local File Header + استخراج bounded
   ============================================================ */
async function validateLfhAndExtract(bytes, cdEntry, cdOffset, deadline) {
  const total = bytes.length;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lfhOffset = cdEntry.lfhOffset;

  if (!(lfhOffset >= 0 && lfhOffset < cdOffset)) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'lfh_not_before_cd' };
  }
  if (!isRangeValid(lfhOffset, LIMITS.LFH_MIN_SIZE, total)) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'lfh_out_of_bounds' };
  }

  const sig = view.getUint32(lfhOffset, true);
  if (sig !== 0x04034b50) return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'bad_lfh_signature' };

  const lfhFlags = view.getUint16(lfhOffset + 6, true);
  const lfhCompressionMethod = view.getUint16(lfhOffset + 8, true);
  const lfhCrc32 = view.getUint32(lfhOffset + 14, true);
  const lfhCompressedSize = view.getUint32(lfhOffset + 18, true);
  const lfhUncompressedSize = view.getUint32(lfhOffset + 22, true);
  const lfhFileNameLength = view.getUint16(lfhOffset + 26, true);
  const lfhExtraFieldLength = view.getUint16(lfhOffset + 28, true);

  const nameStart = lfhOffset + LIMITS.LFH_MIN_SIZE;
  if (!isRangeValid(nameStart, lfhFileNameLength, total)) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'lfh_name_out_of_bounds' };
  }

  let lfhName;
  try {
    lfhName = decodeUtf8Strict(bytes.subarray(nameStart, nameStart + lfhFileNameLength));
  } catch (e) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'lfh_name_decode_failed' };
  }

  // Data descriptor (bit 3) در LFH هم باید صراحتاً رد شود
  if ((lfhFlags & 0x0008) !== 0) {
    return { ok: false, reason: ERROR_CODES.DATA_DESCRIPTOR_USED };
  }

  // سازگاری کامل بین LFH و CD — هر گونه ناهماهنگی مشکوک است
  if (
    lfhName !== cdEntry.name ||
    lfhFlags !== cdEntry.flags ||
    lfhCompressionMethod !== cdEntry.compressionMethod ||
    lfhCrc32 !== cdEntry.crc32 ||
    lfhCompressedSize !== cdEntry.compressedSize ||
    lfhUncompressedSize !== cdEntry.uncompressedSize
  ) {
    return { ok: false, reason: ERROR_CODES.LFH_CD_MISMATCH };
  }

  if (cdEntry.compressedSize > LIMITS.MAX_ENTRY_COMPRESSED_SIZE || cdEntry.uncompressedSize > LIMITS.MAX_ENTRY_UNCOMPRESSED_SIZE) {
    return { ok: false, reason: ERROR_CODES.SIZE_LIMIT_EXCEEDED };
  }

  // BUG FIX: داده‌های فشرده بعد از هم نام فایل و هم extra field شروع
  // می‌شوند — نه فقط بعد از extra field. فراموش کردن lfhFileNameLength
  // اینجا باعث می‌شد استخراج از وسط نام فایل شروع شود (داده‌ای اشتباه
  // و درنتیجه crc_mismatch کاذب برای هر entry با نام غیرخالی).
  const dataOffset = nameStart + lfhFileNameLength + lfhExtraFieldLength;
  if (!isRangeValid(dataOffset, cdEntry.compressedSize, total)) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'data_out_of_bounds' };
  }
  // داده‌های فشرده هرگز نباید با Central Directory همپوشانی داشته باشند
  if (dataOffset + cdEntry.compressedSize > cdOffset) {
    return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'data_overlaps_cd' };
  }

  // --- استخراج ---
  let extracted;
  if (cdEntry.compressionMethod === 0) {
    if (cdEntry.compressedSize !== cdEntry.uncompressedSize) {
      return { ok: false, reason: ERROR_CODES.LFH_CD_MISMATCH, detail: 'stored_size_mismatch' };
    }
    // یک کپی محدود و مشخص — نه یک view روی کل بافر آرشیو (که بافر
    // ۱۵۰ مگابایتی را در حافظه زنده نگه می‌داشت).
    extracted = bytes.slice(dataOffset, dataOffset + cdEntry.compressedSize);
  } else {
    // compressionMethod === 8 (Deflate) — تنها گزینهٔ دیگر مجاز
    if (typeof DecompressionStream === 'undefined') {
      return { ok: false, reason: ERROR_CODES.BROWSER_UNSUPPORTED };
    }
    const compressedSlice = bytes.slice(dataOffset, dataOffset + cdEntry.compressedSize);
    const result = await decompressDeflateRawBounded(compressedSlice, cdEntry.uncompressedSize, deadline);
    if (!result.ok) return result;
    extracted = result.bytes;
  }

  const actualCrc = computeCrc32(extracted);
  if (actualCrc !== cdEntry.crc32) {
    return { ok: false, reason: ERROR_CODES.CRC_MISMATCH };
  }

  return { ok: true, bytes: extracted };
}

/**
 * decompress محدود deflate-raw با استفاده از API استاندارد مرورگر.
 * خروجی دقیقاً در یک بافر از پیش‌تخصیص‌یافته (به‌اندازهٔ
 * expectedSize) نوشته می‌شود — بدون الگوی chunks[]+concat. اگر
 * خروجی واقعی بیشتر یا کمتر از expectedSize باشد، رد می‌شود.
 */
async function decompressDeflateRawBounded(compressedBytes, expectedSize, deadline) {
  const outputBuffer = new Uint8Array(Math.min(expectedSize, LIMITS.MAX_OUTPUT_BYTES));
  let written = 0;
  let stream, reader;

  try {
    // از ReadableStream مستقیم استفاده می‌کنیم، نه Blob — سازندهٔ Blob
    // معمولاً یک کپی داخلی دیگر از داده می‌سازد؛ enqueue مستقیم یک
    // Uint8Array از قبل محدودشده، این کپی اضافه را کاملاً حذف می‌کند
    // (کاهش تقویت حافظه طبق الزام صریح مشخصات).
    stream = new ReadableStream({
      start(controller) {
        controller.enqueue(compressedBytes);
        controller.close();
      },
    }).pipeThrough(new DecompressionStream('deflate-raw'));
    reader = stream.getReader();

    while (true) {
      if (Date.now() > deadline) {
        await safeCancel(reader);
        return { ok: false, reason: ERROR_CODES.TIMEOUT };
      }

      let chunkResult;
      try {
        chunkResult = await reader.read();
      } catch (e) {
        // جریان compressed نامعتبر/بدشکل بود
        return { ok: false, reason: ERROR_CODES.MALFORMED_ARCHIVE, detail: 'deflate_stream_error' };
      }

      const { done, value } = chunkResult;
      if (done) break;

      if (written + value.length > outputBuffer.length) {
        await safeCancel(reader);
        return { ok: false, reason: ERROR_CODES.OUTPUT_LIMIT_EXCEEDED };
      }
      outputBuffer.set(value, written);
      written += value.length;
    }
  } finally {
    if (reader) {
      try { reader.releaseLock(); } catch (e) { /* نادیده گرفتن — cleanup تلاش‌محور */ }
    }
  }

  if (written !== expectedSize) {
    return { ok: false, reason: ERROR_CODES.OUTPUT_LIMIT_EXCEEDED, detail: 'size_mismatch' };
  }

  return { ok: true, bytes: outputBuffer.subarray(0, written) };
}

async function safeCancel(reader) {
  try { await reader.cancel(); } catch (e) { /* نادیده گرفتن — best-effort */ }
}

/* ============================================================
   بخش ۹: نقطهٔ ورود عمومی
   ============================================================ */
const ArchiveEntryReader = {
  version: ARCHIVE_ENTRY_READER_VERSION,

  /**
   * readEntry(input, targetDescriptor)
   *   input: یک File-like object (name, size, arrayBuffer()) —
   *          دقیقاً همان چیزی که به ArchiveInspector.inspect() هم
   *          داده می‌شود.
   *   targetDescriptor: { canonicalPath, lfhOffset, compressedSize,
   *          uncompressedSize, crc32, compressionMethod } — دقیقاً
   *          یکی از موارد pluginTargetDescriptors تولیدشدهٔ
   *          ArchiveInspector؛ این تابع خودش هرگز یکی را انتخاب
   *          نمی‌کند.
   *
   * هرگز استثنای کنترل‌نشده پرتاب نمی‌کند.
   */
  async readEntry(input, targetDescriptor) {
    const startTime = Date.now();
    const deadline = startTime + LIMITS.MAX_READ_TIME_MS;

    function fail(reason, detail) {
      return { ok: false, readerVersion: ARCHIVE_ENTRY_READER_VERSION, errorCode: reason, detail: detail || null };
    }

    try {
      if (!input || typeof input !== 'object' || typeof input.arrayBuffer !== 'function') {
        return fail(ERROR_CODES.INVALID_INPUT, 'input فاقد arrayBuffer() است.');
      }
      if (!Number.isFinite(input.size) || input.size <= 0) {
        return fail(ERROR_CODES.EMPTY_ARCHIVE);
      }
      if (input.size > LIMITS.MAX_ARCHIVE_SIZE) {
        return fail(ERROR_CODES.ARCHIVE_TOO_LARGE);
      }

      const descriptorError = validateTargetDescriptor(targetDescriptor);
      if (descriptorError) {
        return fail(ERROR_CODES.INVALID_INPUT, descriptorError);
      }

      let buffer;
      try {
        buffer = await input.arrayBuffer();
      } catch (e) {
        return fail(ERROR_CODES.INVALID_INPUT, 'خواندن محتوای فایل ناموفق بود.');
      }
      const bytes = new Uint8Array(buffer);
      if (bytes.byteLength === 0) return fail(ERROR_CODES.EMPTY_ARCHIVE, 'بافر واقعی آرشیو خالی است.');
      if (bytes.byteLength > LIMITS.MAX_ARCHIVE_SIZE) return fail(ERROR_CODES.ARCHIVE_TOO_LARGE, 'اندازهٔ واقعی بافر آرشیو از سقف امن بیشتر است.');

      const eocd = findAndValidateEocd(bytes);
      if (!eocd.ok) return fail(eocd.reason, eocd.detail);

      const scan = scanCentralDirectory(bytes, eocd.cdOffset, eocd.cdSize, eocd.totalEntries, targetDescriptor, deadline);
      if (!scan.ok) return fail(scan.reason, scan.detail);

      const extraction = await validateLfhAndExtract(bytes, scan.matchedEntry, eocd.cdOffset, deadline);
      if (!extraction.ok) return fail(extraction.reason, extraction.detail);

      const extractedFile = new ExtractedEntryFile(targetDescriptor.canonicalPath, extraction.bytes);

      return {
        ok: true,
        readerVersion: ARCHIVE_ENTRY_READER_VERSION,
        file: extractedFile,
        bytesExtracted: extraction.bytes.length,
        crc32Verified: true,
        timeElapsedMs: Date.now() - startTime,
      };
    } catch (err) {
      console.error('ArchiveEntryReader: خطای غیرمنتظره', err);
      return fail(ERROR_CODES.MALFORMED_ARCHIVE, 'خطای غیرمنتظره؛ به‌صورت ایمن رد شد.');
    }
  },
};

window.ArchiveEntryReader = ArchiveEntryReader;

})();

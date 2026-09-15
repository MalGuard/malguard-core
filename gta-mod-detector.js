/* ============================================================
   GTA Guard — gta-mod-detector.js  (GTA Mod Detector v1.0.0)
   ------------------------------------------------------------
   این فایل یک اسکنر بدافزار نیست و جایگزین Engine v2.2.0 نمی‌شود.

   کارش فقط پاسخ به این سؤال است:
     «این ورودی احتمالاً به یک مود GTA تعلق دارد یا نه، چه نوع
      قطعه‌ای از یک مود GTA است، و کدام لایهٔ بعدی باید آن را
      پردازش کند؟»

   این فایل هرگز پاسخ نمی‌دهد:
     «آیا این فایل بدافزار است؟»

   آن سؤال همیشه مسئولیت Engine v2.2.0 (و لایه‌های بازرسی آینده
   مثل بازرسی آرشیو) است، نه این فایل.

   محدودیت‌های امنیتی مطلق:
     - هرگز فایل ورودی را اجرا، لود، کامپایل، یا به هر شکلی فعال
       نمی‌کند (بدون eval/Function/WebAssembly/فراخوانی پردازه).
     - هرگز DLL/ASI را لود یا export آن‌ها را صدا نمی‌زند.
     - هرگز کد اسکریپت (Lua/C#) را اجرا یا کامپایل نمی‌کند.
     - هرگز آرشیو (zip/7z/rar/rpf) را استخراج یا باز نمی‌کند —
       فقط بایت‌های ابتدایی آن را برای شناسایی امضا (magic bytes)
       می‌خواند، دقیقاً همان‌طور که برای هر نوع فایل دیگر انجام
       می‌شود؛ این مرحلهٔ «بازرسی آرشیو» (ARCHIVE_INSPECTION) در
       نسخهٔ بعدی پروژه ساخته خواهد شد، نه اینجا.
     - هرگز از یک PE-parser دوم، یک موتور امتیازدهی دوم، یا یک
       ارزیاب Rules دوم استفاده نمی‌کند — این فایل به‌کلی مستقل از
       engine.js است و آن را در خود صدا نمی‌زند.
     - هرگز فایل کامل یا هش آن را به هیچ سروری ارسال نمی‌کند.

   این پیاده‌سازی قطعی (deterministic) است: یک ورودی یکسان همیشه
   یک نتیجهٔ یکسان تولید می‌کند.
   ============================================================ */

'use strict';

const GTA_MOD_DETECTOR_VERSION = '1.0.0';

/* ------------------------------------------------------------
   محدودیت‌های دفاعی (همان روح LIMITS در engine.js — بایت‌خوانی
   محدود و بدون تخصیص حافظهٔ نامحدود)
   ------------------------------------------------------------ */
const DETECTOR_LIMITS = Object.freeze({
  MAGIC_SNIFF_BYTES: 16,          // فقط ۱۶ بایت اول برای تشخیص امضای container
  CONTEXT_SCAN_BYTES: 65536,      // حداکثر ۶۴ کیلوبایت برای جست‌وجوی کلیدواژهٔ زمینه‌ای GTA
  MAX_FILENAME_LENGTH: 1024,      // نام فایل‌های طولانی‌تر از این کوتاه/رد می‌شوند
  MAX_EXTENSION_TOKENS: 12,       // سقف تعداد بخش‌های نام فایل که بررسی می‌شوند
});

/* ------------------------------------------------------------
   مقادیر استاندارد enum خروجی
   ------------------------------------------------------------ */
const MOD_TYPES = Object.freeze({
  PLUGIN: 'plugin',
  EXECUTABLE: 'executable',
  SCRIPT: 'script',
  ASSET: 'asset',
  METADATA: 'metadata',
  PACKAGE: 'package',   // .rpf — بستهٔ اختصاصی RAGE
  ARCHIVE: 'archive',   // .zip/.7z/.rar — آرشیو عمومی
  UNKNOWN: 'unknown',
});

const CONFIDENCE = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low' });

const ROUTES = Object.freeze({
  ENGINE: 'ENGINE',
  ARCHIVE_INSPECTION: 'ARCHIVE_INSPECTION',
  INCONCLUSIVE: 'INCONCLUSIVE',
  REJECT: 'REJECT',
});

/* ------------------------------------------------------------
   جداول پسوند — طبقه‌بندی بر اساس بخش ۵ مشخصات.
   هر پسوند یک «سطح اختصاصی‌بودن به GTA» پیش‌فرض دارد که مبنای
   محاسبهٔ confidence اولیه است (نه تصمیم نهایی):
     'specific' → این پسوند تقریباً همیشه در بافت مادسازی GTA/RAGE
                  دیده می‌شود (نه اثبات قطعی، فقط شواهد قوی‌تر).
     'generic'  → این پسوند در نرم‌افزارهای بسیار متنوعی (از جمله
                  بازی‌های دیگر مثل Minecraft/Roblox/Skyrim) هم
                  استفاده می‌شود؛ به‌تنهایی شاهد ضعیفی است.
   ------------------------------------------------------------ */
const EXTENSION_TABLE = Object.freeze({
  '.asi': { modType: MOD_TYPES.PLUGIN, specificity: 'specific' },
  '.dll': { modType: MOD_TYPES.PLUGIN, specificity: 'generic' },

  '.exe': { modType: MOD_TYPES.EXECUTABLE, specificity: 'generic' },

  '.cs': { modType: MOD_TYPES.SCRIPT, specificity: 'generic' },
  '.lua': { modType: MOD_TYPES.SCRIPT, specificity: 'generic' }, // توجه: .lua مال Roblox هم هست

  '.ytd': { modType: MOD_TYPES.ASSET, specificity: 'specific' },
  '.ydd': { modType: MOD_TYPES.ASSET, specificity: 'specific' },
  '.yft': { modType: MOD_TYPES.ASSET, specificity: 'specific' },
  '.ymap': { modType: MOD_TYPES.ASSET, specificity: 'specific' },

  '.meta': { modType: MOD_TYPES.METADATA, specificity: 'specific' },
  '.ini': { modType: MOD_TYPES.METADATA, specificity: 'generic' },
  '.json': { modType: MOD_TYPES.METADATA, specificity: 'generic' },
  '.xml': { modType: MOD_TYPES.METADATA, specificity: 'generic' },

  '.rpf': { modType: MOD_TYPES.PACKAGE, specificity: 'specific' },

  '.zip': { modType: MOD_TYPES.ARCHIVE, specificity: 'generic' },
  '.7z': { modType: MOD_TYPES.ARCHIVE, specificity: 'generic' },
  '.rar': { modType: MOD_TYPES.ARCHIVE, specificity: 'generic' },
});

// پسوندهای «بی‌گناه‌نما» که در حیلهٔ پسوند دوگانه (مثل invoice.pdf.exe)
// معمولاً به‌عنوان طعمه در وسط نام فایل ظاهر می‌شوند — فقط برای
// تشخیص بستهٔ مشکوک استفاده می‌شود، نه برای طبقه‌بندی GTA بودن.
const DECOY_LOOKING_EXTENSIONS = new Set([
  '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.txt', '.doc', '.docx',
  '.mp3', '.mp4', '.avi', '.mov', '.rtf', '.csv',
]);

// پسوندهایی که اجرای مستقیم/بارگذاری کد را نشان می‌دهند — اگر این‌ها
// در وسط نام (نه در انتها) ظاهر شوند نیز شاهد بستهٔ مشکوک است.
const EXECUTABLE_LIKE_EXTENSIONS = new Set(['.exe', '.dll', '.asi', '.bat', '.cmd', '.scr', '.com', '.ps1']);

/* ------------------------------------------------------------
   کلیدواژه‌های زمینه‌ای GTA — فقط برای افزایش/کاهش اطمینان
   طبقه‌بندی استفاده می‌شوند، هرگز برای تشخیص بدافزار. دقیقاً همان
   فلسفهٔ gta_markers در rules.json (شاهد زمینه‌ای، نه شاهد امنیتی)
   اما اینجا به‌طور کاملاً مستقل و بدون وابستگی به rules.json
   پیاده‌سازی شده تا هیچ وابستگی‌ای به فایل‌های منجمد ایجاد نشود.
   ------------------------------------------------------------ */
const GTA_CONTEXT_KEYWORDS = Object.freeze([
  'grand theft auto', 'gtav', 'gta5', 'gta 5', 'gta iv', 'gtaiv', 'gta sa', 'gta vc',
  'scripthookv', 'scripthookdotnet', 'scripthook', 'rage engine', 'rockstar games',
  'social club', 'openiv', 'fivem', 'ragemp', 'altv', 'menyoo', 'gta online',
]);

// کلیدواژه‌های بافت بازی‌های دیگر — اگر این‌ها بدون هیچ کلیدواژهٔ GTA
// دیده شوند، به‌صراحت اطمینان GTA بودن را کاهش می‌دهند (بخش ۴ مشخصات:
// «Minecraft/Roblox/Skyrim/Fallout را به‌عنوان GTA طبقه‌بندی نکن»).
const OTHER_GAME_KEYWORDS = Object.freeze([
  'minecraft', 'forge mod', 'fabric mod', 'roblox', 'skyrim', 'fallout 4',
  'fallout new vegas', 'nexusmods skyrim', 'the sims 4',
]);

/* ============================================================
   ابزارهای امن/بدون‌استثنا
   ============================================================ */

function safeLower(s) {
  try { return String(s).toLowerCase(); } catch (e) { return ''; }
}

/**
 * نام فایل را به آرایه‌ای از «توکن‌های پسوند» تجزیه می‌کند.
 * مثال: "cool.mod.asi.zip" -> [".mod", ".asi", ".zip"]
 * توکن آخر همیشه «پسوند اصلی/مؤثر» (primaryExtension) است — دقیقاً
 * همان چیزی که سیستم‌عامل برای تعیین نوع فایل استفاده می‌کند.
 */
function tokenizeExtensions(filename) {
  const name = safeLower(filename).trim();
  if (!name || name.length > DETECTOR_LIMITS.MAX_FILENAME_LENGTH) return [];

  // نام‌هایی که با نقطه شروع می‌شوند (فایل مخفی یونیکسی مثل ".gitignore")
  // را به‌عنوان اولین نقطه نادیده می‌گیریم تا اشتباهاً پسوند فرض نشود.
  const trimmedLeadingDot = name.replace(/^\.+/, '');
  const parts = trimmedLeadingDot.split('.');
  if (parts.length < 2) return []; // بدون پسوند

  const tokens = [];
  const start = Math.max(1, parts.length - DETECTOR_LIMITS.MAX_EXTENSION_TOKENS);
  for (let i = start; i < parts.length; i++) {
    const seg = parts[i].trim();
    if (seg) tokens.push('.' + seg);
  }
  return tokens;
}

/**
 * بایت‌های ابتدایی فایل را برای شناسایی امضای container می‌خواند.
 * هرگز کل فایل را نمی‌خواند؛ فقط چند بایت اول. در صورت هر خطایی،
 * null برمی‌گرداند و detector ادامه می‌دهد (بدون کرش).
 */
async function readMagicBytes(file, count) {
  try {
    if (!file || typeof file.slice !== 'function') return null;
    const blob = file.slice(0, count);
    const buf = await blob.arrayBuffer();
    return new Uint8Array(buf);
  } catch (e) {
    return null;
  }
}

/** مقایسهٔ امن یک پیشوند بایتی با یک آرایهٔ اعداد مورد انتظار. */
function bytesStartWith(bytes, expected) {
  if (!bytes || bytes.length < expected.length) return false;
  for (let i = 0; i < expected.length; i++) {
    if (bytes[i] !== expected[i]) return false;
  }
  return true;
}

/**
 * تشخیص امضای container بر اساس بایت‌های ابتدایی. این تابع فقط
 * می‌خواند و مقایسه می‌کند — هرگز فایل را باز/اجرا نمی‌کند.
 *
 * توجه صادقانه: امضاهای ZIP/7z/RAR/MZ استانداردهای عمومی و کاملاً
 * مستند هستند. امضاهای RSC7/RSC8 (برای ytd/ydd/yft/ymap) و
 * RPF7/RPF8 (برای rpf) قراردادهایی هستند که عمدتاً در ابزارهای
 * جامعهٔ مادسازی (مثل CodeWalker/OpenIV) مستند شده‌اند، نه یک
 * استاندارد رسمی منتشرشده توسط Rockstar — بنابراین این‌ها به‌عنوان
 * «شاهد اکتشافی با اطمینان محدود» علامت‌گذاری می‌شوند و هرگز به‌تنهایی
 * تعیین‌کنندهٔ route نیستند، فقط سطح confidence را تنظیم می‌کنند.
 */
function sniffContainerMagic(bytes) {
  if (!bytes || bytes.length === 0) return { kind: null, verified: false };

  if (bytesStartWith(bytes, [0x4d, 0x5a])) return { kind: 'mz_pe', verified: true }; // MZ
  if (bytesStartWith(bytes, [0x50, 0x4b, 0x03, 0x04])) return { kind: 'zip', verified: true };
  if (bytesStartWith(bytes, [0x50, 0x4b, 0x05, 0x06])) return { kind: 'zip', verified: true }; // آرشیو خالی
  if (bytesStartWith(bytes, [0x50, 0x4b, 0x07, 0x08])) return { kind: 'zip', verified: true }; // spanned
  if (bytesStartWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { kind: '7z', verified: true };
  if (bytesStartWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return { kind: 'rar', verified: true }; // RAR4/RAR5 هر دو با این پیشوند شروع می‌شوند

  // اکتشافی، اطمینان محدود (بالا را ببینید):
  const asciiHead = bytesToAsciiSafe(bytes.subarray(0, 4));
  if (asciiHead === 'RSC7' || asciiHead === 'RSC8') return { kind: 'rage_resource', verified: false };
  if (asciiHead === 'RPF7' || asciiHead === 'RPF8') return { kind: 'rage_package', verified: false };

  return { kind: 'unrecognized', verified: false };
}

function bytesToAsciiSafe(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '\u0000';
  }
  return s;
}

/**
 * جست‌وجوی محدود (bounded) کلیدواژهٔ زمینه‌ای در نام فایل + چند
 * کیلوبایت ابتدایی محتوا. فقط یک substring-search ساده روی رشتهٔ
 * ASCII کوچک‌حرف است — هیچ اجرا/کامپایل/eval ای در کار نیست؛ دقیقاً
 * همان تکنیک کم‌خطری که engine.js برای اسکن رشته استفاده می‌کند.
 */
async function scanGtaContext(file, filenameLower) {
  const found = { gtaKeywords: [], otherGameKeywords: [] };

  for (const kw of GTA_CONTEXT_KEYWORDS) {
    if (filenameLower.includes(kw)) found.gtaKeywords.push(kw);
  }
  for (const kw of OTHER_GAME_KEYWORDS) {
    if (filenameLower.includes(kw)) found.otherGameKeywords.push(kw);
  }

  // برای انواع متنی/کوچک (اسکریپت، متادیتا، fallback عمومی) محتوای
  // ابتدایی را هم بررسی می‌کنیم؛ برای فایل‌های باینری بزرگ (پلاگین/
  // آرشیو/اجرایی) این کار بی‌فایده و پرهزینه است، پس رد می‌شویم.
  try {
    if (file && typeof file.slice === 'function' && typeof file.size === 'number' && file.size > 0) {
      const sliceSize = Math.min(file.size, DETECTOR_LIMITS.CONTEXT_SCAN_BYTES);
      const buf = await file.slice(0, sliceSize).arrayBuffer();
      const bytes = new Uint8Array(buf);
      const text = safeLower(bytesToAsciiSafe(bytes));
      for (const kw of GTA_CONTEXT_KEYWORDS) {
        if (!found.gtaKeywords.includes(kw) && text.includes(kw)) found.gtaKeywords.push(kw);
      }
      for (const kw of OTHER_GAME_KEYWORDS) {
        if (!found.otherGameKeywords.includes(kw) && text.includes(kw)) found.otherGameKeywords.push(kw);
      }
    }
  } catch (e) {
    // خواندن محتوا اختیاری است؛ اگر شکست خورد فقط از نتایج نام فایل استفاده می‌کنیم
  }

  return found;
}

/* ============================================================
   تشخیص بستهٔ مشکوک (بدون قضاوت دربارهٔ بدافزار بودن)
   ============================================================ */
function detectSuspiciousPackaging(extensionTokens, primaryExt, magic) {
  const reasons = [];
  let suspicious = false;

  if (extensionTokens.length >= 2) {
    const earlierTokens = extensionTokens.slice(0, -1);

    // الگوی «طعمه در ابتدا، اجرایی در انتها» — مثل invoice.pdf.exe
    const hasDecoyEarlier = earlierTokens.some(t => DECOY_LOOKING_EXTENSIONS.has(t));
    const primaryIsExecutableLike = EXECUTABLE_LIKE_EXTENSIONS.has(primaryExt);
    if (hasDecoyEarlier && primaryIsExecutableLike) {
      suspicious = true;
      reasons.push('نام فایل الگوی کلاسیک «پسوند دوگانهٔ فریبنده» را نشان می‌دهد (یک پسوند بی‌خطرنما قبل از پسوند واقعی اجرایی/پلاگین).');
    }

    // الگوی «اجرایی/پلاگین در وسط، غیراجرایی در انتها» — کم‌خطرتر اما
    // همچنان گمراه‌کننده و قابل‌گزارش.
    const hasExecutableLikeEarlier = earlierTokens.some(t => EXECUTABLE_LIKE_EXTENSIONS.has(t));
    if (hasExecutableLikeEarlier && !primaryIsExecutableLike) {
      suspicious = true;
      reasons.push('نام فایل حاوی یک پسوند اجرایی/پلاگین در میانهٔ نام است، در حالی که پسوند واقعی/مؤثر چیز دیگری است.');
    }
  }

  // ناهماهنگی پسوند ادعاشده با امضای واقعی محتوا (فقط برای
  // مواردی که با اطمینان بالا قابل‌تأیید هستند: MZ/ZIP/7z/RAR)
  if (magic && magic.verified) {
    const primaryInfo = EXTENSION_TABLE[primaryExt];
    const primaryModType = primaryInfo ? primaryInfo.modType : null;

    const magicImpliesArchive = magic.kind === 'zip' || magic.kind === '7z' || magic.kind === 'rar';
    const magicImpliesExecutableContainer = magic.kind === 'mz_pe';

    if (magicImpliesExecutableContainer && primaryModType && primaryModType !== MOD_TYPES.PLUGIN && primaryModType !== MOD_TYPES.EXECUTABLE) {
      suspicious = true;
      reasons.push('محتوای فایل با امضای یک فایل اجرایی ویندوز (MZ/PE) شروع می‌شود، اما پسوند ادعاشده با این نوع همخوانی ندارد.');
    }
    if (magicImpliesArchive && primaryModType && primaryModType !== MOD_TYPES.ARCHIVE && primaryModType !== MOD_TYPES.PACKAGE) {
      suspicious = true;
      reasons.push('محتوای فایل با امضای یک آرشیو فشرده شروع می‌شود، اما پسوند ادعاشده با این نوع همخوانی ندارد.');
    }
    if (!magicImpliesArchive && !magicImpliesExecutableContainer && (primaryModType === MOD_TYPES.ARCHIVE || primaryModType === MOD_TYPES.PLUGIN)) {
      // پسوند ادعا می‌کند آرشیو/پلاگین است اما امضای شناخته‌شدهٔ متناظر یافت نشد
      suspicious = true;
      reasons.push('پسوند فایل مدعی یک نوع خاص (آرشیو یا پلاگین) است، اما امضای محتوای فایل با آن مطابقت ندارد.');
    }
  }

  return { suspicious, reasons };
}

/* ============================================================
   تعیین modType/confidence/route بر اساس همهٔ شواهد جمع‌آوری‌شده
   ============================================================ */
function classify(primaryExt, extensionTokens, gtaContext, magic, suspiciousPackaging) {
  const reasons = [];
  const info = EXTENSION_TABLE[primaryExt];

  const hasStrongGtaKeyword = gtaContext.gtaKeywords.length > 0;
  const hasOtherGameKeyword = gtaContext.otherGameKeywords.length > 0 && !hasStrongGtaKeyword;

  if (hasOtherGameKeyword) {
    reasons.push('شواهد زمینه‌ای به بازی/پلتفرم دیگری غیر از GTA اشاره دارند (' + gtaContext.otherGameKeywords.join(', ') + ')؛ این ورودی به‌عنوان مود GTA طبقه‌بندی نمی‌شود.');
  }

  // --- بدون پسوند شناخته‌شده در انتهای نام ---
  if (!info) {
    if (magic && (magic.kind === 'rage_resource' || magic.kind === 'rage_package')) {
      // اکتشافی، اطمینان محدود — پسوند نامعتبر است ولی امضا به RAGE اشاره دارد
      reasons.push('پسوند فایل شناخته‌شده نیست، اما امضای محتوا با فرمت‌های منابع RAGE مطابقت اکتشافی دارد.');
      return {
        modType: MOD_TYPES.UNKNOWN, isGtaMod: false, confidence: CONFIDENCE.LOW,
        route: ROUTES.INCONCLUSIVE, reasons,
      };
    }
    if (hasStrongGtaKeyword) {
      reasons.push('پسوند فایل شناخته‌شده نیست، اما نام/محتوای فایل حاوی کلیدواژه‌های زمینه‌ای GTA است.');
      return {
        modType: MOD_TYPES.UNKNOWN, isGtaMod: false, confidence: CONFIDENCE.LOW,
        route: ROUTES.INCONCLUSIVE, reasons,
      };
    }
    reasons.push('پسوند فایل (' + (primaryExt || 'بدون پسوند') + ') در هیچ‌یک از دسته‌های شناخته‌شدهٔ مود GTA نیست.');
    return {
      modType: MOD_TYPES.UNKNOWN, isGtaMod: false, confidence: CONFIDENCE.HIGH,
      route: ROUTES.REJECT, reasons,
    };
  }

  // --- پسوند شناخته‌شده است ---
  const modType = info.modType;
  let confidence = info.specificity === 'specific' ? CONFIDENCE.MEDIUM : CONFIDENCE.LOW;
  let isGtaMod = info.specificity === 'specific';

  if (hasStrongGtaKeyword) {
    confidence = CONFIDENCE.HIGH;
    isGtaMod = true;
    reasons.push('کلیدواژه‌های زمینه‌ای GTA در نام/محتوای فایل یافت شد: ' + gtaContext.gtaKeywords.slice(0, 3).join(', ') + '.');
  } else if (hasOtherGameKeyword) {
    isGtaMod = false;
    confidence = CONFIDENCE.LOW;
  } else if (info.specificity === 'specific') {
    reasons.push('پسوند «' + primaryExt + '» عمدتاً در بافت مادسازی GTA/RAGE استفاده می‌شود.');
  } else {
    reasons.push('پسوند «' + primaryExt + '» عمومی است و به‌تنهایی شاهد کافی برای تعیین ارتباط با GTA نیست.');
  }

  // اطمینان اکتشافی امضای محتوا (RSC7/RSC8/RPF7/RPF8) — همیشه فقط
  // تقویت‌کننده، هرگز به‌تنهایی تعیین‌کنندهٔ isGtaMod=true نیست چون
  // این امضاها رسماً مستند نشده‌اند (بالا را ببینید).
  if (magic && !magic.verified && (magic.kind === 'rage_resource' || magic.kind === 'rage_package')) {
    if (confidence === CONFIDENCE.LOW) confidence = CONFIDENCE.MEDIUM;
    reasons.push('امضای ابتدایی محتوا با قراردادهای شناخته‌شدهٔ جامعه برای فایل‌های منبع RAGE مطابقت اکتشافی دارد (تأییدشدهٔ رسمی نیست).');
  }

  // --- تعیین route بر اساس نوع. برای .asi (اختصاصی GTA/RAGE) این
  // مستقل از confidence است، اما برای .dll (یک container عمومی
  // ویندوز که در همهٔ نرم‌افزارها به کار می‌رود) صرفِ داشتنِ این
  // پسوند دلیلی بر تعلق به یک مود GTA نیست — بدون شاهد زمینه‌ای
  // واقعی GTA (isGtaMod=true)، نباید به‌طور خودکار وارد پایپ‌لاین
  // Engine شود، چون GTA Guard صراحتاً یک اسکنر GTA-only است. ---
  let route;
  if (primaryExt === '.asi') {
    // استثنای صریح: .asi پسوندی اختصاصی مادسازی GTA/RAGE است و
    // همیشه به Engine v2.2.0 مسیریابی می‌شود (خودِ Engine اعتبار
    // ساختاری PE را می‌سنجد؛ این‌جا فقط مسیریابی نوع فایل است).
    route = ROUTES.ENGINE;
    reasons.push('پسوند .asi اختصاصاً در مادسازی GTA/RAGE استفاده می‌شود و مستقیماً توسط Engine v2.2.0 قابل‌تحلیل است.');
  } else if (primaryExt === '.dll') {
    if (isGtaMod) {
      // شاهد زمینه‌ای واقعی GTA (کلیدواژه در نام/محتوا) پیدا شده —
      // اکنون منطقی است که به Engine مسیریابی شود.
      route = ROUTES.ENGINE;
      reasons.push('شواهد زمینه‌ای GTA برای این DLL یافت شد؛ به Engine v2.2.0 مسیریابی می‌شود.');
    } else if (hasOtherGameKeyword) {
      // شاهد صریح تعلق به بازی/پلتفرم دیگر — خارج از محدودهٔ این ابزار.
      route = ROUTES.REJECT;
      reasons.push('این DLL به بازی/پلتفرم دیگری اشاره دارد و خارج از محدودهٔ GTA Guard (اسکنر اختصاصی GTA) است.');
    } else {
      // یک DLL عمومی ویندوز بدون هیچ شاهد GTA — نباید صرفاً به‌خاطر
      // پسوند اجرایی‌بودن وارد پایپ‌لاین امنیتی GTA شود.
      route = ROUTES.INCONCLUSIVE;
      reasons.push('این یک DLL عمومی ویندوز است؛ بدون شاهد زمینه‌ای GTA، به‌طور خودکار به Engine مسیریابی نمی‌شود.');
    }
  } else if (modType === MOD_TYPES.ARCHIVE || modType === MOD_TYPES.PACKAGE) {
    route = ROUTES.ARCHIVE_INSPECTION;
    reasons.push('این نوع بسته نیازمند بازرسی آرشیو است (در این نسخه فقط مسیریابی می‌شود، استخراج نمی‌شود).');
  } else {
    // executable / script / asset / metadata — فعلاً هیچ لایهٔ
    // پردازشی برای این‌ها وجود ندارد، صرف‌نظر از confidence.
    route = ROUTES.INCONCLUSIVE;
    reasons.push('در حال حاضر هیچ لایهٔ تحلیل ایمن‌ای برای این نوع فایل در دسترس نیست؛ توقف ایمن.');
  }

  if (suspiciousPackaging) {
    // بستهٔ مشکوک هرگز باعث REJECT نمی‌شود (ممکن است کاذب باشد)، اما
    // هرگز نباید بی‌سروصدا نادیده گرفته شود — به INCONCLUSIVE تنزل
    // می‌دهیم تا حتماً برای بازبینی علامت‌گذاری شود، مگر مسیر از قبل
    // ENGINE بوده (چون Engine خودش این را با پرچم DLL/EXE می‌سنجد).
    if (route !== ROUTES.ENGINE) {
      route = ROUTES.INCONCLUSIVE;
    }
  }

  return { modType, isGtaMod, confidence, route, reasons };
}

/* ============================================================
   نقطهٔ ورود عمومی
   ============================================================ */
const GtaModDetector = {
  version: GTA_MOD_DETECTOR_VERSION,

  /**
   * تحلیل یک فایل و بازگرداندن یک نتیجهٔ طبقه‌بندی/مسیریابی.
   * این تابع هرگز استثنای کنترل‌نشده پرتاب نمی‌کند.
   */
  async analyze(file) {
    const baseInvalid = (reasonMsg) => ({
      isGtaMod: false,
      confidence: CONFIDENCE.LOW,
      modType: MOD_TYPES.UNKNOWN,
      detectedExtensions: [],
      suspiciousPackaging: false,
      route: ROUTES.REJECT,
      reasons: [reasonMsg],
      detectorVersion: GTA_MOD_DETECTOR_VERSION,
    });

    try {
      if (!file || typeof file !== 'object') {
        return baseInvalid('ورودی نامعتبر است (فایل نیست).');
      }
      if (typeof file.name !== 'string' || !file.name.trim()) {
        return baseInvalid('فایل بدون نام قابل‌طبقه‌بندی نیست.');
      }
      if (typeof file.size === 'number' && file.size === 0) {
        return baseInvalid('فایل خالی است.');
      }

      const filenameLower = safeLower(file.name);

      if (file.name.length > DETECTOR_LIMITS.MAX_FILENAME_LENGTH) {
        return {
          isGtaMod: false, confidence: CONFIDENCE.LOW, modType: MOD_TYPES.UNKNOWN,
          detectedExtensions: [], suspiciousPackaging: false, route: ROUTES.REJECT,
          reasons: ['نام فایل بیش‌ازحد طولانی است و به‌صورت ایمن رد شد.'],
          detectorVersion: GTA_MOD_DETECTOR_VERSION,
        };
      }

      const extensionTokens = tokenizeExtensions(file.name);

      if (extensionTokens.length === 0) {
        return {
          isGtaMod: false, confidence: CONFIDENCE.HIGH, modType: MOD_TYPES.UNKNOWN,
          detectedExtensions: [], suspiciousPackaging: false, route: ROUTES.REJECT,
          reasons: ['فایل هیچ پسوندی ندارد.'], detectorVersion: GTA_MOD_DETECTOR_VERSION,
        };
      }

      const primaryExt = extensionTokens[extensionTokens.length - 1];
      const detectedExtensions = extensionTokens.filter(t => EXTENSION_TABLE[t] !== undefined);
      // همیشه پسوند اصلی را هم در فهرست نگه می‌داریم، حتی اگر ناشناخته باشد،
      // چون این خودِ اطلاعات مهمی برای مصرف‌کنندهٔ خروجی است.
      if (!detectedExtensions.includes(primaryExt)) detectedExtensions.push(primaryExt);

      const magicBytes = await readMagicBytes(file, DETECTOR_LIMITS.MAGIC_SNIFF_BYTES);
      const magic = sniffContainerMagic(magicBytes);

      const gtaContext = await scanGtaContext(file, filenameLower);

      const packaging = detectSuspiciousPackaging(extensionTokens, primaryExt, magic);

      const classification = classify(primaryExt, extensionTokens, gtaContext, magic, packaging.suspicious);

      return {
        isGtaMod: classification.isGtaMod,
        confidence: classification.confidence,
        modType: classification.modType,
        detectedExtensions,
        suspiciousPackaging: packaging.suspicious,
        route: classification.route,
        reasons: [...classification.reasons, ...packaging.reasons],
        detectorVersion: GTA_MOD_DETECTOR_VERSION,
      };
    } catch (err) {
      // هرگز نباید به اینجا برسد؛ اگر برسد، همچنان یک نتیجهٔ ساختاریافته
      // و ایمن برمی‌گردانیم، نه یک استثنای کنترل‌نشده.
      console.error('GtaModDetector: خطای غیرمنتظره', err);
      return baseInvalid('خطای غیرمنتظره در طول تحلیل رخ داد؛ به‌صورت ایمن رد شد.');
    }
  },
};

window.GtaModDetector = GtaModDetector;

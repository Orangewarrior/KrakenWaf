//! Open Redirect & Remote File Inclusion (RFI) detection CMC module.
//!
//! The module inspects request **parameters** — names taken from the URL query
//! string on `GET` and from the body on `POST`/other methods — and decides, per
//! parameter, whether the *value* is an attempt to drive an open redirect or a
//! remote/local file inclusion.
//!
//! ## Two-stage decision
//!
//! 1. **Hot-parameter gate.** A parameter is only inspected when its (decoded,
//!    lowercased) name *matches a "hot" redirect/inclusion parameter token*.
//!    The base list is [`HOT_PARAMS_ENGLISH`]; additional localized lists are
//!    enabled per-language through the `multiple-languages-params` /
//!    `custom-languages-params` config block (see [`LangParams`]). Matching is
//!    **substring containment** for multi-character tokens (so `homepage`
//!    matches `page` and `redirect_url` matches both `redirect` and `url`) and
//!    **exact** for single-character tokens (`u`, `r`) to avoid pathological
//!    false positives.
//!
//! 2. **Value classification.** The matched parameter's value is decoded
//!    through the global normalizer (UTF-16 transcode → repeated percent-decode
//!    → `+`→space) and its leading control/whitespace bytes are stripped with
//!    [`crate::waf::strip_control_and_space_prefix`]. Then:
//!      * a value whose decoded form **starts with** an entry of
//!        [`OPEN_REDIRECT_STARTS_WITH`] → **Open Redirect** (`CWE-601`),
//!      * a value whose decoded form **starts with** an entry of
//!        [`RFI_STARTS_WITH`] → **RFI** (`CWE-98`),
//!      * a value that **ends with** `?` or a NUL (`%00`) → **RFI** (`CWE-98`).
//!
//! All three outcomes are reported at **High** severity and the engine blocks
//! the attacker.
//!
//! ## Why decoding is centralized
//!
//! Every encoding-evasion case from the spec (percent, double-percent,
//! mixed-case hex, UTF-16BE/LE, `+`, and control-character prefixes) is handled
//! by the shared normalizer, so this module never re-implements decoding. The
//! one piece of hardening it needed — stripping a leading control/whitespace
//! prefix before the `starts_with` check — was added to the normalizer as a
//! reusable helper so **every** CMC module benefits.

use super::CmcManager;
use crate::waf::{normalize_str, strip_control_and_space_prefix};

/// Base redirect/inclusion-prone parameter names (always active).
pub const HOT_PARAMS_ENGLISH: &[&str] = &[
    "redirect", "url", "return", "open", "u", "r", "href", "next", "callback", "last", "dest",
    "uri", "target", "continue", "page", "module", "path", "template", "file", "include", "inc",
    "doc", "document", "folder", "root", "dir", "view", "load", "show",
];

/// Value prefixes that indicate an **open redirect** (scheme-relative URLs,
/// backslash/UNC confusion, and dangerous URL schemes).
pub const OPEN_REDIRECT_STARTS_WITH: &[&str] = &[
    "//",
    "///",
    "\\\\",
    "\\",
    "/\\",
    "\\/",
    "http:",
    "https:",
    "ws:",
    "wss:",
    "ftp:",
    "ftps:",
    "file:",
    "javascript:",
    "data:",
    "vbscript:",
    "blob:",
    "about:",
    "view-source:",
    "intent:",
    "android-app:",
    "market:",
    "itms-services:",
];

/// Value prefixes that indicate a **remote/local file inclusion** (PHP wrappers
/// and other inclusion-prone URI schemes).
pub const RFI_STARTS_WITH: &[&str] = &[
    "php:",
    "php://",
    "php://filter",
    "php://input",
    "php://memory",
    "php://temp",
    "expect:",
    "expect://",
    "zip:",
    "zip://",
    "phar:",
    "gopher:",
    "dict:",
    "ldap:",
    "ldaps:",
    "glob:",
    "zlib:",
    "compress.zlib:",
    "compress.bzip2:",
    "rar:",
    "ogg:",
];

// ── Localized hot-parameter lists ───────────────────────────────────────────

pub const HOT_PARAMS_CHINESE_MANDARIN: &[&str] = &[
    "chongdingxiang", "fanhui", "dakai", "xiayige", "huidiao", "zuihou", "mudidi", "mubiao",
    "jixu", "yemian", "mokuai", "lujing", "muban", "wenjian", "baohan", "wendang", "wenjianjia",
    "gen", "mulu", "chakan", "jiazai", "xianshi",
];

pub const HOT_PARAMS_CHINESE: &[&str] = &[
    "重定向", "返回", "打开", "下一个", "回调", "最后", "目的地", "目标", "继续", "页面",
    "模块", "路径", "模板", "文件", "包含", "文档", "文件夹", "根", "目录", "查看", "加载",
    "显示",
];

pub const HOT_PARAMS_HINDI: &[&str] = &[
    "रीडायरेक्ट", "वापसी", "खोलें", "अगला", "कॉलबैक", "अंतिम", "गंतव्य", "लक्ष्य", "जारीरखें",
    "पृष्ठ", "मॉड्यूल", "पथ", "टेम्पलेट", "फ़ाइल", "शामिल", "दस्तावेज", "फ़ोल्डर", "रूट",
    "निर्देशिका", "देखें", "लोड", "दिखाएं",
];

pub const HOT_PARAMS_SPANISH: &[&str] = &[
    "redirigir", "retorno", "abrir", "siguiente", "callback", "ultimo", "destino", "objetivo",
    "continuar", "pagina", "modulo", "ruta", "plantilla", "archivo", "incluir", "documento",
    "carpeta", "raiz", "directorio", "vista", "cargar", "mostrar",
];

pub const HOT_PARAMS_ARABIC_MODERN_STANDARD: &[&str] = &[
    "إعادة_توجيه", "عودة", "فتح", "التالي", "استدعاء", "الأخير", "وجهة", "هدف", "متابعة", "صفحة",
    "وحدة", "مسار", "قالب", "ملف", "تضمين", "مستند", "مجلد", "جذر", "دليل", "عرض", "تحميل",
    "إظهار",
];

pub const HOT_PARAMS_FRENCH: &[&str] = &[
    "redirection", "retour", "ouvrir", "suivant", "rappel", "dernier", "destination", "cible",
    "continuer", "page", "module", "chemin", "modele", "fichier", "inclure", "document", "dossier",
    "racine", "repertoire", "vue", "charger", "afficher",
];

pub const HOT_PARAMS_BENGALI: &[&str] = &[
    "পুনর্নির্দেশ", "ফেরত", "খুলুন", "পরবর্তী", "কলব্যাক", "শেষ", "গন্তব্য", "লক্ষ্য",
    "চালিয়েযান", "পৃষ্ঠা", "মডিউল", "পথ", "টেমপ্লেট", "ফাইল", "অন্তর্ভুক্ত", "নথি", "ফোল্ডার",
    "মূল", "ডিরেক্টরি", "দেখুন", "লোড", "দেখান",
];

pub const HOT_PARAMS_INDONESIAN: &[&str] = &[
    "pengalihan", "kembali", "buka", "berikutnya", "callback", "terakhir", "tujuan", "target",
    "lanjutkan", "halaman", "modul", "jalur", "templat", "berkas", "sertakan", "dokumen", "folder",
    "akar", "direktori", "tampilan", "muat", "tampilkan",
];

pub const HOT_PARAMS_RUSSIAN: &[&str] = &[
    "редирект", "возврат", "открыть", "следующий", "колбэк", "последний", "назначение", "цель",
    "продолжить", "страница", "модуль", "путь", "шаблон", "файл", "включить", "документ", "папка",
    "корень", "директория", "просмотр", "загрузить", "показать",
];

pub const HOT_PARAMS_GERMAN: &[&str] = &[
    "weiterleitung", "rueckgabe", "oeffnen", "naechste", "rueckruf", "letzte", "ziel", "zielobjekt",
    "fortsetzen", "seite", "modul", "pfad", "vorlage", "datei", "einschliessen", "dokument",
    "ordner", "wurzel", "verzeichnis", "ansicht", "laden", "anzeigen",
];

pub const HOT_PARAMS_JAPANESE: &[&str] = &[
    "リダイレクト", "戻り", "開く", "次", "コールバック", "最後", "宛先", "対象", "続行",
    "ページ", "モジュール", "パス", "テンプレート", "ファイル", "インクルード", "文書",
    "フォルダ", "ルート", "ディレクトリ", "ビュー", "ロード", "表示",
];

pub const HOT_PARAMS_PORTUGUESE: &[&str] = &[
    "redirecionamento", "retorno", "abrir", "proximo", "callback", "ultimo", "destino", "alvo",
    "continuar", "pagina", "modulo", "caminho", "modelo", "arquivo", "incluir", "documento",
    "pasta", "raiz", "diretorio", "visualizar", "carregar", "mostrar",
];

/// Which optional localized hot-parameter lists are active. Mirrors the
/// `custom-languages-params` map in `rules/cmc/config.yaml`. By default every
/// language is disabled (English only); a language list is added to the search
/// set only when its flag is `true` **and** `multiple-languages-params` is on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct LangParams {
    /// Master switch: when `false`, only [`HOT_PARAMS_ENGLISH`] is used.
    pub enabled: bool,
    pub russian: bool,
    pub japanese: bool,
    pub german: bool,
    pub bengali: bool,
    pub indonesian: bool,
    pub french: bool,
    /// Covers both the `arabic_modern` and `arabic_modern_standard` config keys.
    pub arabic_modern_standard: bool,
    pub spanish: bool,
    pub chinese_mandarin: bool,
    pub chinese: bool,
    pub hindi: bool,
    pub portuguese: bool,
}

/// The vulnerability class a value classified into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnKind {
    /// Open redirect — scheme-relative URL, backslash confusion, or external
    /// scheme (`CWE-601`).
    OpenRedirect,
    /// Remote/Local File Inclusion — PHP wrapper, inclusion scheme, or a
    /// trailing `?` / `%00` truncation marker (`CWE-98`).
    Rfi,
}

impl VulnKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            VulnKind::OpenRedirect => "open_redirect",
            VulnKind::Rfi => "rfi",
        }
    }
}

/// A single detection: which parameter fired, which hot token it matched, the
/// vulnerability class, and the prefix/marker that classified the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRedirectRfiMatch {
    kind: VulnKind,
    parameter: String,
    matched_token: String,
    marker: String,
}

impl OpenRedirectRfiMatch {
    #[must_use]
    pub fn kind(&self) -> VulnKind {
        self.kind
    }
    #[must_use]
    pub fn parameter(&self) -> &str {
        &self.parameter
    }
    #[must_use]
    pub fn matched_token(&self) -> &str {
        &self.matched_token
    }
    /// The prefix / suffix marker that triggered the classification (e.g.
    /// `https:`, `//`, `php://`, or `trailing-%00`).
    #[must_use]
    pub fn marker(&self) -> &str {
        &self.marker
    }
}

/// Detector holding the active hot-parameter token set.
#[derive(Debug, Clone)]
pub struct OpenRedirectRfiDetector {
    tokens: Vec<&'static str>,
}

#[derive(Debug, Default)]
pub struct OpenRedirectRfiDetectorBuilder {
    lang: LangParams,
}

impl OpenRedirectRfiDetectorBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            lang: LangParams::default(),
        }
    }

    #[must_use]
    pub fn lang_params(mut self, lang: LangParams) -> Self {
        self.lang = lang;
        self
    }

    #[must_use]
    pub fn build(self) -> OpenRedirectRfiDetector {
        let mut tokens: Vec<&'static str> = HOT_PARAMS_ENGLISH.to_vec();
        if self.lang.enabled {
            let l = &self.lang;
            let extra: &[(bool, &[&str])] = &[
                (l.russian, HOT_PARAMS_RUSSIAN),
                (l.japanese, HOT_PARAMS_JAPANESE),
                (l.german, HOT_PARAMS_GERMAN),
                (l.bengali, HOT_PARAMS_BENGALI),
                (l.indonesian, HOT_PARAMS_INDONESIAN),
                (l.french, HOT_PARAMS_FRENCH),
                (l.arabic_modern_standard, HOT_PARAMS_ARABIC_MODERN_STANDARD),
                (l.spanish, HOT_PARAMS_SPANISH),
                (l.chinese_mandarin, HOT_PARAMS_CHINESE_MANDARIN),
                (l.chinese, HOT_PARAMS_CHINESE),
                (l.hindi, HOT_PARAMS_HINDI),
                (l.portuguese, HOT_PARAMS_PORTUGUESE),
            ];
            for (on, list) in extra {
                if *on {
                    tokens.extend_from_slice(list);
                }
            }
        }
        OpenRedirectRfiDetector { tokens }
    }
}

impl OpenRedirectRfiDetector {
    /// Inspect one raw location string (query string or body) for an open
    /// redirect / RFI in a hot parameter's value. Returns the first match.
    #[must_use]
    pub fn detect(&self, raw_location: &str) -> Option<OpenRedirectRfiMatch> {
        for (key_raw, value_raw) in extract_pairs(raw_location) {
            let key_norm = normalize_str(key_raw).to_ascii_lowercase();
            let Some(token) = self.matched_token(&key_norm) else {
                continue;
            };
            if let Some((kind, marker)) = classify_value(value_raw) {
                return Some(OpenRedirectRfiMatch {
                    kind,
                    parameter: key_norm,
                    matched_token: token.to_string(),
                    marker,
                });
            }
        }
        None
    }

    /// Return the first hot token the (decoded, lowercased) parameter name
    /// matches: exact match for single-character tokens, substring containment
    /// for everything else.
    fn matched_token(&self, key_norm_lower: &str) -> Option<&'static str> {
        if key_norm_lower.is_empty() {
            return None;
        }
        for &tok in &self.tokens {
            if tok.len() == 1 {
                if key_norm_lower == tok {
                    return Some(tok);
                }
            } else if memchr::memmem::find(key_norm_lower.as_bytes(), tok.as_bytes()).is_some() {
                // SIMD-accelerated substring search (faster than `str::contains`);
                // byte-level matching is equivalent here since both operands are
                // valid UTF-8.
                return Some(tok);
            }
        }
        None
    }
}

/// Split a raw `application/x-www-form-urlencoded`-style location into
/// `(key, value)` pairs.
///
/// Two passes are run and concatenated so an attacker cannot hide the `=`/`&`
/// separators behind encoding: the **raw** split on literal `&`/`=`, and a
/// split of the fully **normalized** location (which surfaces `%26`/`%3D`-
/// encoded separators). Each segment is split on its first `=`; a segment with
/// no `=` contributes its whole text as a key with an empty value.
fn extract_pairs(raw_location: &str) -> Vec<(&str, &str)> {
    fn split_into<'a>(location: &'a str, out: &mut Vec<(&'a str, &'a str)>) {
        for segment in location.split('&') {
            if segment.is_empty() {
                continue;
            }
            match segment.split_once('=') {
                Some((k, v)) => out.push((k, v)),
                None => out.push((segment, "")),
            }
        }
    }

    let mut pairs: Vec<(&str, &str)> = Vec::new();
    split_into(raw_location, &mut pairs);
    pairs
}

/// Classify a raw parameter value. Returns `Some((kind, marker))` when the
/// value is a redirect/inclusion attempt, otherwise `None`.
fn classify_value(value_raw: &str) -> Option<(VulnKind, String)> {
    // Decode through the shared normalizer (UTF-16 → percent → `+`), then strip
    // a leading control/whitespace prefix so `\t\r\nhttps://…` is judged on its
    // scheme, not on the invisible bytes in front of it.
    let decoded = normalize_str(value_raw);
    let trimmed = strip_control_and_space_prefix(&decoded);
    let lower = trimmed.to_ascii_lowercase();

    for prefix in OPEN_REDIRECT_STARTS_WITH {
        if lower.starts_with(prefix) {
            return Some((VulnKind::OpenRedirect, (*prefix).to_string()));
        }
    }
    for prefix in RFI_STARTS_WITH {
        if lower.starts_with(prefix) {
            return Some((VulnKind::Rfi, (*prefix).to_string()));
        }
    }

    // Trailing truncation markers: a `?` or a `%00` (decoded to NUL) at the end
    // of the value are classic local/remote file inclusion path-cutters.
    let raw_lower = value_raw.to_ascii_lowercase();
    if trimmed.ends_with('?') {
        return Some((VulnKind::Rfi, "trailing-?".to_string()));
    }
    if trimmed.ends_with('\0') || raw_lower.ends_with("%00") {
        return Some((VulnKind::Rfi, "trailing-%00".to_string()));
    }

    None
}

impl CmcManager {
    /// Inspect a request's query string and body for open redirect / RFI in a
    /// hot parameter value. The query is checked first (covers `GET`), then the
    /// body (covers `POST` and other body-bearing methods).
    ///
    /// Returns `Some(Finding)` (High severity) on the first detection so the
    /// engine blocks the attacker and the event is logged to raw / JSONL /
    /// `SQLite`. Returns `None` when the module is disabled or nothing matches.
    #[must_use]
    pub fn inspect_open_redirect_rfi(&self, query: &str, body: &str) -> Option<super::Finding> {
        let detector = self.open_redirect_rfi.as_ref()?;
        let matched = detector
            .detect(query)
            .or_else(|| detector.detect(body))?;

        let (title, cwe, reference_url) = match matched.kind() {
            VulnKind::OpenRedirect => (
                "CMC open redirect detection",
                "CWE-601",
                "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
            ),
            VulnKind::Rfi => (
                "CMC remote file inclusion (RFI) detection",
                "CWE-98",
                "https://owasp.org/www-community/attacks/Remote_File_Inclusion",
            ),
        };

        let description = match matched.kind() {
            VulnKind::OpenRedirect => format!(
                "Blocked open redirect: hot parameter '{param}' (matched token '{tok}') carries a \
                 value that resolves to an external/scheme-relative URL (marker '{marker}'). An \
                 attacker can use it to bounce victims to an attacker-controlled destination.",
                param = matched.parameter(),
                tok = matched.matched_token(),
                marker = matched.marker(),
            ),
            VulnKind::Rfi => format!(
                "Blocked remote/local file inclusion: hot parameter '{param}' (matched token \
                 '{tok}') carries a value using an inclusion wrapper/scheme or a truncation \
                 marker (marker '{marker}').",
                param = matched.parameter(),
                tok = matched.matched_token(),
                marker = matched.marker(),
            ),
        };

        Some(super::finding(
            title,
            super::Severity::High,
            cwe,
            &description,
            reference_url,
            format!(
                "cmc::open_redirect_rfi_detect:kind={} parameter={} token={} marker={}",
                matched.kind().as_str(),
                matched.parameter(),
                matched.matched_token(),
                matched.marker(),
            ),
            "cmc/open_redirect_rfi_detect.rs:generated",
            if detector.detect(query).is_some() {
                query
            } else {
                body
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> OpenRedirectRfiDetector {
        OpenRedirectRfiDetectorBuilder::new().build()
    }

    fn detector_with(lang: LangParams) -> OpenRedirectRfiDetector {
        OpenRedirectRfiDetectorBuilder::new().lang_params(lang).build()
    }

    #[test]
    fn clean_local_path_is_not_a_vuln() {
        // homepage=/test/local — `homepage` matches `page`, but `/test/local`
        // starts with a single slash, not `//`, so it is not a redirect.
        assert!(detector()
            .detect("book=orange_blue&homepage=/test/local")
            .is_none());
    }

    #[test]
    fn scheme_relative_simple() {
        let m = detector().detect("next=//evil.example/path").expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn homepage_substring_match_external_url() {
        let m = detector()
            .detect("book=orange_blue&homepage=https://evil.com")
            .expect("homepage contains `page`");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
        assert_eq!(m.matched_token(), "page");
    }

    #[test]
    fn scheme_relative_percent_encoded() {
        let m = detector()
            .detect("next=%2f%2fevil.example%2fpath")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn double_encoded_scheme_relative() {
        let m = detector()
            .detect("next=%252f%252fevil.example%252fpath")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn https_partially_encoded_scheme() {
        let m = detector()
            .detect("next=https%3a%2f%2fevil.example%2flogin")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn mixed_case_scheme() {
        let m = detector()
            .detect("next=hTtPs://evil.example/login")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn backslash_confusion() {
        let m = detector()
            .detect("next=\\\\evil.example\\login")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn backslash_encoded() {
        let m = detector()
            .detect("next=%5c%5cevil.example%5clogin")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn userinfo_host_confusion() {
        let m = detector()
            .detect("next=https://trusted.example@evil.example/login")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn encoded_userinfo_host_confusion() {
        let m = detector()
            .detect("next=https%3a%2f%2ftrusted.example%40evil.example%2flogin")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn control_char_prefixed_scheme() {
        let m = detector()
            .detect("next=%09%0d%0ahttps://evil.example/login")
            .expect("control chars must be stripped before the scheme check");
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn rfi_php_wrapper() {
        let m = detector()
            .detect("file=php://filter/convert.base64-encode/resource=index.php")
            .expect("match");
        assert_eq!(m.kind(), VulnKind::Rfi);
    }

    #[test]
    fn rfi_external_include() {
        let m = detector()
            .detect("include=http://evil.example/shell.txt")
            .expect("match");
        // http: is in OPEN_REDIRECT_STARTS_WITH and is checked first.
        assert_eq!(m.kind(), VulnKind::OpenRedirect);
    }

    #[test]
    fn rfi_trailing_question_mark() {
        let m = detector()
            .detect("page=/etc/passwd?")
            .expect("trailing ? is an RFI marker");
        assert_eq!(m.kind(), VulnKind::Rfi);
    }

    #[test]
    fn rfi_trailing_null_byte() {
        let m = detector()
            .detect("file=/etc/passwd%00")
            .expect("trailing %00 is an RFI marker");
        assert_eq!(m.kind(), VulnKind::Rfi);
    }

    #[test]
    fn non_hot_param_is_ignored() {
        // `book` is not a hot parameter, so an external URL value is ignored.
        assert!(detector().detect("book=https://evil.com").is_none());
    }

    #[test]
    fn single_char_token_requires_exact_match() {
        // `u` matches exactly…
        assert!(detector().detect("u=https://evil.com").is_some());
        // …but `username` must NOT match via the single-char `u`.
        assert!(detector().detect("username=https://evil.com").is_none());
    }

    #[test]
    fn spec_payloads_block_when_language_enabled() {
        let lang = LangParams {
            enabled: true,
            spanish: true,
            chinese_mandarin: true,
            chinese: true,
            japanese: true,
            ..LangParams::default()
        };
        let d = detector_with(lang);
        assert!(d.detect("retorno=https%3a%2f%2fevil.example").is_some());
        assert!(d.detect("destino=//evil.example").is_some());
        assert!(d.detect("redirigir=%252f%252fevil.example").is_some());
        assert!(d.detect("リダイレクト=https://evil.example").is_some());
        assert!(d.detect("重定向=%2f%2fevil.example").is_some());
        assert!(d
            .detect("redirection=https://trusted.example@evil.example")
            .is_some());
    }

    #[test]
    fn localized_param_ignored_when_language_disabled() {
        // `mostrar` (Spanish "show") shares no substring with any English token,
        // so with languages off it must be ignored even with a redirect value.
        assert!(detector().detect("mostrar=//evil.example").is_none());
    }

    #[test]
    fn localized_param_used_when_language_enabled() {
        let lang = LangParams {
            enabled: true,
            spanish: true,
            ..LangParams::default()
        };
        assert!(detector_with(lang)
            .detect("mostrar=//evil.example")
            .is_some());
    }

    #[test]
    fn master_switch_off_disables_all_localized_lists() {
        // Even with spanish=true, enabled=false means only English is used.
        let lang = LangParams {
            enabled: false,
            spanish: true,
            ..LangParams::default()
        };
        assert!(detector_with(lang)
            .detect("mostrar=//evil.example")
            .is_none());
    }

    #[test]
    fn portuguese_param_used_when_language_enabled() {
        let lang = LangParams {
            enabled: true,
            portuguese: true,
            ..LangParams::default()
        };
        let d = detector_with(lang);
        // `carregar` (PT "load") and `mostrar` (PT "show") share no substring with
        // any English token, so they are clean Portuguese-gated cases.
        assert!(d.detect("carregar=https://evil.example").is_some());
        assert!(d.detect("mostrar=//evil.example").is_some());
        assert!(d
            .detect("arquivo=php://filter/convert.base64-encode/resource=x.php")
            .is_some());
    }

    #[test]
    fn portuguese_param_ignored_when_language_disabled() {
        // `carregar` is Portuguese-only (no English substring overlap); with
        // languages off it must be ignored even with a redirect value.
        assert!(detector().detect("carregar=//evil.example").is_none());
    }

    #[test]
    fn value_in_body_is_detected() {
        let d = detector();
        assert!(d.detect("redirect=javascript:alert(1)").is_some());
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SstiRule {
    // ── Jinja2 / Twig / Nunjucks / Pebble / Handlebars ─────────────────────
    DoubleCurly,        // {{ … }}
    DoubleCurlyEquals,  // {{= … }}  (Handlebars raw / Angular)
    // ── Velocity / Spring EL / Freemarker (dollar variants) ─────────────────
    DollarCurly,        // ${ … }
    DollarBangCurly,    // $!{ … }   Velocity null-safe output reference
    // ── Ruby / Kotlin / Scala string interpolation ───────────────────────────
    HashCurly,          // #{ … }
    // ── Ruby ERB / ASP classic ───────────────────────────────────────────────
    ErbOutput,          // <%= … %>
    ErbBlock,           // <% … %>
    // ── Jinja2 / Django / Twig block tags ───────────────────────────────────
    PercentBlock,       // {% … %}
    // ── Apache Freemarker (angle-bracket syntax) ─────────────────────────────
    FreeMarkerDirective, // <# … >
    // ── Apache Freemarker (bracket syntax) ───────────────────────────────────
    FreemarkerBracket,  // [# … ]  directive bracket form
    FreemarkerInline,   // [= … ]  inline expression shorthand
    // ── Apache Velocity control directives (non-curly form) ──────────────────
    VelocitySet,        // #set( … )
    VelocityForeach,    // #foreach( … )
    VelocityIf,         // #if( … )
    VelocityWhile,      // #while( … )
    // ── Thymeleaf ────────────────────────────────────────────────────────────
    StarCurly,          // *{ … }   Thymeleaf selection variable
    AtCurly,            // @{ … }   Thymeleaf URL
    AtParen,            // @( … )   Razor / Blazor
    TildeCurly,         // ~{ … }   Thymeleaf fragment expression
    // ── Slim / other ────────────────────────────────────────────────────────
    CurlyEquals,        // {= … }
    LineEquals,         // \n= …    Slim line expression
    DoubleSquare,       // [[ … ]]  Tornado / Vue
}

impl SstiRule {
    pub fn id(self) -> usize {
        match self {
            Self::DoubleCurly        => 1,
            Self::DollarCurly        => 2,
            Self::HashCurly          => 3,
            Self::ErbOutput          => 4,
            Self::ErbBlock           => 5,
            Self::DoubleCurlyEquals  => 6,
            Self::CurlyEquals        => 7,
            Self::LineEquals         => 8,
            Self::StarCurly          => 9,
            Self::AtCurly            => 10,
            Self::AtParen            => 11,
            Self::PercentBlock       => 12,
            Self::FreeMarkerDirective => 13,
            Self::VelocitySet        => 14,
            Self::DoubleSquare       => 15,
            Self::DollarBangCurly    => 16,
            Self::FreemarkerBracket  => 17,
            Self::FreemarkerInline   => 18,
            Self::VelocityForeach    => 19,
            Self::VelocityIf         => 20,
            Self::VelocityWhile      => 21,
            Self::TildeCurly         => 22,
        }
    }

    pub fn pattern(self) -> &'static str {
        match self {
            Self::DoubleCurly        => "{{ ... }}",
            Self::DollarCurly        => "${ ... }",
            Self::DollarBangCurly    => "$!{ ... }",
            Self::HashCurly          => "#{ ... }",
            Self::ErbOutput          => "<%= ... %>",
            Self::ErbBlock           => "<% ... %>",
            Self::DoubleCurlyEquals  => "{{= ... }}",
            Self::CurlyEquals        => "{= ... }",
            Self::LineEquals         => "\\n= ... \\n",
            Self::StarCurly          => "*{ ... }",
            Self::AtCurly            => "@{ ... }",
            Self::AtParen            => "@( ... )",
            Self::TildeCurly         => "~{ ... }",
            Self::PercentBlock       => "{% ... %}",
            Self::FreeMarkerDirective => "<# ... >",
            Self::FreemarkerBracket  => "[# ... ]",
            Self::FreemarkerInline   => "[= ... ]",
            Self::VelocitySet        => "#set( ... )",
            Self::VelocityForeach    => "#foreach( ... )",
            Self::VelocityIf         => "#if( ... )",
            Self::VelocityWhile      => "#while( ... )",
            Self::DoubleSquare       => "[[ ... ]]",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SstiDfaBuilder;
#[derive(Debug, Clone)]
pub struct SstiDfa;

impl SstiDfaBuilder {
    pub fn new() -> Self {
        Self
    }
    pub fn build(self) -> SstiDfa {
        SstiDfa
    }
}

impl SstiDfa {
    pub fn detect(&self, input: &str) -> Option<SstiRule> {
        // Check longer/more-specific patterns first to avoid prefix aliasing.

        // Handlebars raw / Angular {{= … }}
        if find_bounded(input, "{{=", "}}", 256) {
            return Some(SstiRule::DoubleCurlyEquals);
        }
        // Generic Jinja2/Twig/Nunjucks {{ … }}
        if find_bounded(input, "{{", "}}", 256) {
            return Some(SstiRule::DoubleCurly);
        }

        // Velocity null-safe $!{ … } — must test before ${ to avoid miss
        if find_bounded(input, "$!{", "}", 256) {
            return Some(SstiRule::DollarBangCurly);
        }
        // Velocity / Spring EL / Freemarker ${ … }
        if find_bounded(input, "${", "}", 256) {
            return Some(SstiRule::DollarCurly);
        }

        // Ruby / Kotlin #{ … }
        if find_bounded(input, "#{", "}", 256) {
            return Some(SstiRule::HashCurly);
        }

        // Ruby ERB / JSP-EL
        if find_bounded(input, "<%=", "%>", 256) {
            return Some(SstiRule::ErbOutput);
        }
        if find_bounded(input, "<%", "%>", 256) {
            return Some(SstiRule::ErbBlock);
        }

        // Jinja2 / Django block tags {% … %}
        if find_bounded(input, "{%", "%}", 512) {
            return Some(SstiRule::PercentBlock);
        }

        // Freemarker angle-bracket <# … > and </#…>
        if find_bounded(input, "<#", ">", 512) {
            return Some(SstiRule::FreeMarkerDirective);
        }

        // Freemarker bracket-directive syntax [#letter…] or [/#…]
        if find_bracket_directive(input) {
            return Some(SstiRule::FreemarkerBracket);
        }
        // Freemarker bracket inline [= … ]
        if find_bounded(input, "[=", "]", 256) {
            return Some(SstiRule::FreemarkerInline);
        }

        // Velocity control directives (non-curly form, with optional whitespace before `(`)
        if find_velocity_directive(input, "#set(") {
            return Some(SstiRule::VelocitySet);
        }
        if find_velocity_directive(input, "#foreach(") {
            return Some(SstiRule::VelocityForeach);
        }
        if find_velocity_directive(input, "#if(") {
            return Some(SstiRule::VelocityIf);
        }
        if find_velocity_directive(input, "#while(") {
            return Some(SstiRule::VelocityWhile);
        }

        // Thymeleaf
        if find_bounded(input, "~{", "}", 256) {
            return Some(SstiRule::TildeCurly);
        }
        if find_bounded(input, "*{", "}", 256) {
            return Some(SstiRule::StarCurly);
        }
        if find_bounded(input, "@{", "}", 256) {
            return Some(SstiRule::AtCurly);
        }
        if find_bounded(input, "@(", ")", 256) {
            return Some(SstiRule::AtParen);
        }

        // Slim
        if find_bounded(input, "{=", "}", 256) {
            return Some(SstiRule::CurlyEquals);
        }
        if detect_line_equals(input) {
            return Some(SstiRule::LineEquals);
        }

        // Tornado / Vue [[ … ]] — after FreemarkerInline to avoid shadowing
        if find_bounded(input, "[[", "]]", 512) {
            return Some(SstiRule::DoubleSquare);
        }

        None
    }
}

fn find_bounded(input: &str, open: &str, close: &str, max_len: usize) -> bool {
    let bytes = input.as_bytes();
    let open_b = open.as_bytes();
    let close_b = close.as_bytes();
    let mut i = 0;
    while i + open_b.len() <= bytes.len() {
        if &bytes[i..i + open_b.len()] == open_b {
            let end_limit = usize::min(bytes.len(), i + open_b.len() + max_len + close_b.len());
            let mut j = i + open_b.len();
            while j + close_b.len() <= end_limit {
                if &bytes[j..j + close_b.len()] == close_b {
                    return true;
                }
                j += 1;
            }
        }
        i += 1;
    }
    false
}

/// Detect Freemarker bracket-directive syntax: `[#letter…]` or `[/#letter…]`.
/// The input is already ASCII-lowercased by the engine before reaching the DFA.
fn find_bracket_directive(input: &str) -> bool {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'[' {
            let next = bytes[i + 1];
            if next == b'#' && i + 2 < bytes.len() && bytes[i + 2].is_ascii_alphabetic() {
                return true;
            }
            if next == b'/'
                && i + 3 < bytes.len()
                && bytes[i + 2] == b'#'
                && bytes[i + 3].is_ascii_alphabetic()
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Detect Velocity non-curly directives with optional whitespace before `(`.
fn find_velocity_directive(input: &str, directive: &str) -> bool {
    let bytes = input.as_bytes();
    let dir_b = directive.as_bytes();
    if bytes.windows(dir_b.len()).any(|w| w.eq_ignore_ascii_case(dir_b)) {
        return true;
    }
    // Also accept `#name (` with a space/tab before `(`
    let name = &dir_b[..dir_b.len() - 1];
    let mut i = 0;
    while i + name.len() < bytes.len() {
        if bytes[i..i + name.len()].eq_ignore_ascii_case(name) {
            let mut j = i + name.len();
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn detect_line_equals(input: &str) -> bool {
    input.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with('=') && trimmed.len() > 1 && trimmed.len() <= 257
    })
}

#[cfg(test)]
mod tests {
    use super::{SstiDfaBuilder, SstiRule};

    #[test]
    fn detects_common_ssti_families() {
        let dfa = SstiDfaBuilder::new().build();

        assert!(matches!(dfa.detect("{{7*7}}"), Some(SstiRule::DoubleCurly)));
        assert!(matches!(
            dfa.detect("{% debug %}"),
            Some(SstiRule::PercentBlock)
        ));
        assert!(matches!(
            dfa.detect("<#assign x=7>"),
            Some(SstiRule::FreeMarkerDirective)
        ));
        assert!(matches!(
            dfa.detect("#set($x = 7 * 7)"),
            Some(SstiRule::VelocitySet)
        ));
        assert!(matches!(
            dfa.detect("[[user.name]]"),
            Some(SstiRule::DoubleSquare)
        ));
    }

    #[test]
    fn detects_extended_ssti_patterns() {
        let dfa = SstiDfaBuilder::new().build();

        assert!(matches!(
            dfa.detect("$!{user.name}"),
            Some(SstiRule::DollarBangCurly)
        ));
        assert!(matches!(
            dfa.detect("[#list items as item][/#list]"),
            Some(SstiRule::FreemarkerBracket)
        ));
        assert!(matches!(
            dfa.detect("[= 7 * 7 ]"),
            Some(SstiRule::FreemarkerInline)
        ));
        assert!(matches!(
            dfa.detect("#foreach($item in $list)#end"),
            Some(SstiRule::VelocityForeach)
        ));
        assert!(matches!(
            dfa.detect("#if($user == 'admin')owned#end"),
            Some(SstiRule::VelocityIf)
        ));
        assert!(matches!(
            dfa.detect("~{fragments/nav :: menu}"),
            Some(SstiRule::TildeCurly)
        ));
    }

    #[test]
    fn dollarbankcurly_detected_before_dollarcurly() {
        let dfa = SstiDfaBuilder::new().build();
        assert!(matches!(
            dfa.detect("$!{7*7}"),
            Some(SstiRule::DollarBangCurly)
        ));
    }
}

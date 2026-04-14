#[derive(Debug, Clone, Copy)]
pub enum SstiRule {
    DoubleCurly,
    DollarCurly,
    HashCurly,
    ErbOutput,
    ErbBlock,
    DoubleCurlyEquals,
    CurlyEquals,
    LineEquals,
    StarCurly,
    AtCurly,
    AtParen,
}

impl SstiRule {
    pub fn id(self) -> usize {
        match self {
            Self::DoubleCurly => 1,
            Self::DollarCurly => 2,
            Self::HashCurly => 3,
            Self::ErbOutput => 4,
            Self::ErbBlock => 5,
            Self::DoubleCurlyEquals => 6,
            Self::CurlyEquals => 7,
            Self::LineEquals => 8,
            Self::StarCurly => 9,
            Self::AtCurly => 10,
            Self::AtParen => 11,
        }
    }
    pub fn pattern(self) -> &'static str {
        match self {
            Self::DoubleCurly => "{{ ... }}",
            Self::DollarCurly => "${ ... }",
            Self::HashCurly => "#{ ... }",
            Self::ErbOutput => "<%= ... %>",
            Self::ErbBlock => "<% ... %>",
            Self::DoubleCurlyEquals => "{{= ... }}",
            Self::CurlyEquals => "{= ... }",
            Self::LineEquals => "\\n= ... \\n",
            Self::StarCurly => "*{ ... }",
            Self::AtCurly => "@{ ... }",
            Self::AtParen => "@( ... )",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SstiDfaBuilder;
#[derive(Debug, Clone)]
pub struct SstiDfa;

impl SstiDfaBuilder {
    pub fn new() -> Self { Self }
    pub fn build(self) -> SstiDfa { SstiDfa }
}

impl SstiDfa {
    pub fn detect(&self, input: &str) -> Option<SstiRule> {
        if find_bounded(input, "{{=", "}}", 256) { return Some(SstiRule::DoubleCurlyEquals); }
        if find_bounded(input, "{{", "}}", 256) { return Some(SstiRule::DoubleCurly); }
        if find_bounded(input, "${", "}", 256) { return Some(SstiRule::DollarCurly); }
        if find_bounded(input, "#{", "}", 256) { return Some(SstiRule::HashCurly); }
        if find_bounded(input, "<%=", "%>", 256) { return Some(SstiRule::ErbOutput); }
        if find_bounded(input, "<%", "%>", 256) { return Some(SstiRule::ErbBlock); }
        if find_bounded(input, "{=", "}", 256) { return Some(SstiRule::CurlyEquals); }
        if detect_line_equals(input) { return Some(SstiRule::LineEquals); }
        if find_bounded(input, "*{", "}", 256) { return Some(SstiRule::StarCurly); }
        if find_bounded(input, "@{", "}", 256) { return Some(SstiRule::AtCurly); }
        if find_bounded(input, "@(", ")", 256) { return Some(SstiRule::AtParen); }
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

fn detect_line_equals(input: &str) -> bool {
    input.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with('=') && trimmed.len() > 1 && trimmed.len() <= 257
    })
}

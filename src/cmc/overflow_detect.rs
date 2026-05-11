#[derive(Debug, Clone)]
pub struct OverflowCmcBuilder {
    threshold: usize,
}
#[derive(Debug, Clone)]
pub struct OverflowCmc {
    threshold: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeArch {
    X86,
    X64,
    Arm,
}

impl ShellcodeArch {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "x86-32",
            Self::X64 => "x86-64",
            Self::Arm => "arm",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ShellcodeMatch {
    arch: ShellcodeArch,
    pattern: &'static str,
    score: usize,
}

impl ShellcodeMatch {
    pub fn arch(self) -> ShellcodeArch {
        self.arch
    }

    pub fn pattern(self) -> &'static str {
        self.pattern
    }

    pub fn score(self) -> usize {
        self.score
    }
}

impl Default for OverflowCmcBuilder {
    fn default() -> Self {
        Self { threshold: 10 }
    }
}

impl OverflowCmcBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use] 
    pub fn threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }
    #[must_use] 
    pub fn build(self) -> OverflowCmc {
        OverflowCmc {
            threshold: self.threshold,
        }
    }
}

impl OverflowCmc {
    #[allow(clippy::unused_self)]
    pub fn detect_shellcode(&self, input: &str) -> Option<ShellcodeMatch> {
        let bytes = collect_escaped_bytes(input);
        if bytes.is_empty() {
            return None;
        }

        if longest_run(&bytes, 0x90) >= 4 {
            return Some(ShellcodeMatch {
                arch: ShellcodeArch::X86,
                pattern: "x86/x64 nop sled",
                score: longest_run(&bytes, 0x90),
            });
        }

        if repeated_sequence_count(&bytes, &[0x00, 0x00, 0xa0, 0xe1]) >= 2 {
            return Some(ShellcodeMatch {
                arch: ShellcodeArch::Arm,
                pattern: "arm nop sled",
                score: repeated_sequence_count(&bytes, &[0x00, 0x00, 0xa0, 0xe1]),
            });
        }

        if repeated_sequence_count(&bytes, &[0xc0, 0x46]) >= 4 {
            return Some(ShellcodeMatch {
                arch: ShellcodeArch::Arm,
                pattern: "thumb nop sled",
                score: repeated_sequence_count(&bytes, &[0xc0, 0x46]),
            });
        }

        if let Some(matched) = detect_arch_patterns(&bytes, ShellcodeArch::X64, X64_PATTERNS) {
            return Some(matched);
        }
        if let Some(matched) = detect_arch_patterns(&bytes, ShellcodeArch::X86, X86_PATTERNS) {
            return Some(matched);
        }
        detect_arch_patterns(&bytes, ShellcodeArch::Arm, ARM_PATTERNS)
    }

    pub fn detect_run(&self, input: &str) -> Option<(char, usize)> {
        let mut chars = input.chars();
        let mut prev = chars.next()?;
        let mut count = 1usize;
        let mut digit_count = usize::from(prev.is_ascii_digit());
        let mut format_specifiers = 0usize;
        let mut traversal_segments = 0usize;

        for ch in chars {
            if ch == prev {
                count += 1;
                if count >= self.threshold {
                    return Some((ch, count));
                }
            } else {
                prev = ch;
                count = 1;
            }

            if ch.is_ascii_digit() {
                digit_count += 1;
                if digit_count >= self.threshold * 3 {
                    return Some(('0', digit_count));
                }
            } else {
                digit_count = 0;
            }
        }

        let bytes = input.as_bytes();
        let mut i = 0usize;
        while i + 1 < bytes.len() {
            if bytes[i] == b'%' && matches!(bytes[i + 1], b'n' | b'p' | b's' | b'x' | b'd' | b'u') {
                format_specifiers += 1;
                if format_specifiers >= self.threshold / 2 {
                    return Some(('%', format_specifiers));
                }
                i += 2;
                continue;
            }
            i += 1;
        }

        for segment in input.split('/') {
            if segment == ".." {
                traversal_segments += 1;
                if traversal_segments >= self.threshold / 2 {
                    return Some(('.', traversal_segments));
                }
            } else if !segment.is_empty() {
                traversal_segments = 0;
            }
        }

        None
    }
}

const X86_PATTERNS: &[(&[u8], &str, usize)] = &[
    (&[0xcd, 0x80], "linux int 0x80 syscall", 2),
    (
        &[0x31, 0xc0, 0x50, 0x68],
        "xor eax/push shellcode prologue",
        2,
    ),
    (
        &[0x31, 0xdb, 0x31, 0xc9, 0x31, 0xd2],
        "zero ebx/ecx/edx registers",
        2,
    ),
    (&[0x6a, 0x0b, 0x58, 0x99, 0x52], "execve syscall setup", 2),
    (&[0x31, 0xc0, 0xb0, 0x0b], "execve eax syscall number", 2),
    (
        &[0xeb, 0x1f, 0x5e, 0x89, 0x76],
        "jmp-call-pop decoder stub",
        2,
    ),
    (
        &[0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68],
        "embedded /bin/sh",
        1,
    ),
];

const X64_PATTERNS: &[(&[u8], &str, usize)] = &[
    (&[0x0f, 0x05], "linux syscall instruction", 2),
    (&[0x48, 0x31, 0xd2], "xor rdx,rdx", 1),
    (&[0x48, 0x31, 0xf6], "xor rsi,rsi", 1),
    (&[0x48, 0x31, 0xff], "xor rdi,rdi", 1),
    (&[0x48, 0xbb], "movabs rbx immediate", 1),
    (&[0x6a, 0x3b, 0x58, 0x0f, 0x05], "execve syscall setup", 3),
    (&[0x48, 0x89, 0xe7], "mov rdi,rsp", 1),
    (
        &[0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68],
        "embedded /bin/sh",
        1,
    ),
];

const ARM_PATTERNS: &[(&[u8], &str, usize)] = &[
    (
        &[0x01, 0x30, 0x8f, 0xe2],
        "arm adr/add pc shellcode prologue",
        2,
    ),
    (&[0x13, 0xff, 0x2f, 0xe1], "arm to thumb bx transition", 2),
    (&[0x0b, 0x27, 0x01, 0xdf], "thumb execve svc", 3),
    (
        &[0x78, 0x46, 0x0a, 0x30],
        "thumb pc-relative shellcode setup",
        2,
    ),
    (&[0x04, 0xe0, 0x2d, 0xe5], "arm push lr/stmdb sp", 1),
    (
        &[0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68],
        "embedded /bin/sh",
        1,
    ),
];

fn detect_arch_patterns(
    bytes: &[u8],
    arch: ShellcodeArch,
    patterns: &[(&[u8], &'static str, usize)],
) -> Option<ShellcodeMatch> {
    let mut score = 0usize;
    let mut first_pattern = None;

    for (needle, label, weight) in patterns {
        if contains_subsequence(bytes, needle) {
            score += *weight;
            first_pattern.get_or_insert(*label);
        }
    }

    (score >= 3).then(|| ShellcodeMatch {
        arch,
        pattern: first_pattern.unwrap_or("opcode cluster"),
        score,
    })
}

fn collect_escaped_bytes(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        if i + 3 < bytes.len()
            && bytes[i] == b'\\'
            && bytes[i + 1].eq_ignore_ascii_case(&b'x')
            && is_hex(bytes[i + 2])
            && is_hex(bytes[i + 3])
        {
            out.push(hex_byte(bytes[i + 2], bytes[i + 3]));
            i += 4;
            continue;
        }

        if i + 2 < bytes.len() && bytes[i] == b'%' && is_hex(bytes[i + 1]) && is_hex(bytes[i + 2]) {
            out.push(hex_byte(bytes[i + 1], bytes[i + 2]));
            i += 3;
            continue;
        }

        if i + 3 < bytes.len()
            && bytes[i] == b'0'
            && bytes[i + 1].eq_ignore_ascii_case(&b'x')
            && is_hex(bytes[i + 2])
            && is_hex(bytes[i + 3])
        {
            out.push(hex_byte(bytes[i + 2], bytes[i + 3]));
            i += 4;
            continue;
        }

        if i + 5 < bytes.len()
            && bytes[i] == b'\\'
            && bytes[i + 1].eq_ignore_ascii_case(&b'u')
            && bytes[i + 2] == b'0'
            && bytes[i + 3] == b'0'
            && is_hex(bytes[i + 4])
            && is_hex(bytes[i + 5])
        {
            out.push(hex_byte(bytes[i + 4], bytes[i + 5]));
            i += 6;
            continue;
        }

        i += 1;
    }

    out
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn hex_byte(high: u8, low: u8) -> u8 {
    (hex_nibble(high) << 4) | hex_nibble(low)
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn longest_run(bytes: &[u8], needle: u8) -> usize {
    let mut best = 0usize;
    let mut current = 0usize;

    for byte in bytes {
        if *byte == needle {
            current += 1;
            best = best.max(current);
        } else {
            current = 0;
        }
    }

    best
}

fn repeated_sequence_count(bytes: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }

    let mut best = 0usize;
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        let mut count = 0usize;
        while i + ((count + 1) * needle.len()) <= bytes.len()
            && &bytes[i + (count * needle.len())..i + ((count + 1) * needle.len())] == needle
        {
            count += 1;
        }
        best = best.max(count);
        i += 1;
    }
    best
}

fn contains_subsequence(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{OverflowCmcBuilder, ShellcodeArch};

    #[test]
    fn detects_structured_overflow_patterns() {
        let cmc = OverflowCmcBuilder::new().threshold(10).build();

        assert!(cmc.detect_run("AAAAAAAAAAAA").is_some());
        assert!(cmc.detect_run("%n%n%n%n%n").is_some());
        assert!(cmc.detect_run("123456789012345678901234567890").is_some());
        assert!(cmc.detect_run("../../../../../../etc/passwd").is_some());
    }

    #[test]
    fn detects_common_x86_shellcode_opcodes() {
        let cmc = OverflowCmcBuilder::new().threshold(10).build();

        let nop_sled = r"\x90\x90\x90\x90\x90\xcc";
        let execve = r"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

        let nop = cmc.detect_shellcode(nop_sled).expect("x86 nop sled");
        assert_eq!(nop.arch(), ShellcodeArch::X86);

        let shellcode = cmc.detect_shellcode(execve).expect("x86 execve shellcode");
        assert_eq!(shellcode.arch(), ShellcodeArch::X86);
    }

    #[test]
    fn detects_common_x64_shellcode_opcodes() {
        let cmc = OverflowCmcBuilder::new().threshold(10).build();

        let payload = r"\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x6a\x3b\x58\x0f\x05";
        let shellcode = cmc.detect_shellcode(payload).expect("x64 shellcode");

        assert_eq!(shellcode.arch(), ShellcodeArch::X64);
    }

    #[test]
    fn detects_common_arm_and_thumb_shellcode_opcodes() {
        let cmc = OverflowCmcBuilder::new().threshold(10).build();

        let arm = r"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0a\x30\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68";
        let thumb_nop = r"\xc0\x46\xc0\x46\xc0\x46\xc0\x46";

        let shellcode = cmc.detect_shellcode(arm).expect("arm shellcode");
        assert_eq!(shellcode.arch(), ShellcodeArch::Arm);

        let sled = cmc.detect_shellcode(thumb_nop).expect("thumb nop sled");
        assert_eq!(sled.arch(), ShellcodeArch::Arm);
    }

    #[test]
    fn parses_percent_and_0x_encoded_shellcode_bytes() {
        let cmc = OverflowCmcBuilder::new().threshold(10).build();

        assert!(cmc.detect_shellcode("%90%90%90%90%cc").is_some());
        assert!(cmc.detect_shellcode("0x6a0x3b0x580x0f0x05").is_some());
    }
}

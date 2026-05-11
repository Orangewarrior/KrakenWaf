#[derive(Debug, Clone)]
pub struct SqliCommentsCmcBuilder { threshold: usize }
#[derive(Debug, Clone)]
pub struct SqliCommentsCmc { threshold: usize }

impl Default for SqliCommentsCmcBuilder {
    fn default() -> Self { Self { threshold: 2 } }
}

impl SqliCommentsCmcBuilder {
    pub fn new() -> Self { Self::default() }
    pub fn threshold(mut self, threshold: usize) -> Self { self.threshold = threshold; self }
    pub fn build(self) -> SqliCommentsCmc { SqliCommentsCmc { threshold: self.threshold } }
}

impl SqliCommentsCmc {
    pub fn count_matches(&self, input: &str) -> usize {
        let bytes = input.as_bytes();
        let mut i = 0;
        let mut total = 0;
        while i + 3 < bytes.len() {
            if bytes[i] == b'/' && bytes[i + 1] == b'*' {
                i += 2;
                let mut saw_star = false;
                while i < bytes.len() {
                    match bytes[i] {
                        b'*' => { saw_star = true; i += 1; }
                        b'/' if saw_star => { total += 1; i += 1; break; }
                        _ => { saw_star = false; i += 1; }
                    }
                }
            } else {
                i += 1;
            }
        }
        total
    }
    pub fn matches(&self, input: &str) -> bool { self.count_matches(input) >= self.threshold }
}

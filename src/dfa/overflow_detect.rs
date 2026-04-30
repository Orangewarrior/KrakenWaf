#[derive(Debug, Clone)]
pub struct OverflowDfaBuilder { threshold: usize }
#[derive(Debug, Clone)]
pub struct OverflowDfa { threshold: usize }

impl Default for OverflowDfaBuilder {
    fn default() -> Self { Self { threshold: 10 } }
}

impl OverflowDfaBuilder {
    pub fn new() -> Self { Self::default() }
    pub fn threshold(mut self, threshold: usize) -> Self { self.threshold = threshold; self }
    pub fn build(self) -> OverflowDfa { OverflowDfa { threshold: self.threshold } }
}

impl OverflowDfa {
    pub fn detect_run(&self, input: &str) -> Option<(char, usize)> {
        let mut chars = input.chars();
        let mut prev = chars.next()?;
        let mut count = 1usize;
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
        }
        None
    }
}

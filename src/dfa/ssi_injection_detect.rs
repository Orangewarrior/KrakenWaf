#[derive(Debug, Clone)]
pub struct SsiInjectionDfaBuilder;
#[derive(Debug, Clone)]
pub struct SsiInjectionDfa;

impl SsiInjectionDfaBuilder {
    pub fn new() -> Self { Self }
    pub fn build(self) -> SsiInjectionDfa { SsiInjectionDfa }
}

impl SsiInjectionDfa {
    pub fn detect(&self, input: &str) -> Option<String> {
        let hay = input.to_lowercase();
        if !hay.contains("<!--#") || !hay.contains("-->") { return None; }
        for kw in ["include", "exec", "echo", "config", "fsize", "flastmod", "printenv", "set", "if", "elif", "else", "endif"] {
            let marker = format!("<!--#{kw}");
            if hay.contains(&marker) {
                return Some(marker);
            }
        }
        None
    }
}

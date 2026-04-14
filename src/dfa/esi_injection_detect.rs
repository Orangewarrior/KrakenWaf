#[derive(Debug, Clone)]
pub struct EsiInjectionDfaBuilder;
#[derive(Debug, Clone)]
pub struct EsiInjectionDfa;

impl EsiInjectionDfaBuilder {
    pub fn new() -> Self { Self }
    pub fn build(self) -> EsiInjectionDfa { EsiInjectionDfa }
}

impl EsiInjectionDfa {
    pub fn detect(&self, input: &str) -> Option<String> {
        let hay = input.to_lowercase();
        for pat in ["<esi:include", "<esi:inline", "<esi:debug", "<!--esi"] {
            if hay.contains(pat) {
                return Some(pat.to_string());
            }
        }
        None
    }
}

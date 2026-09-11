#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinDivertFilter {
    pub expression: String,
}

impl WinDivertFilter {
    pub fn new(expression: &str) -> Option<Self> {
        let expression = expression.trim();

        if expression.is_empty() {
            return None;
        }

        Some(Self {
            expression: expression.to_string(),
        })
    }

    pub fn expression(&self) -> &str {
        &self.expression
    }

    pub fn is_empty(&self) -> bool {
        self.expression.is_empty()
    }
}

impl Default for WinDivertFilter {
    fn default() -> Self {
        Self {
            expression: "true".to_string(),
        }
    }
}
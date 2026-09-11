#[derive(Debug, Clone)]
pub struct ProvenanceRecord {
    pub source: String,
    pub timestamp: u64,
    pub confidence: f32,
}

impl ProvenanceRecord {
    pub fn new(
        source: &str,
        timestamp: u64,
        confidence: f32,
    ) -> Self {
        Self {
            source: source.to_string(),
            timestamp,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }

    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }

    pub fn is_low_confidence(&self) -> bool {
        self.confidence < 0.5
    }
}
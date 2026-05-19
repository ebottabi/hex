#[derive(Debug, Clone)]
pub struct LoopState {
    pub active: bool,
    pub iteration: u32,
    pub max_iterations: Option<u32>,
}

impl LoopState {
    pub fn new(max_iterations: Option<u32>) -> Self {
        LoopState {
            active: true,
            iteration: 0,
            max_iterations,
        }
    }
}

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowAdmission {
    Existing,
    AtCapacity,
    Create,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOpenDecision {
    Existing,
    AtCapacity,
    RateLimited,
    Create,
}

pub struct FlowCreationBudget {
    tokens: f64,
    updated_at: Instant,
}

#[derive(Default)]
pub struct AuthorizationFreshness {
    last_success_at: Option<Instant>,
}

pub fn classify_flow_admission(
    flow_exists: bool,
    active_flow_count: usize,
    max_flows: usize,
) -> FlowAdmission {
    if flow_exists {
        FlowAdmission::Existing
    } else if active_flow_count >= max_flows {
        FlowAdmission::AtCapacity
    } else {
        FlowAdmission::Create
    }
}

impl FlowCreationBudget {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: FLOW_CREATION_BURST,
            updated_at: now,
        }
    }

    fn try_take_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated_at);
        self.tokens = (self.tokens + elapsed.as_secs_f64() * FLOW_CREATION_REFILL_PER_SECOND)
            .min(FLOW_CREATION_BURST);
        self.updated_at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

impl AuthorizationFreshness {
    pub fn requires_recheck(&self, now: Instant) -> bool {
        self.last_success_at.is_none_or(|last_success_at| {
            now.saturating_duration_since(last_success_at) >= FLOW_AUTHORIZATION_COALESCE_WINDOW
        })
    }

    pub fn record_success(&mut self, now: Instant) {
        self.last_success_at = Some(now);
    }
}

pub async fn decide_flow_open<F, Fut>(
    admission: FlowAdmission,
    budget: &mut FlowCreationBudget,
    freshness: &mut AuthorizationFreshness,
    now: Instant,
    validate: F,
) -> Result<FlowOpenDecision>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    match admission {
        FlowAdmission::Existing => return Ok(FlowOpenDecision::Existing),
        FlowAdmission::AtCapacity => return Ok(FlowOpenDecision::AtCapacity),
        FlowAdmission::Create => {}
    }
    if !budget.try_take_at(now) {
        return Ok(FlowOpenDecision::RateLimited);
    }
    if freshness.requires_recheck(now) {
        validate().await?;
        // 从查询开始时计时会缩短而不会延长缓存窗口；慢查询后宁可提前再验。
        freshness.record_success(now);
    }
    Ok(FlowOpenDecision::Create)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEntryRegistration {
    pub entry_id: String,
    pub version: String,
    pub advertised_address: String,
    pub received_at: i64,
}

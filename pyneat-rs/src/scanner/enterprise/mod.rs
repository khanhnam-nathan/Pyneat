//! Enterprise Security Rules
//!
//! Enterprise-grade compliance, DLP, audit, and multi-tenant rules.

pub mod gdpr_pii;
pub mod audit_trail;
pub mod oauth_sso;
pub mod rate_limit;
pub mod tenant_isolation;
pub mod data_exfil;
pub mod supply_chain_lock;
pub mod infrastructure_security;
pub mod scanner;

pub use gdpr_pii::gdpr_pii_rules;
pub use audit_trail::audit_trail_rules;
pub use oauth_sso::oauth_sso_rules;
pub use rate_limit::rate_limit_rules;
pub use tenant_isolation::tenant_isolation_rules;
pub use data_exfil::data_exfil_rules;
pub use supply_chain_lock::supply_chain_lock_rules;
pub use infrastructure_security::infrastructure_security_rules;
pub use scanner::EnterpriseScanner;

#[cfg(test)]
mod tests;

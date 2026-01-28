//! Screen implementations for the TUI
//!
//! Each screen module provides:
//! - A render function that draws the screen
//! - State management specific to that screen
//! - Input handling for screen-specific actions

pub mod overview;
pub mod accounts;
pub mod sessions;
pub mod mail;

pub use overview::{render_overview, OverviewData, MachineStatus, AlertSummary, RepoStatus};
pub use accounts::{render_accounts, AccountsData, AccountStatus, AccountSortField};
pub use sessions::{render_sessions, SessionsData, SessionInfo, SessionGroupBy};
pub use mail::{render_mail, MailData, ThreadSummary, MessageInfo, MailPane};

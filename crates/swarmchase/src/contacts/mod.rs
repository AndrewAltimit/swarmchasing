//! Contacts: discovery for affected operators, and the provider directory.
//!
//! For each affected endpoint, the first security.txt (RFC 9116) found on the
//! host or its parent domains, else the registrar's abuse contact from RDAP.
//! Every contact carries its source link, a confidence level and the date it
//! was found. These are reads of published contact files on the affected
//! organisation's own site and the registry, never of agent infrastructure.
//!
//! Providers' channels come from the committed directory
//! (`contacts/providers.toml`, [`Directory`]): `case contacts` adds a
//! provider's entries when a developer or host claim names it, and
//! `swarmchase contacts verify` re-reads each entry's source and drafts the
//! changes for the admin.
//!
//! [`parse`] reads security.txt files and RDAP records, [`lookup`] runs the
//! discovery for a case, [`directory`] seeds provider contacts, [`verify`]
//! re-checks the directory, and [`cli`] is `swarmchase contacts`.

pub mod cli;
pub mod directory;
pub mod lookup;
pub mod parse;
pub mod verify;

pub use cli::{ContactsCmd, run_contacts};
pub use directory::{DirContact, Directory, Provider, case_channel, seed_providers};
pub use lookup::{Lookup, find_contacts};
pub use parse::{domain_candidates, from_security_txt, rdap_abuse, registered_domain};
pub use verify::{Check, draft_update, verify_directory};

//! TCP-based probes, one submodule per scanning technique.
pub mod syn;

// Future sibling probes plug in the same way, e.g.:
// pub mod ack;
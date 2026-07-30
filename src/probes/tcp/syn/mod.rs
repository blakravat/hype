//! TCP SYN host discovery (IPv4 only): one shared raw socket, a
//! dedicated sender thread, and a dedicated receiver thread.
mod client;
mod job;
mod packet;
mod receiver;
mod route;
mod sender;

pub use client::{check, Client};
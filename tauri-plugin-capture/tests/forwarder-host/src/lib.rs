//! Linux harness for the same forwarding implementation used by Android.
//! Tests use a local datagram socket as a TUN, with actual TCP/UDP stack code.
#![allow(dead_code)]

#[path = "../../../src/models.rs"]
mod models;
pub use models::*;

#[path = "../../../src/forwarder.rs"]
mod forwarder;

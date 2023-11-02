#![no_std]

#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
//! Implementation of Stake-based Threshold Multisignatures

extern crate alloc;

extern crate blake2;
extern crate blst;
extern crate linked_list_allocator;
extern crate num_bigint;
extern crate num_rational;
extern crate num_traits;
extern crate rand_core;
extern crate serde;

mod eligibility_check;
mod error;
pub mod key_reg;
mod merkle_tree;
pub mod stm;

pub use crate::error::{
    AggregationError, CoreVerifierError, RegisterError, StmAggregateSignatureError,
    StmSignatureError,
};

#[cfg(feature = "benchmark-internals")]
pub mod multi_sig;

#[cfg(not(feature = "benchmark-internals"))]
mod multi_sig;

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

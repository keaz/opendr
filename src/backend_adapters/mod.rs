//! Backend adapters grouped by FSM domain.
//!
//! The public `backend_adapters` module remains stable while the implementation
//! is split by domain so search, write, and compare work can evolve without
//! colliding in one shared hotspot file.

mod compare;
mod search;
mod write;

pub use compare::{
    AllowAllCompareAccessControl, CompareBackendAdapter, ProductionAttributeComparator,
    ProductionCompareMetrics,
};
pub use search::SearchBackendAdapter;
pub use write::{
    AllowAllWriteAciChecker, PassthroughSchemaValidator, ProductionWriteMetrics,
    WriteBackendAdapter,
};

use crate::trace::types::SerializableTraceEvent;
use bitcoin::OutPoint;

#[derive(Clone, Debug, Default)]
pub struct BlockTraceItem {
    pub outpoint: OutPoint,
    pub trace: Vec<SerializableTraceEvent>,
}

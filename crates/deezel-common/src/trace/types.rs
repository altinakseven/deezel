use serde::{Deserialize, Serialize};
use alkanes_support::trace::{self as alkanes_trace};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SerializableTrace {
    pub events: Vec<SerializableTraceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SerializableTraceEvent {
    EnterDelegatecall(SerializableTraceContext),
    EnterStaticcall(SerializableTraceContext),
    EnterCall(SerializableTraceContext),
    RevertContext(SerializableTraceResponse),
    ReturnContext(SerializableTraceResponse),
    CreateAlkane(SerializableAlkaneId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableTraceContext {
    pub inner: SerializableContext,
    pub target: SerializableAlkaneId,
    pub fuel: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableContext {
    pub myself: SerializableAlkaneId,
    pub caller: SerializableAlkaneId,
    pub vout: u32,
    pub incoming_alkanes: Vec<SerializableAlkaneTransfer>,
    pub inputs: Vec<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableAlkaneId {
    pub block: u128,
    pub tx: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableAlkaneTransfer {
    pub id: SerializableAlkaneId,
    pub value: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableTraceResponse {
    pub inner: SerializableExtendedCallResponse,
    pub fuel_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableExtendedCallResponse {
    pub storage: Vec<(Vec<u8>, Vec<u8>)>,
    pub data: Vec<u8>,
    pub alkanes: Vec<SerializableAlkaneTransfer>,
}

impl From<alkanes_trace::Trace> for SerializableTrace {
    fn from(trace: alkanes_trace::Trace) -> Self {
        let events = trace.0.lock().unwrap().clone().into_iter().map(|e| e.into()).collect();
        Self { events }
    }
}

impl From<alkanes_trace::TraceEvent> for SerializableTraceEvent {
    fn from(event: alkanes_trace::TraceEvent) -> Self {
        match event {
            alkanes_trace::TraceEvent::EnterDelegatecall(ctx) => SerializableTraceEvent::EnterDelegatecall(ctx.into()),
            alkanes_trace::TraceEvent::EnterStaticcall(ctx) => SerializableTraceEvent::EnterStaticcall(ctx.into()),
            alkanes_trace::TraceEvent::EnterCall(ctx) => SerializableTraceEvent::EnterCall(ctx.into()),
            alkanes_trace::TraceEvent::RevertContext(resp) => SerializableTraceEvent::RevertContext(resp.into()),
            alkanes_trace::TraceEvent::ReturnContext(resp) => SerializableTraceEvent::ReturnContext(resp.into()),
            alkanes_trace::TraceEvent::CreateAlkane(id) => SerializableTraceEvent::CreateAlkane(id.into()),
        }
    }
}

impl From<alkanes_trace::TraceContext> for SerializableTraceContext {
    fn from(ctx: alkanes_trace::TraceContext) -> Self {
        Self {
            inner: ctx.inner.into(),
            target: ctx.target.into(),
            fuel: ctx.fuel,
        }
    }
}

impl From<alkanes_support::context::Context> for SerializableContext {
    fn from(ctx: alkanes_support::context::Context) -> Self {
        Self {
            myself: ctx.myself.into(),
            caller: ctx.caller.into(),
            vout: ctx.vout,
            incoming_alkanes: ctx.incoming_alkanes.0.into_iter().map(|t| t.into()).collect(),
            inputs: ctx.inputs,
        }
    }
}

impl From<alkanes_support::id::AlkaneId> for SerializableAlkaneId {
    fn from(id: alkanes_support::id::AlkaneId) -> Self {
        Self {
            block: id.block,
            tx: id.tx,
        }
    }
}

impl From<alkanes_support::parcel::AlkaneTransfer> for SerializableAlkaneTransfer {
    fn from(transfer: alkanes_support::parcel::AlkaneTransfer) -> Self {
        Self {
            id: transfer.id.into(),
            value: transfer.value,
        }
    }
}

impl From<alkanes_trace::TraceResponse> for SerializableTraceResponse {
    fn from(resp: alkanes_trace::TraceResponse) -> Self {
        Self {
            inner: resp.inner.into(),
            fuel_used: resp.fuel_used,
        }
    }
}

impl From<alkanes_support::response::ExtendedCallResponse> for SerializableExtendedCallResponse {
    fn from(resp: alkanes_support::response::ExtendedCallResponse) -> Self {
        Self {
            storage: resp.storage.0.into_iter().collect(),
            data: resp.data,
            alkanes: resp.alkanes.0.into_iter().map(|t| t.into()).collect(),
        }
    }
}

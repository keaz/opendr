//! FSM-based request handlers for LDAP operations
//!
//! This module provides request handlers that process LDAP operations through FSMs,
//! managing FSM state transitions, event handling, and response generation.

use async_trait::async_trait;
use log::{debug, error, info, warn};
use tokio::net::TcpStream;

use crate::backend::DirectoryBackend;
use crate::fsm::{StateMachine, WriteEvent, WriteOperation, WriteResultCode, CompareParams};
use crate::server::{ServerError, send_search_response, send_modify_response, send_add_response, send_delete_response, send_compare_response, send_extended_response};
use crate::server_fsm::{ConnectionFsmSet, OperationFsmInstance};
use crate::write_fsm::{WriteFsmImpl, WriteEntry, Modification};
use crate::compare_fsm::CompareFsmImpl;
use crate::extended_op_fsm::ExtendedOpFsmImpl;

use ldap_parser::ldap::{
    LdapMessage, ProtocolOp, SearchRequest, ModifyRequest, AddRequest, LdapDN,
    CompareRequest, ExtendedRequest, ModDnRequest,
};
use rasn_ldap::ResultCode;

/// Result type for FSM handlers
pub type FsmHandlerResult = Result<(), ServerError>;

/// Trait for FSM-based operation handlers
#[async_trait]
pub trait FsmOperationHandler: Send + Sync {
    /// Handle the operation through FSMs
    async fn handle_with_fsm(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message: &LdapMessage,
    ) -> FsmHandlerResult;
    
    /// Check if FSM routing is enabled for this operation
    fn is_fsm_enabled(&self, fsm_set: &ConnectionFsmSet) -> bool;
    
    /// Get the operation name for logging
    fn operation_name(&self) -> &'static str;
}

/// Search operation FSM handler
pub struct SearchFsmHandler;

impl SearchFsmHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FsmOperationHandler for SearchFsmHandler {
    async fn handle_with_fsm(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message: &LdapMessage,
    ) -> FsmHandlerResult {
        let message_id = message.message_id.0;
        
        // Extract search request
        let search_request = match &message.protocol_op {
            ProtocolOp::SearchRequest(req) => req,
            _ => return Err(ServerError::Protocol("Expected SearchRequest".to_string())),
        };
        
        debug!("Processing search request through FSM for message ID {}", message_id);
        
        // For now, since SearchFsm is not fully implemented, we'll return a placeholder response
        // TODO: Implement full SearchFsm integration when SearchFsm is complete
        
        // Create placeholder FSM instance
        if let Err(e) = fsm_set.create_search_fsm(message_id) {
            error!("Failed to create SearchFsm for message {}: {}", message_id, e);
            return Err(ServerError::Internal(format!("FSM creation failed: {}", e)));
        }
        
        // Send placeholder response for now
        send_search_response(
            socket,
            message_id,
            ResultCode::Success,
            "Search through FSM - placeholder implementation",
            vec![], // Empty search results for now
        ).await?;
        
        // Clean up FSM
        fsm_set.remove_operation_fsm(message_id);
        
        info!("Search request processed through FSM for message ID {}", message_id);
        Ok(())
    }
    
    fn is_fsm_enabled(&self, fsm_set: &ConnectionFsmSet) -> bool {
        fsm_set.is_fsm_enabled("search")
    }
    
    fn operation_name(&self) -> &'static str {
        "search"
    }
}

/// Write operations FSM handler (handles Add, Modify, ModifyDN, Delete)
pub struct WriteFsmHandler;

impl WriteFsmHandler {
    pub fn new() -> Self {
        Self
    }
    
    /// Handle Add request through WriteFsm
    async fn handle_add_request(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message_id: u32,
        add_request: &AddRequest<'_>,
    ) -> FsmHandlerResult {
        debug!("Processing add request through WriteFsm for message ID {}", message_id);
        
        // Create WriteFsm instance
        if let Err(e) = fsm_set.create_write_fsm(message_id) {
            error!("Failed to create WriteFsm for message {}: {}", message_id, e);
            return Err(ServerError::Internal(format!("FSM creation failed: {}", e)));
        }
        
        // Convert AddRequest to WriteEntry
        let dn = add_request.entry.0.to_string();
        let mut write_entry = WriteEntry::new(dn.clone());
        
        // Process attributes from the add request
        for attribute in &add_request.attributes {
            let attr_name = attribute.attr_type.0.to_string();
            let attr_values: Vec<String> = attribute.attr_vals.iter()
                .map(|v| String::from_utf8_lossy(&v.0).to_string())
                .collect();
            
            if attr_name.eq_ignore_ascii_case("objectClass") {
                write_entry.object_classes.extend(attr_values);
            } else {
                write_entry.add_attribute(attr_name, attr_values);
            }
        }
        
        // Create WriteOperation - convert to LDIF format for now
        let mut ldif_data = format!("dn: {}\n", dn);
        for class in &write_entry.object_classes {
            ldif_data.push_str(&format!("objectClass: {}\n", class));
        }
        for (attr, values) in &write_entry.attributes {
            for value in values {
                ldif_data.push_str(&format!("{}: {}\n", attr, value));
            }
        }
        
        let write_op = WriteOperation::Add {
            dn: dn.clone(),
            entry: ldif_data.into_bytes(),
        };
        
        // Drive FSM through state transitions
        let result = self.process_write_operation(fsm_set, message_id, write_op).await;
        
        // Send response
        match result {
            Ok(_) => {
                send_add_response(socket, message_id, ResultCode::Success, "Entry added successfully").await?;
                info!("Add request processed successfully through WriteFsm for message ID {}", message_id);
            }
            Err(e) => {
                error!("Add request failed in WriteFsm for message ID {}: {:?}", message_id, e);
                send_add_response(socket, message_id, ResultCode::OperationsError, &e.to_string()).await?;
            }
        }
        
        // Clean up FSM
        fsm_set.remove_operation_fsm(message_id);
        Ok(())
    }
    
    /// Handle Modify request through WriteFsm
    async fn handle_modify_request(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message_id: u32,
        modify_request: &ModifyRequest<'_>,
    ) -> FsmHandlerResult {
        debug!("Processing modify request through WriteFsm for message ID {}", message_id);
        
        // Create WriteFsm instance
        if let Err(e) = fsm_set.create_write_fsm(message_id) {
            error!("Failed to create WriteFsm for message {}: {}", message_id, e);
            return Err(ServerError::Internal(format!("FSM creation failed: {}", e)));
        }
        
        let dn = modify_request.object.0.to_string();
        
        // Convert modifications
        let mut modifications = Vec::new();
        for change in &modify_request.changes {
            let attr_name = change.modification.attr_type.0.to_string();
            let attr_values: Vec<String> = change.modification.attr_vals.iter()
                .map(|v| String::from_utf8_lossy(&v.0).to_string())
                .collect();
            
            let modification = match change.operation.0 {
                0 => Modification::Add { name: attr_name, values: attr_values },
                1 => Modification::Delete { name: attr_name, values: attr_values },
                2 => Modification::Replace { name: attr_name, values: attr_values },
                _ => {
                    error!("Unknown modify operation: {}", change.operation.0);
                    send_modify_response(socket, message_id, ResultCode::ProtocolError, "Unknown modify operation").await?;
                    fsm_set.remove_operation_fsm(message_id);
                    return Ok(());
                }
            };
            
            modifications.push(modification);
        }
        
        // Create WriteOperation - convert to LDIF format for now
        let mut ldif_data = String::new();
        for modification in &modifications {
            match modification {
                Modification::Add { name, values } => {
                    for value in values {
                        ldif_data.push_str(&format!("add: {}\n{}: {}\n-\n", name, name, value));
                    }
                },
                Modification::Delete { name, values } => {
                    for value in values {
                        ldif_data.push_str(&format!("delete: {}\n{}: {}\n-\n", name, name, value));
                    }
                },
                Modification::Replace { name, values } => {
                    ldif_data.push_str(&format!("replace: {}\n", name));
                    for value in values {
                        ldif_data.push_str(&format!("{}: {}\n", name, value));
                    }
                    ldif_data.push_str("-\n");
                },
            }
        }
        
        let write_op = WriteOperation::Modify {
            dn: dn.clone(),
            changes: ldif_data.into_bytes(),
        };
        
        // Drive FSM through state transitions
        let result = self.process_write_operation(fsm_set, message_id, write_op).await;
        
        // Send response
        match result {
            Ok(_) => {
                send_modify_response(socket, message_id, ResultCode::Success, "Entry modified successfully").await?;
                info!("Modify request processed successfully through WriteFsm for message ID {}", message_id);
            }
            Err(e) => {
                error!("Modify request failed in WriteFsm for message ID {}: {:?}", message_id, e);
                send_modify_response(socket, message_id, ResultCode::OperationsError, &e.to_string()).await?;
            }
        }
        
        // Clean up FSM
        fsm_set.remove_operation_fsm(message_id);
        Ok(())
    }
    
    /// Handle Delete request through WriteFsm
    async fn handle_delete_request(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message_id: u32,
        delete_request: &LdapDN<'_>,
    ) -> FsmHandlerResult {
        debug!("Processing delete request through WriteFsm for message ID {}", message_id);
        
        // Create WriteFsm instance
        if let Err(e) = fsm_set.create_write_fsm(message_id) {
            error!("Failed to create WriteFsm for message {}: {}", message_id, e);
            return Err(ServerError::Internal(format!("FSM creation failed: {}", e)));
        }
        
        let dn = delete_request.0.to_string();
        
        // Create WriteOperation
        let write_op = WriteOperation::Delete { dn: dn.clone() };
        
        // Drive FSM through state transitions
        let result = self.process_write_operation(fsm_set, message_id, write_op).await;
        
        // Send response
        match result {
            Ok(_) => {
                send_delete_response(socket, message_id, ResultCode::Success, "Entry deleted successfully").await?;
                info!("Delete request processed successfully through WriteFsm for message ID {}", message_id);
            }
            Err(e) => {
                error!("Delete request failed in WriteFsm for message ID {}: {:?}", message_id, e);
                send_delete_response(socket, message_id, ResultCode::OperationsError, &e.to_string()).await?;
            }
        }
        
        // Clean up FSM
        fsm_set.remove_operation_fsm(message_id);
        Ok(())
    }
    
    /// Handle ModifyDN request through WriteFsm
    async fn handle_modify_dn_request(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message_id: u32,
        modify_dn_request: &ModDnRequest<'_>,
    ) -> FsmHandlerResult {
        debug!("Processing modifyDN request through WriteFsm for message ID {}", message_id);
        
        // Create WriteFsm instance
        if let Err(e) = fsm_set.create_write_fsm(message_id) {
            error!("Failed to create WriteFsm for message {}: {}", message_id, e);
            return Err(ServerError::Internal(format!("FSM creation failed: {}", e)));
        }
        
        let dn = modify_dn_request.entry.0.to_string();
        let new_rdn = modify_dn_request.newrdn.0.to_string();
        let delete_old = modify_dn_request.deleteoldrdn;
        let new_superior = modify_dn_request.newsuperior.as_ref()
            .map(|s| s.0.to_string());
        
        // Create WriteOperation
        let write_op = WriteOperation::ModifyDn {
            dn: dn.clone(),
            new_rdn,
            delete_old,
            new_superior,
        };
        
        // Drive FSM through state transitions
        let result = self.process_write_operation(fsm_set, message_id, write_op).await;
        
        // Send response
        match result {
            Ok(_) => {
                send_modify_response(socket, message_id, ResultCode::Success, "Entry DN modified successfully").await?;
                info!("ModifyDN request processed successfully through WriteFsm for message ID {}", message_id);
            }
            Err(e) => {
                error!("ModifyDN request failed in WriteFsm for message ID {}: {:?}", message_id, e);
                send_modify_response(socket, message_id, ResultCode::OperationsError, &e.to_string()).await?;
            }
        }
        
        // Clean up FSM
        fsm_set.remove_operation_fsm(message_id);
        Ok(())
    }
    
    /// Process write operation through FSM state transitions
    async fn process_write_operation(
        &self,
        fsm_set: &mut ConnectionFsmSet,
        message_id: u32,
        write_op: WriteOperation,
    ) -> Result<WriteResultCode, Box<dyn std::error::Error + Send + Sync>> {
        // Get FSM instance
        let fsm = match fsm_set.get_operation_fsm_mut(message_id) {
            Some(OperationFsmInstance::Write(fsm)) => fsm,
            Some(_) => return Err("Wrong FSM type for write operation".into()),
            None => return Err("No FSM found for message".into()),
        };
        
        // Start the write operation
        let start_event = WriteEvent::StartWrite(write_op);
        fsm.handle_event(start_event).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        // Drive through validation states
        let validation_event = WriteEvent::ValidationComplete;
        fsm.handle_event(validation_event).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        let schema_event = WriteEvent::SchemaCheckComplete;
        fsm.handle_event(schema_event).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        let aci_event = WriteEvent::AciCheckComplete;
        fsm.handle_event(aci_event).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        // Start transaction
        let txn_event = WriteEvent::TransactionStarted;
        fsm.handle_event(txn_event).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        // Complete write
        let write_complete_event = WriteEvent::WriteComplete;
        fsm.handle_event(write_complete_event).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        // Commit transaction
        let commit_event = WriteEvent::CommitComplete;
        fsm.handle_event(commit_event).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        Ok(WriteResultCode::Success)
    }
}

#[async_trait]
impl FsmOperationHandler for WriteFsmHandler {
    async fn handle_with_fsm(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message: &LdapMessage,
    ) -> FsmHandlerResult {
        let message_id = message.message_id.0;
        
        match &message.protocol_op {
            ProtocolOp::AddRequest(req) => {
                self.handle_add_request(socket, fsm_set, message_id, req).await
            }
            ProtocolOp::ModifyRequest(req) => {
                self.handle_modify_request(socket, fsm_set, message_id, req).await
            }
            ProtocolOp::DelRequest(req) => {
                self.handle_delete_request(socket, fsm_set, message_id, req).await
            }
            ProtocolOp::ModDnRequest(req) => {
                self.handle_modify_dn_request(socket, fsm_set, message_id, req).await
            }
            _ => Err(ServerError::Protocol("Expected write operation request".to_string())),
        }
    }
    
    fn is_fsm_enabled(&self, fsm_set: &ConnectionFsmSet) -> bool {
        fsm_set.is_fsm_enabled("add") || 
        fsm_set.is_fsm_enabled("modify") ||
        fsm_set.is_fsm_enabled("modifyDn") ||
        fsm_set.is_fsm_enabled("delete")
    }
    
    fn operation_name(&self) -> &'static str {
        "write"
    }
}

/// Compare operation FSM handler
pub struct CompareFsmHandler;

impl CompareFsmHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FsmOperationHandler for CompareFsmHandler {
    async fn handle_with_fsm(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message: &LdapMessage,
    ) -> FsmHandlerResult {
        let message_id = message.message_id.0;
        
        // Extract compare request
        let compare_request = match &message.protocol_op {
            ProtocolOp::CompareRequest(req) => req,
            _ => return Err(ServerError::Protocol("Expected CompareRequest".to_string())),
        };
        
        debug!("Processing compare request through CompareFsm for message ID {}", message_id);
        
        // Create CompareFsm instance
        if let Err(e) = fsm_set.create_compare_fsm(message_id) {
            error!("Failed to create CompareFsm for message {}: {}", message_id, e);
            return Err(ServerError::Internal(format!("FSM creation failed: {}", e)));
        }
        
        // Extract compare parameters
        let dn = compare_request.entry.0.to_string();
        let attribute_name = compare_request.ava.attribute_desc.0.to_string();
        let attribute_value = compare_request.ava.assertion_value.as_ref().to_vec();
        
        let compare_params = CompareParams {
            dn: dn.clone(),
            attribute: attribute_name.clone(),
            value: attribute_value.clone(),
        };
        
        // Get FSM instance and process the compare
        let result = match fsm_set.get_operation_fsm_mut(message_id) {
            Some(OperationFsmInstance::Compare(_fsm)) => {
                // TODO: Drive CompareFsm through its state transitions
                // For now, we'll implement a basic comparison result
                
                // In a real implementation, we would:
                // 1. Send StartCompare event to FSM
                // 2. Drive through validation and access control states  
                // 3. Perform the actual comparison
                // 4. Return the result
                
                // Placeholder implementation
                Ok(true) // Assume comparison is true for now
            }
            Some(_) => Err("Wrong FSM type for compare operation"),
            None => Err("No FSM found for message"),
        };
        
        // Send response
        match result {
            Ok(comparison_result) => {
                let result_code = if comparison_result { ResultCode::CompareTrue } else { ResultCode::CompareFalse };
                send_compare_response(socket, message_id, result_code, "Compare operation completed").await?;
                info!("Compare request processed successfully through CompareFsm for message ID {}", message_id);
            }
            Err(e) => {
                error!("Compare request failed in CompareFsm for message ID {}: {}", message_id, e);
                send_compare_response(socket, message_id, ResultCode::OperationsError, e).await?;
            }
        }
        
        // Clean up FSM
        fsm_set.remove_operation_fsm(message_id);
        Ok(())
    }
    
    fn is_fsm_enabled(&self, fsm_set: &ConnectionFsmSet) -> bool {
        fsm_set.is_fsm_enabled("compare")
    }
    
    fn operation_name(&self) -> &'static str {
        "compare"
    }
}

/// Extended operation FSM handler
pub struct ExtendedOpFsmHandler;

impl ExtendedOpFsmHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FsmOperationHandler for ExtendedOpFsmHandler {
    async fn handle_with_fsm(
        &self,
        socket: &mut TcpStream,
        fsm_set: &mut ConnectionFsmSet,
        message: &LdapMessage,
    ) -> FsmHandlerResult {
        let message_id = message.message_id.0;
        
        // Extract extended request
        let extended_request = match &message.protocol_op {
            ProtocolOp::ExtendedRequest(req) => req,
            _ => return Err(ServerError::Protocol("Expected ExtendedRequest".to_string())),
        };
        
        debug!("Processing extended request through ExtendedOpFsm for message ID {}", message_id);
        
        // Create ExtendedOpFsm instance
        if let Err(e) = fsm_set.create_extended_op_fsm(message_id) {
            error!("Failed to create ExtendedOpFsm for message {}: {}", message_id, e);
            return Err(ServerError::Internal(format!("FSM creation failed: {}", e)));
        }
        
        let oid = extended_request.request_name.0.to_string();
        let request_value = extended_request.request_value.as_ref()
            .map(|v| v.as_ref().to_vec());
        
        // Get FSM instance and process the extended operation
        let result = match fsm_set.get_operation_fsm_mut(message_id) {
            Some(OperationFsmInstance::ExtendedOp(_fsm)) => {
                // TODO: Drive ExtendedOpFsm through its state transitions
                // For now, we'll implement basic handling for WhoAmI
                
                match oid.as_str() {
                    "1.3.6.1.4.1.4203.1.11.3" => {
                        // WhoAmI operation - return current user DN
                        let response_value = if let Some(user_dn) = fsm_set.authenticated_dn() {
                            format!("dn:{}", user_dn).into_bytes()
                        } else {
                            b"anonymous".to_vec()
                        };
                        Ok(Some(response_value))
                    }
                    _ => Err(format!("Unsupported extended operation: {}", oid))
                }
            }
            Some(_) => Err("Wrong FSM type for extended operation".to_string()),
            None => Err("No FSM found for message".to_string()),
        };
        
        // Send response
        match result {
            Ok(response_value) => {
                send_extended_response(
                    socket, 
                    message_id, 
                    ResultCode::Success, 
                    "Extended operation completed", 
                    oid.as_str(),
                    response_value
                ).await?;
                info!("Extended request processed successfully through ExtendedOpFsm for message ID {}", message_id);
            }
            Err(e) => {
                error!("Extended request failed in ExtendedOpFsm for message ID {}: {}", message_id, e);
                send_extended_response(
                    socket, 
                    message_id, 
                    ResultCode::OperationsError, 
                    &e,
                    &oid,
                    None
                ).await?;
            }
        }
        
        // Clean up FSM
        fsm_set.remove_operation_fsm(message_id);
        Ok(())
    }
    
    fn is_fsm_enabled(&self, fsm_set: &ConnectionFsmSet) -> bool {
        fsm_set.is_fsm_enabled("extended")
    }
    
    fn operation_name(&self) -> &'static str {
        "extended"
    }
}

/// Factory for creating FSM operation handlers
pub struct FsmHandlerFactory {
    search_handler: SearchFsmHandler,
    write_handler: WriteFsmHandler,
    compare_handler: CompareFsmHandler,
    extended_op_handler: ExtendedOpFsmHandler,
}

impl FsmHandlerFactory {
    pub fn new() -> Self {
        Self {
            search_handler: SearchFsmHandler::new(),
            write_handler: WriteFsmHandler::new(),
            compare_handler: CompareFsmHandler::new(),
            extended_op_handler: ExtendedOpFsmHandler::new(),
        }
    }
    
    /// Get the appropriate handler for a given LDAP message
    pub fn get_handler(&self, message: &LdapMessage) -> Option<&dyn FsmOperationHandler> {
        match &message.protocol_op {
            ProtocolOp::SearchRequest(_) => Some(&self.search_handler),
            ProtocolOp::AddRequest(_) |
            ProtocolOp::ModifyRequest(_) |
            ProtocolOp::DelRequest(_) |
            ProtocolOp::ModDnRequest(_) => Some(&self.write_handler),
            ProtocolOp::CompareRequest(_) => Some(&self.compare_handler),
            ProtocolOp::ExtendedRequest(_) => Some(&self.extended_op_handler),
            _ => None, // Bind requests and other operations handled elsewhere
        }
    }
}

impl Default for FsmHandlerFactory {
    fn default() -> Self {
        Self::new()
    }
}
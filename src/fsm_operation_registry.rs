use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Information about an operation tracked by the FSM runtime.
#[derive(Debug, Clone)]
pub struct OperationInfo {
    /// LDAP message ID for this operation.
    pub message_id: i32,
    /// When this operation was created.
    pub created_at: Instant,
    /// Type of operation.
    pub operation_type: OperationType,
}

/// Types of LDAP operations tracked by the connection-scoped FSM runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Search,
    Add,
    Modify,
    ModifyDN,
    Delete,
    Compare,
    Extended,
}

/// Registry for connection-scoped FSM operations keyed by LDAP message ID.
#[derive(Debug)]
pub struct FsmOperationRegistry<T> {
    operations: HashMap<i32, T>,
    operation_info: HashMap<i32, OperationInfo>,
}

impl<T> FsmOperationRegistry<T> {
    /// Register a new operation and its metadata.
    pub fn add_operation(
        &mut self,
        message_id: i32,
        operation: T,
        operation_type: OperationType,
    ) -> Result<(), String> {
        if self.operations.contains_key(&message_id) {
            return Err(format!("Message ID {} already in use", message_id));
        }

        let info = OperationInfo {
            message_id,
            created_at: Instant::now(),
            operation_type,
        };

        self.operations.insert(message_id, operation);
        self.operation_info.insert(message_id, info);
        Ok(())
    }

    /// Get a mutable reference to a tracked operation.
    pub fn get_mut(&mut self, message_id: i32) -> Option<&mut T> {
        self.operations.get_mut(&message_id)
    }

    /// Get a reference to a tracked operation.
    pub fn get(&self, message_id: i32) -> Option<&T> {
        self.operations.get(&message_id)
    }

    /// Remove and return a tracked operation.
    pub fn remove(&mut self, message_id: i32) -> Option<T> {
        self.operation_info.remove(&message_id);
        self.operations.remove(&message_id)
    }

    /// Number of tracked operations.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// True when there are no tracked operations.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Snapshot of tracked operation metadata.
    pub fn active_operations(&self) -> Vec<OperationInfo> {
        self.operation_info.values().cloned().collect()
    }

    /// Remove operations matching a predicate.
    pub fn cleanup_where<F>(&mut self, mut predicate: F) -> usize
    where
        F: FnMut(&T) -> bool,
    {
        let terminal_ids: Vec<i32> = self
            .operations
            .iter()
            .filter(|(_, operation)| predicate(operation))
            .map(|(id, _)| *id)
            .collect();

        let count = terminal_ids.len();
        for id in terminal_ids {
            self.remove(id);
        }
        count
    }

    /// Remove operations older than the provided maximum age.
    pub fn cleanup_timed_out_operations(&mut self, max_operation_age: Duration) -> usize {
        let now = Instant::now();
        let timed_out_ids: Vec<i32> = self
            .operation_info
            .iter()
            .filter(|(_, info)| now.duration_since(info.created_at) > max_operation_age)
            .map(|(id, _)| *id)
            .collect();

        let count = timed_out_ids.len();
        for id in timed_out_ids {
            self.remove(id);
        }
        count
    }

    /// Return message IDs of operations approaching timeout.
    pub fn get_operations_approaching_timeout(
        &self,
        warning_threshold: Duration,
        max_operation_age: Duration,
    ) -> Vec<i32> {
        let now = Instant::now();
        let warning_age = max_operation_age.saturating_sub(warning_threshold);

        self.operation_info
            .iter()
            .filter(|(_, info)| {
                let age = now.duration_since(info.created_at);
                age > warning_age && age < max_operation_age
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

impl<T> Default for FsmOperationRegistry<T> {
    fn default() -> Self {
        Self {
            operations: HashMap::new(),
            operation_info: HashMap::new(),
        }
    }
}

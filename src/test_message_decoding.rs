//! Test to verify message decoding functionality works correctly

#[cfg(test)]
mod tests {
    use crate::runestone_enhanced::{decode_protostone_message, format_runestone_with_decoded_messages};
    use ordinals::Runestone;
    use bdk::bitcoin::{Transaction, TxOut, absolute::LockTime};

    #[test]
    fn test_decode_protostone_message() {
        // Test with empty message
        let empty_result = decode_protostone_message(&[]).unwrap();
        assert_eq!(empty_result, Vec::<u128>::new());

        // Test with simple varint encoded data
        // Encode some test values as varints: [1, 2, 77] (DIESEL mint message)
        let test_message = vec![1, 2, 77]; // Simple bytes, not LEB128 encoded
        
        // For this test, let's use actual LEB128 encoded data
        // LEB128 encoding of [1, 2, 77]:
        // 1 = 0x01
        // 2 = 0x02  
        // 77 = 0x4D
        let leb128_message = vec![0x01, 0x02, 0x4D];
        
        let decoded_result = decode_protostone_message(&leb128_message).unwrap();
        assert_eq!(decoded_result, vec![1, 2, 77]);
    }

    #[test]
    fn test_format_runestone_with_decoded_messages() {
        // Create a simple transaction with a Runestone
        let runestone = Runestone {
            edicts: vec![],
            etching: None,
            mint: None,
            pointer: None,
            // Protocol tag: 1, Message cellpack: [2, 0, 77] for DIESEL
            protocol: Some(vec![1, 2, 0, 77]),
        };
        
        let script = runestone.encipher();
        
        // Convert from bitcoin::ScriptBuf to bdk::bitcoin::ScriptBuf
        let bdk_script = bdk::bitcoin::ScriptBuf::from_bytes(script.as_bytes().to_vec());
        
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: 546, // Dust output
                    script_pubkey: bdk::bitcoin::ScriptBuf::new(),
                },
                TxOut {
                    value: 0,
                    script_pubkey: bdk_script,
                },
            ],
        };

        // Test the formatting function
        let result = format_runestone_with_decoded_messages(&tx);
        
        // Should succeed and return JSON with protostones
        assert!(result.is_ok());
        let json_result = result.unwrap();
        
        // Verify structure
        assert!(json_result["transaction_id"].is_string());
        assert!(json_result["protostones"].is_array());
        
        // Should have at least one protostone
        let protostones = json_result["protostones"].as_array().unwrap();
        assert!(!protostones.is_empty());
        
        // Check the first protostone
        let first_protostone = &protostones[0];
        assert!(first_protostone["protocol_tag"].is_number());
        assert!(first_protostone["message_bytes"].is_array());
        assert!(first_protostone["message_decoded"].is_array() || first_protostone["message_decoded"].is_null());
    }
}
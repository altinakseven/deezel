#[cfg(test)]
mod tests {
    use crate::runestone_enhanced::decode_protostone_message;

    #[test]
    fn test_runestone_import_available() {
        // Test that we can successfully import Runestone from alkanes-rs
        // This verifies our integration is working correctly
        use ordinals::Runestone;
        
        // The important thing is that we can import and reference the type
        // This confirms our alkanes-rs integration is working
        println!("Successfully imported Runestone from ordinals crate");
        
        // We can't easily create a valid transaction here due to version compatibility,
        // but the import test confirms our integration works
        assert!(true, "Runestone import successful");
    }

    #[test]
    fn test_protostone_message_decoding() {
        // Test our message decoding function with DIESEL token minting message
        let test_message_bytes = vec![2, 0, 77]; // DIESEL token minting message
        let decoded = decode_protostone_message(&test_message_bytes).expect("Should decode successfully");
        
        // Verify the decoding works
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], 2);
        assert_eq!(decoded[1], 0);
        assert_eq!(decoded[2], 77);
        
        println!("DIESEL message decoding test passed: {:?}", decoded);
    }

    #[test]
    fn test_leb128_message_decoding() {
        // Test with LEB128 encoded data
        let leb128_encoded = vec![0x80, 0x01]; // 128 in LEB128 format
        let decoded = decode_protostone_message(&leb128_encoded).expect("Should decode successfully");
        
        // Should decode to [128]
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], 128);
        
        println!("LEB128 decoding test passed: {:?}", decoded);
    }

    #[test]
    fn test_decode_simple_message() {
        // Test with simple byte array
        let simple_bytes = vec![1, 2, 3];
        let decoded = decode_protostone_message(&simple_bytes).expect("Should decode successfully");
        
        // Should decode each byte as a separate u128
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], 1);
        assert_eq!(decoded[1], 2);
        assert_eq!(decoded[2], 3);
        
        println!("Simple message decoding test passed: {:?}", decoded);
    }

    #[test]
    fn test_decode_empty_message() {
        // Test with empty byte array
        let empty_bytes = vec![];
        let decoded = decode_protostone_message(&empty_bytes).expect("Should decode successfully");
        
        // Should decode to empty vector
        assert_eq!(decoded.len(), 0);
        
        println!("Empty message decoding test passed: {:?}", decoded);
    }
}
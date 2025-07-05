//! Test protostone parsing to debug the protocol tag issue
//! 
//! This test helps us understand what's going wrong with the protostone parsing
//! by tracing through the exact same input as the script.

#[cfg(test)]
mod tests {
    use crate::alkanes::execute::parse_protostones;
    use alkanes_support::cellpack::Cellpack;
    use alkanes_support::id::AlkaneId;

    #[test]
    fn test_script_protostone_parsing() {
        println!("🔍 Testing script protostone parsing: '[3,797,101]:v0:v0'");
        
        // This is exactly what the script passes
        let input = "[3,797,101]:v0:v0";
        
        // Parse using the same function as main.rs
        match parse_protostones(input) {
            Ok(protostone_specs) => {
                println!("✅ Successfully parsed {} protostone specs", protostone_specs.len());
                
                for (i, spec) in protostone_specs.iter().enumerate() {
                    println!("🪨 Protostone spec {}:", i);
                    
                    if let Some(cellpack) = &spec.cellpack {
                        println!("  📦 Cellpack: target={}:{}, inputs={:?}", 
                                 cellpack.target.block, cellpack.target.tx, cellpack.inputs);
                        
                        // Test cellpack encoding
                        let encoded = cellpack.encipher();
                        println!("  🔧 Cellpack encoded: {} bytes = {}", encoded.len(), hex::encode(&encoded));
                    } else {
                        println!("  📦 No cellpack");
                    }
                    
                    println!("  🎯 Edicts: {}", spec.edicts.len());
                    for (j, edict) in spec.edicts.iter().enumerate() {
                        println!("    Edict {}: {}:{} amount={} target={:?}", 
                                 j, edict.alkane_id.block, edict.alkane_id.tx, edict.amount, edict.target);
                    }
                    
                    if let Some(bitcoin_transfer) = &spec.bitcoin_transfer {
                        println!("  💰 Bitcoin transfer: {} sats to {:?}", bitcoin_transfer.amount, bitcoin_transfer.target);
                    }
                }
            },
            Err(e) => {
                println!("❌ Failed to parse protostones: {}", e);
            }
        }
    }
    
    #[test]
    fn test_cellpack_creation() {
        println!("🔍 Testing cellpack creation from [3,797,101]");
        
        // Test the exact cellpack creation
        let values = vec![3u128, 797u128, 101u128];
        
        match Cellpack::try_from(values) {
            Ok(cellpack) => {
                println!("✅ Successfully created cellpack");
                println!("📦 Target: {}:{}", cellpack.target.block, cellpack.target.tx);
                println!("📥 Inputs: {:?}", cellpack.inputs);
                
                let encoded = cellpack.encipher();
                println!("🔧 Encoded: {} bytes = {}", encoded.len(), hex::encode(&encoded));
            },
            Err(e) => {
                println!("❌ Failed to create cellpack: {}", e);
            }
        }
    }
    
    #[test]
    fn test_manual_cellpack() {
        println!("🔍 Testing manual cellpack creation");
        
        let cellpack = Cellpack {
            target: AlkaneId { block: 3, tx: 797 },
            inputs: vec![101],
        };
        
        println!("📦 Manual cellpack: target={}:{}, inputs={:?}", 
                 cellpack.target.block, cellpack.target.tx, cellpack.inputs);
        
        let encoded = cellpack.encipher();
        println!("🔧 Encoded: {} bytes = {}", encoded.len(), hex::encode(&encoded));
        
        // This should match the test output: 039d0665
        assert_eq!(hex::encode(&encoded), "039d0665");
    }
}
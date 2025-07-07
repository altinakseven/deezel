#!/usr/bin/env python3
"""
Analyze the working transaction hex to understand the witness structure
"""

import sys
import struct

def read_varint(data, offset):
    """Read a variable-length integer from data at offset"""
    if offset >= len(data):
        return 0, offset
    
    first_byte = data[offset]
    if first_byte < 0xfd:
        return first_byte, offset + 1
    elif first_byte == 0xfd:
        return struct.unpack('<H', data[offset+1:offset+3])[0], offset + 3
    elif first_byte == 0xfe:
        return struct.unpack('<I', data[offset+1:offset+5])[0], offset + 5
    else:
        return struct.unpack('<Q', data[offset+1:offset+9])[0], offset + 9

def parse_witness(data, offset):
    """Parse witness data from transaction"""
    witness_items = []
    
    # Read number of witness items
    num_items, offset = read_varint(data, offset)
    print(f"  Number of witness items: {num_items}")
    
    for i in range(num_items):
        # Read item length
        item_len, offset = read_varint(data, offset)
        
        # Read item data
        if offset + item_len > len(data):
            print(f"    Item {i}: ERROR - not enough data")
            break
            
        item_data = data[offset:offset + item_len]
        offset += item_len
        
        witness_items.append(item_data)
        
        # Analyze the item
        print(f"    Item {i}: {item_len} bytes")
        if item_len == 0:
            print(f"      Empty item")
        elif item_len == 64:
            print(f"      64-byte item (likely Schnorr signature)")
            print(f"      First 16 bytes: {item_data[:16].hex()}")
            print(f"      Last 16 bytes: {item_data[-16:].hex()}")
        elif item_len == 33:
            print(f"      33-byte item (likely control block)")
            print(f"      First byte (leaf version + parity): 0x{item_data[0]:02x}")
            print(f"      Internal key: {item_data[1:33].hex()}")
        elif item_len > 1000:
            print(f"      Large item (likely script)")
            print(f"      First 32 bytes: {item_data[:32].hex()}")
            print(f"      Last 32 bytes: {item_data[-32:].hex()}")
            
            # Check for envelope markers
            if b'BIN' in item_data:
                print(f"      ✅ Contains BIN protocol marker")
            if b'application/wasm' in item_data:
                print(f"      ✅ Contains application/wasm content type")
                
            # Check script structure
            if len(item_data) > 10:
                if item_data[0] == 0x00:
                    print(f"      ✅ Starts with OP_PUSHBYTES_0")
                if item_data[1] == 0x63:
                    print(f"      ✅ Second byte is OP_IF (0x63)")
                if len(item_data) >= 2 and item_data[-2:] == b'\x68\x51':
                    print(f"      ✅ Ends with OP_ENDIF OP_PUSHNUM_1")
        else:
            print(f"      Medium item: {item_data.hex()}")
    
    return witness_items, offset

def analyze_transaction(hex_data):
    """Analyze transaction structure"""
    data = bytes.fromhex(hex_data.replace('\n', '').replace(' ', ''))
    
    print(f"Transaction size: {len(data)} bytes")
    print(f"Transaction hex length: {len(hex_data.replace('\n', '').replace(' ', ''))} characters")
    
    offset = 0
    
    # Version (4 bytes)
    version = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    print(f"Version: {version}")
    
    # Check for witness flag
    has_witness = False
    if data[offset] == 0x00 and data[offset+1] == 0x01:
        has_witness = True
        offset += 2
        print("✅ Transaction has witness data")
    
    # Input count
    input_count, offset = read_varint(data, offset)
    print(f"Input count: {input_count}")
    
    # Skip inputs for now (we're interested in witness)
    for i in range(input_count):
        # Previous output hash (32 bytes)
        offset += 32
        # Previous output index (4 bytes)
        offset += 4
        # Script length
        script_len, offset = read_varint(data, offset)
        # Script
        offset += script_len
        # Sequence (4 bytes)
        offset += 4
    
    # Output count
    output_count, offset = read_varint(data, offset)
    print(f"Output count: {output_count}")
    
    # Skip outputs
    for i in range(output_count):
        # Value (8 bytes)
        offset += 8
        # Script length
        script_len, offset = read_varint(data, offset)
        # Script
        offset += script_len
    
    # Witness data (if present)
    if has_witness:
        print("\n=== WITNESS DATA ANALYSIS ===")
        for i in range(input_count):
            print(f"\nInput {i} witness:")
            witness_items, offset = parse_witness(data, offset)
    
    # Locktime (4 bytes)
    if offset + 4 <= len(data):
        locktime = struct.unpack('<I', data[offset:offset+4])[0]
        print(f"\nLocktime: {locktime}")

def main():
    try:
        with open('./examples/working-tx.hex', 'r') as f:
            hex_data = f.read().strip()
        
        print("=== WORKING TRANSACTION ANALYSIS ===")
        analyze_transaction(hex_data)
        
    except FileNotFoundError:
        print("Error: ./examples/working-tx.hex not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Analyze deezel v2-v6 transactions and compare with working-tx.hex
"""

import sys
import struct
import os

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
    
    for i in range(num_items):
        # Read item length
        item_len, offset = read_varint(data, offset)
        
        # Read item data
        if offset + item_len > len(data):
            break
            
        item_data = data[offset:offset + item_len]
        offset += item_len
        witness_items.append(item_data)
    
    return witness_items, offset

def analyze_transaction(hex_data, name):
    """Analyze transaction structure and return summary"""
    data = bytes.fromhex(hex_data.replace('\n', '').replace(' ', ''))
    
    result = {
        'name': name,
        'size_bytes': len(data),
        'hex_length': len(hex_data.replace('\n', '').replace(' ', '')),
        'inputs': [],
        'outputs': [],
        'witness_data': []
    }
    
    offset = 0
    
    # Version (4 bytes)
    version = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    result['version'] = version
    
    # Check for witness flag
    has_witness = False
    if data[offset] == 0x00 and data[offset+1] == 0x01:
        has_witness = True
        offset += 2
        result['has_witness'] = True
    else:
        result['has_witness'] = False
    
    # Input count
    input_count, offset = read_varint(data, offset)
    result['input_count'] = input_count
    
    # Parse inputs
    for i in range(input_count):
        input_data = {}
        # Previous output hash (32 bytes)
        prev_hash = data[offset:offset+32]
        offset += 32
        input_data['prev_hash'] = prev_hash.hex()
        
        # Previous output index (4 bytes)
        prev_index = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        input_data['prev_index'] = prev_index
        
        # Script length
        script_len, offset = read_varint(data, offset)
        # Script
        script = data[offset:offset+script_len]
        offset += script_len
        input_data['script_len'] = script_len
        
        # Sequence (4 bytes)
        sequence = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        input_data['sequence'] = sequence
        
        result['inputs'].append(input_data)
    
    # Output count
    output_count, offset = read_varint(data, offset)
    result['output_count'] = output_count
    
    # Parse outputs
    for i in range(output_count):
        output_data = {}
        # Value (8 bytes)
        value = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        output_data['value'] = value
        
        # Script length
        script_len, offset = read_varint(data, offset)
        # Script
        script = data[offset:offset+script_len]
        offset += script_len
        output_data['script_len'] = script_len
        output_data['script'] = script
        
        # Determine script type
        if script_len == 0:
            output_data['type'] = 'EMPTY'
        elif script_len >= 2 and script[0] == 0x6a:  # OP_RETURN
            output_data['type'] = 'OP_RETURN'
        elif script_len == 22 and script[0] == 0x00 and script[1] == 0x14:
            output_data['type'] = 'P2WPKH'
        elif script_len == 34 and script[0] == 0x51 and script[1] == 0x20:
            output_data['type'] = 'P2TR'
        else:
            output_data['type'] = f'UNKNOWN({script_len})'
        
        result['outputs'].append(output_data)
    
    # Witness data (if present)
    if has_witness:
        for i in range(input_count):
            witness_items, offset = parse_witness(data, offset)
            witness_summary = []
            for j, item in enumerate(witness_items):
                item_info = {
                    'index': j,
                    'size': len(item),
                    'type': 'unknown'
                }
                
                # Classify witness item
                if len(item) == 0:
                    item_info['type'] = 'empty'
                elif len(item) == 64:
                    item_info['type'] = 'schnorr_signature'
                elif len(item) == 33:
                    item_info['type'] = 'control_block'
                elif len(item) > 1000:
                    item_info['type'] = 'large_script'
                    # Check for envelope markers
                    if b'BIN' in item:
                        item_info['has_bin'] = True
                    if b'application/wasm' in item:
                        item_info['has_wasm'] = True
                else:
                    item_info['type'] = 'medium_data'
                
                witness_summary.append(item_info)
            
            result['witness_data'].append(witness_summary)
    
    # Calculate virtual size (weight / 4)
    # Rough estimate: base size + witness size / 4
    base_size = len(data)
    if has_witness:
        # Estimate witness size (this is approximate)
        witness_size = sum(sum(len(item) for item in witness) for witness in result['witness_data'])
        result['vsize'] = (base_size * 3 + base_size + witness_size) // 4
    else:
        result['vsize'] = base_size
    
    return result

def print_transaction_summary(tx_data):
    """Print a summary of transaction data"""
    print(f"\n=== {tx_data['name'].upper()} TRANSACTION ANALYSIS ===")
    print(f"Size: {tx_data['size_bytes']:,} bytes")
    print(f"Virtual Size: {tx_data['vsize']:,} vbytes")
    print(f"Version: {tx_data['version']}")
    print(f"Has Witness: {tx_data['has_witness']}")
    print(f"Inputs: {tx_data['input_count']}")
    print(f"Outputs: {tx_data['output_count']}")
    
    # Output details
    print(f"\nOutputs:")
    for i, output in enumerate(tx_data['outputs']):
        print(f"  Output {i}: {output['value']:,} sats, {output['script_len']} bytes ({output['type']})")
    
    # Witness details
    if tx_data['has_witness']:
        print(f"\nWitness Data:")
        for i, witness in enumerate(tx_data['witness_data']):
            print(f"  Input {i}: {len(witness)} witness items")
            for item in witness:
                markers = []
                if item.get('has_bin'):
                    markers.append('BIN')
                if item.get('has_wasm'):
                    markers.append('WASM')
                marker_str = f" ({', '.join(markers)})" if markers else ""
                print(f"    Item {item['index']}: {item['size']:,} bytes ({item['type']}){marker_str}")

def compare_transactions(tx_list):
    """Compare multiple transactions"""
    print(f"\n{'='*80}")
    print("TRANSACTION COMPARISON SUMMARY")
    print(f"{'='*80}")
    
    # Size comparison
    print(f"\n📊 SIZE COMPARISON:")
    print(f"{'Name':<15} {'Size (bytes)':<15} {'VSize (vbytes)':<15} {'Inputs':<8} {'Outputs':<8}")
    print("-" * 70)
    for tx in tx_list:
        print(f"{tx['name']:<15} {tx['size_bytes']:<15,} {tx['vsize']:<15,} {tx['input_count']:<8} {tx['output_count']:<8}")
    
    # Find working transaction for comparison
    working_tx = next((tx for tx in tx_list if 'working' in tx['name']), None)
    if working_tx:
        print(f"\n📈 SIZE EFFICIENCY vs WORKING TRANSACTION:")
        for tx in tx_list:
            if tx['name'] != working_tx['name']:
                size_ratio = tx['size_bytes'] / working_tx['size_bytes']
                vsize_ratio = tx['vsize'] / working_tx['vsize']
                print(f"{tx['name']}: {size_ratio:.2f}x size, {vsize_ratio:.2f}x vsize")
    
    # Witness structure comparison
    print(f"\n🔍 WITNESS STRUCTURE COMPARISON:")
    for tx in tx_list:
        if tx['has_witness']:
            print(f"\n{tx['name']}:")
            for i, witness in enumerate(tx['witness_data']):
                witness_desc = []
                for item in witness:
                    witness_desc.append(f"{item['type']}({item['size']})")
                print(f"  Input {i}: [{', '.join(witness_desc)}]")

def main():
    # List of transaction files to analyze
    tx_files = [
        ('examples/working-tx.hex', 'working'),
        ('examples/deezel-v2-tx.hex', 'deezel-v2'),
        ('examples/deezel-v3-tx.hex', 'deezel-v3'),
        ('examples/deezel-v4-tx.hex', 'deezel-v4'),
        ('examples/deezel-v5-tx.hex', 'deezel-v5'),
        ('examples/deezel-v6-tx.hex', 'deezel-v6'),
        ('examples/deezel-v7-tx.hex', 'deezel-v7'),
        ('examples/deezel-v8-tx.hex', 'deezel-v8'),
    ]
    
    analyzed_transactions = []
    
    for file_path, name in tx_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    hex_data = f.read().strip()
                
                tx_data = analyze_transaction(hex_data, name)
                analyzed_transactions.append(tx_data)
                print_transaction_summary(tx_data)
                
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")
        else:
            print(f"File not found: {file_path}")
    
    if analyzed_transactions:
        compare_transactions(analyzed_transactions)
        
        # Special focus on latest version
        latest_tx = None
        for version in ['deezel-v8', 'deezel-v7', 'deezel-v6', 'deezel-v5', 'deezel-v4', 'deezel-v3', 'deezel-v2']:
            latest_tx = next((tx for tx in analyzed_transactions if tx['name'] == version), None)
            if latest_tx:
                break
        
        if latest_tx:
            print(f"\n{'='*80}")
            print(f"{latest_tx['name'].upper()} SPECIFIC ANALYSIS")
            print(f"{'='*80}")
            
            working_tx = next((tx for tx in analyzed_transactions if 'working' in tx['name']), None)
            if working_tx:
                print(f"\n🎯 {latest_tx['name'].upper()} vs WORKING TRANSACTION:")
                print(f"Size difference: {latest_tx['size_bytes'] - working_tx['size_bytes']:,} bytes")
                print(f"VSize difference: {latest_tx['vsize'] - working_tx['vsize']:,} vbytes")
                print(f"Input difference: {latest_tx['input_count'] - working_tx['input_count']} inputs")
                print(f"Output difference: {latest_tx['output_count'] - working_tx['output_count']} outputs")
                
                # Witness structure analysis
                if latest_tx['has_witness'] and working_tx['has_witness']:
                    print(f"\n🔍 WITNESS STRUCTURE ANALYSIS:")
                    print(f"Working transaction witness pattern:")
                    for i, witness in enumerate(working_tx['witness_data']):
                        pattern = [f"'{item['type']}({item['size']})'" for item in witness]
                        print(f"  Input {i}: [{', '.join(pattern)}]")
                    
                    print(f"{latest_tx['name']} transaction witness pattern:")
                    for i, witness in enumerate(latest_tx['witness_data']):
                        pattern = [f"'{item['type']}({item['size']})'" for item in witness]
                        print(f"  Input {i}: [{', '.join(pattern)}]")
                    
                    # Check if latest matches working pattern
                    working_pattern = []
                    for witness in working_tx['witness_data']:
                        working_pattern.append([item['type'] for item in witness])
                    
                    latest_pattern = []
                    for witness in latest_tx['witness_data']:
                        latest_pattern.append([item['type'] for item in witness])
                    
                    if working_pattern == latest_pattern:
                        print(f"✅ {latest_tx['name']} has same witness structure as working transaction")
                    else:
                        print(f"❌ {latest_tx['name']} has different witness structure than working transaction")
                        
                        # Detailed analysis of differences
                        print()
                        print("🔍 DETAILED WITNESS DIFFERENCES:")
                        
                        # Check if working has 1 input vs latest having multiple
                        if len(working_tx['witness_data']) == 1 and len(latest_tx['witness_data']) > 1:
                            print(f"❌ Working transaction has 1 input, {latest_tx['name']} has {len(latest_tx['witness_data'])} inputs")
                            print("💡 SOLUTION: Need to optimize to single input like working transaction")
                            
                            # Check if first input matches working pattern
                            if len(latest_tx['witness_data']) > 0:
                                first_input_pattern = [item['type'] for item in latest_tx['witness_data'][0]]
                                working_input_pattern = [item['type'] for item in working_tx['witness_data'][0]]
                                
                                if first_input_pattern == working_input_pattern:
                                    print("✅ First input witness pattern matches working transaction")
                                    print("💡 Additional inputs are causing the difference")
                                else:
                                    print("❌ Even first input witness pattern differs from working transaction")

if __name__ == "__main__":
    main()
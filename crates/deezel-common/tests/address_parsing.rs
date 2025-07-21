use std::str::FromStr;
use bitcoin::Address;

#[test]
fn test_parse_bech32_address() {
    let addr_str = "bcrt1qsdn4y2n5z2u0p82j22827z2q9gqgqgqgqgqgqg";
    let address = Address::from_str(addr_str);
    assert!(address.is_ok(), "Failed to parse bech32 address: {:?}", address.err());
}
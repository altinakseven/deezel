#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cursor_bufread() {
        let data = b"hello world";
        let mut cursor = Cursor::new(data);
        
        // Test fill_buf
        let buf = cursor.fill_buf().unwrap();
        assert_eq!(buf, b"hello world");
        
        // Test consume
        cursor.consume(5);
        let buf = cursor.fill_buf().unwrap();
        assert_eq!(buf, b" world");
        
        // Test consume more
        cursor.consume(6);
        let buf = cursor.fill_buf().unwrap();
        assert_eq!(buf, b"");
    }
}
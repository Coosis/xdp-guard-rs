pub fn as_byte_slice<'a, T>(val: &'a T) -> &'a [u8] {
    unsafe {
        std::slice::from_raw_parts(
            val as *const T as *const u8,
            std::mem::size_of::<T>()
        )
    }
}

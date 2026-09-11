pub unsafe fn read_raw(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

pub unsafe trait TrustedBuffer {
    fn pointer(&self) -> *const u8;
}

pub struct Buffer(*const u8);

unsafe impl TrustedBuffer for Buffer {
    fn pointer(&self) -> *const u8 {
        self.0
    }
}

extern "C" {
    fn native_read(pointer: *const u8) -> u8;
}

const EXAMPLE: &str = "unsafe { untrusted(); } extern \"C\" { fn example(); }";

// unsafe { commented_out(); }

#[cfg(test)]
mod tests {
    pub unsafe fn test_helper(pointer: *const u8) -> u8 {
        unsafe { *pointer }
    }
}

pub fn safe() -> &'static str {
    EXAMPLE
}

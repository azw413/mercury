/// RegExp flags. `to_byte` is the encoding stored in the bytecode header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyntaxFlags {
    pub ignore_case: bool,
    pub global: bool,
    pub multiline: bool,
    pub unicode: bool,
    pub dot_all: bool,
    pub sticky: bool,
    pub has_indices: bool,
}

impl SyntaxFlags {
    /// Parse a flags string; `None` if it has an unknown or repeated flag.
    pub fn parse(flags: &[u16]) -> Option<Self> {
        let mut result = Self::default();
        for &unit in flags {
            let flag = match char::from_u32(u32::from(unit))? {
                'i' => &mut result.ignore_case,
                'm' => &mut result.multiline,
                'g' => &mut result.global,
                'u' => &mut result.unicode,
                'y' => &mut result.sticky,
                's' => &mut result.dot_all,
                'd' => &mut result.has_indices,
                _ => return None,
            };
            if *flag {
                return None;
            }
            *flag = true;
        }
        Some(result)
    }

    pub fn to_byte(self) -> u8 {
        u8::from(self.ignore_case)
            | u8::from(self.global) << 1
            | u8::from(self.multiline) << 2
            | u8::from(self.unicode) << 3
            | u8::from(self.dot_all) << 4
            | u8::from(self.sticky) << 5
            | u8::from(self.has_indices) << 6
    }
}

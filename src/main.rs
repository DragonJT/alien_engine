use std::{process::Command, fs};

pub struct Reader {
    pub data: Vec<u8>,
    pub pos: usize,
}

impl Reader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    pub fn seek(&mut self, pos: usize) {
        if pos > self.data.len() {
            panic!("seek out of range: 0x{:X}", pos);
        }
        self.pos = pos;
    }

    pub fn read_u16(&mut self) -> u16 {
        if self.pos + 2 > self.data.len() {
            panic!("EOF reading u16");
        }

        let b0 = self.data[self.pos];
        let b1 = self.data[self.pos + 1];
        self.pos += 2;

        u16::from_le_bytes([b0, b1])
    }

    pub fn read_u32(&mut self) -> u32 {
        if self.pos + 4 > self.data.len() {
            panic!("EOF reading u32");
        }

        let b0 = self.data[self.pos];
        let b1 = self.data[self.pos + 1];
        let b2 = self.data[self.pos + 2];
        let b3 = self.data[self.pos + 3];
        self.pos += 4;

        u32::from_le_bytes([b0, b1, b2, b3])
    }

    pub fn peek_bytes(&self, off: usize, len: usize) -> &[u8] {
        if off + len > self.data.len() {
            panic!("peek out of range: off=0x{:X} len=0x{:X}", off, len);
        }
        &self.data[off..off + len]
    }

    pub fn read_u8(&mut self) -> u8 {
        if self.pos + 1 > self.data.len() { panic!("EOF reading u8"); }
        let v = self.data[self.pos];
        self.pos += 1;
        v
    }

    pub fn read_u64(&mut self) -> u64 {
        if self.pos + 8 > self.data.len() { panic!("EOF reading u64"); }
        let b = &self.data[self.pos..self.pos + 8];
        self.pos += 8;
        u64::from_le_bytes(b.try_into().unwrap())
    }

    pub fn skip(&mut self, n: usize) {
        let new_pos = self.pos + n;
        if new_pos > self.data.len() { panic!("skip out of range"); }
        self.pos = new_pos;
    }
}

#[derive(Debug)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
}

pub fn parse_dos_header(r: &mut Reader) -> DosHeader {
    if r.data.len() < 0x40 {
        panic!("file too small for DOS header");
    }

    // e_magic at 0x00
    r.seek(0x00);
    let e_magic = r.read_u16();

    if e_magic != 0x5A4D {
        panic!("not a PE file (expected MZ, got 0x{:04X})", e_magic);
    }

    // e_lfanew at 0x3C
    r.seek(0x3C);
    let e_lfanew = r.read_u32();

    let pe_offset = e_lfanew as usize;

    if pe_offset + 4 > r.data.len() {
        panic!("e_lfanew outside file: 0x{:X}", pe_offset);
    }

    let sig = r.peek_bytes(pe_offset, 4);
    if sig != b"PE\0\0" {
        panic!("invalid PE signature at 0x{:X}", pe_offset);
    }

    // Move reader to PE header start
    r.seek(pe_offset);

    DosHeader { e_magic, e_lfanew }
}


#[derive(Debug, Clone, Copy)]
pub struct DataDir { pub rva: u32, pub size: u32 }

pub fn parse_optional_header_pe32_and_dirs(r: &mut Reader) -> [DataDir; 16] {
    let opt_start = r.pos;

    let magic = r.read_u16();
    if magic != 0x010B {
        panic!("expected PE32 optional header magic 0x010B, got 0x{:04X}", magic);
    }

    // We don't need most fields yet, but we DO need NumberOfRvaAndSizes to sanity-check.
    // Layout up to NumberOfRvaAndSizes is fixed; easiest is to jump to it by offset.

    // NumberOfRvaAndSizes is at offset 92 from opt_start for PE32
    r.seek(opt_start + 92);
    let number_of_rva_and_sizes = r.read_u32();
    if number_of_rva_and_sizes < 16 {
        panic!("expected at least 16 data directories, got {}", number_of_rva_and_sizes);
    }

    // DataDirectory array starts at offset 96 from opt_start
    r.seek(opt_start + 96);

    let mut dirs = [DataDir { rva: 0, size: 0 }; 16];
    for i in 0..16 {
        let rva = r.read_u32();
        let size = r.read_u32();
        dirs[i] = DataDir { rva, size };
    }

    // Leave reader at end of optional header (caller can place it precisely too)
    dirs
}


#[derive(Debug, Clone)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

pub fn parse_sections(r: &mut Reader, count: u16) -> Vec<Section> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut name = [0u8; 8];
        for i in 0..8 { name[i] = r.read_u8(); }

        let virtual_size = r.read_u32();
        let virtual_address = r.read_u32();
        let size_of_raw_data = r.read_u32();
        let pointer_to_raw_data = r.read_u32();

        // skip the rest of IMAGE_SECTION_HEADER
        // PointerToRelocations (4) + PointerToLinenumbers (4) + NumReloc (2) + NumLines (2) + Characteristics (4)
        r.skip(16);

        out.push(Section {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
        });
    }
    out
}

pub fn section_name(s: &Section) -> String {
    let end = s.name.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&s.name[..end]).to_string()
}

pub fn rva_to_offset(sections: &[Section], rva: u32) -> usize {
    for s in sections {
        let start = s.virtual_address;
        let span = s.virtual_size.max(s.size_of_raw_data);
        let end = start.saturating_add(span);
        if rva >= start && rva < end {
            let delta = rva - start;
            return (s.pointer_to_raw_data + delta) as usize;
        }
    }
    panic!("RVA 0x{:08X} not in any section", rva);
}

#[derive(Debug)]
pub struct MdStream {
    pub name: String,
    pub offset: u32, // relative to metadata root start
    pub size: u32,
}

fn align4(r: &mut Reader) {
    while (r.pos & 3) != 0 {
        r.read_u8();
    }
}

pub fn parse_metadata_streams(r: &mut Reader, md_root_off: usize) -> Vec<MdStream> {
    r.seek(md_root_off);

    let sig = r.read_u32();
    if sig != 0x424A_5342 { // "BSJB"
        panic!("expected BSJB at 0x{:X}, got 0x{:08X}", md_root_off, sig);
    }

    let _major = r.read_u16();
    let _minor = r.read_u16();
    let _reserved = r.read_u32();

    let ver_len = r.read_u32() as usize;
    let ver_start = r.pos;
    r.skip(ver_len);
    // version string is nul-padded; print up to first 0
    let ver_bytes = &r.data[ver_start..ver_start + ver_len];
    let ver_end = ver_bytes.iter().position(|&b| b == 0).unwrap_or(ver_bytes.len());
    let _ver = String::from_utf8_lossy(&ver_bytes[..ver_end]).to_string();

    align4(r);

    let _flags = r.read_u16();
    let stream_count = r.read_u16();

    let mut streams = Vec::with_capacity(stream_count as usize);
    for _ in 0..stream_count {
        let offset = r.read_u32();
        let size = r.read_u32();

        let name_start = r.pos;
        while r.data[r.pos] != 0 {
            r.pos += 1;
        }
        let name = String::from_utf8_lossy(&r.data[name_start..r.pos]).to_string();
        r.pos += 1; // consume null
        align4(r);

        streams.push(MdStream { name, offset, size });
    }

    streams
}

pub fn parse_tables_row_counts(r: &mut Reader, tables_off: usize) -> ([u32; 64], u8, u64, usize) {
    r.seek(tables_off);

    let _reserved = r.read_u32();
    let _major = r.read_u8();
    let _minor = r.read_u8();
    let heap_sizes = r.read_u8(); // IMPORTANT later
    let _reserved2 = r.read_u8();

    let valid_mask = r.read_u64();
    let _sorted_mask = r.read_u64();

    let mut rows = [0u32; 64];
    for i in 0..64 {
        if ((valid_mask >> i) & 1) != 0 {
            rows[i] = r.read_u32();
        }
    }
    let tables_row_data_start = r.pos;
    (rows, heap_sizes, valid_mask, tables_row_data_start)
}

const TABLE_NAMES: [&str; 64] = [
    "Module",                 //  0
    "TypeRef",                //  1
    "TypeDef",                //  2
    "FieldPtr",               //  3
    "Field",                  //  4
    "MethodPtr",              //  5
    "MethodDef",              //  6
    "ParamPtr",               //  7
    "Param",                  //  8
    "InterfaceImpl",          //  9
    "MemberRef",              // 10
    "Constant",               // 11
    "CustomAttribute",        // 12
    "FieldMarshal",           // 13
    "DeclSecurity",           // 14
    "ClassLayout",            // 15
    "FieldLayout",            // 16
    "StandAloneSig",          // 17
    "EventMap",               // 18
    "EventPtr",               // 19
    "Event",                  // 20
    "PropertyMap",            // 21
    "PropertyPtr",            // 22
    "Property",               // 23
    "MethodSemantics",        // 24
    "MethodImpl",             // 25
    "ModuleRef",              // 26
    "TypeSpec",               // 27
    "ImplMap",                // 28
    "FieldRVA",               // 29
    "ENCLog",                 // 30
    "ENCMap",                 // 31
    "Assembly",               // 32
    "AssemblyProcessor",      // 33
    "AssemblyOS",             // 34
    "AssemblyRef",            // 35
    "AssemblyRefProcessor",   // 36
    "AssemblyRefOS",          // 37
    "File",                   // 38
    "ExportedType",           // 39
    "ManifestResource",       // 40
    "NestedClass",            // 41
    "GenericParam",           // 42
    "MethodSpec",             // 43
    "GenericParamConstraint", // 44
    "Reserved45",             // 45
    "Reserved46",             // 46
    "Reserved47",             // 47
    "Reserved48",             // 48
    "Reserved49",             // 49
    "Reserved50",             // 50
    "Reserved51",             // 51
    "Reserved52",             // 52
    "Reserved53",             // 53
    "Reserved54",             // 54
    "Reserved55",             // 55
    "Reserved56",             // 56
    "Reserved57",             // 57
    "Reserved58",             // 58
    "Reserved59",             // 59
    "Reserved60",             // 60
    "Reserved61",             // 61
    "Reserved62",             // 62
    "Reserved63",             // 63
];

pub fn dump_tables(rows: &[u32; 64], valid_mask: u64) {
    for i in 0..64 {
        if ((valid_mask >> i) & 1) != 0 {
            println!("Table {:>2} {:<18} rows {}", i, TABLE_NAMES[i], rows[i]);
        }
    }
}

fn read_cstr(data: &[u8], start: usize) -> String {
    let mut p = start;
    while p < data.len() && data[p] != 0 { p += 1; }
    String::from_utf8_lossy(&data[start..p]).to_string()
}

fn strings_get(data: &[u8], strings_heap_off: usize, ix: u32) -> String {
    if ix == 0 {
        return String::new(); // required by metadata spec
    }
    let off = strings_heap_off + ix as usize;
    if off >= data.len() {
        panic!("string index out of range");
    }
    read_cstr(data, off)
}

pub struct Cor20{
    pub cb:u32,
    pub major:u16,
    pub minor:u16,
    pub metadata_rva:u32,
    pub metadata_size:u32,
}

fn parse_cor20(r:&mut Reader) -> Cor20{
    let cb = r.read_u32();
    let major = r.read_u16();
    let minor = r.read_u16();
    let metadata_rva = r.read_u32();
    let metadata_size = r.read_u32();
    Cor20 { cb, major, minor, metadata_rva, metadata_size }
}

//-----------------------------

fn heap_index_size(heap_sizes: u8, bit: u8) -> u16 {
    if ((heap_sizes >> bit) & 1) != 0 { 4 } else { 2 }
}

fn table_index_size(rows: &[u32;64], table_id: usize) -> u16 {
    if rows[table_id] > 0xFFFF { 4 } else { 2 }
}

fn coded_index_size(rows: &[u32;64], tag_bits: u8, targets: &[usize]) -> u16 {
    let mut max_rows = 0u32;
    for &t in targets {
        max_rows = max_rows.max(rows[t]);
    }
    if (max_rows << tag_bits) > 0xFFFF { 4 } else { 2 }
}

fn compute_row_sizes(heap_sizes: u8, rows: &[u32;64]) -> [u16;64] {

    let s = heap_index_size(heap_sizes, 0);
    let g = heap_index_size(heap_sizes, 1);
    let b = heap_index_size(heap_sizes, 2);

    let field_index = table_index_size(rows, 4);
    let method_index = table_index_size(rows, 6);
    let param_index = table_index_size(rows, 8);

    let resolution_scope = coded_index_size(rows, 2, &[0, 26, 35, 1]);
    let typedef_or_ref   = coded_index_size(rows, 2, &[2, 1, 27]);

    let mut rs = [0u16; 64];

    // Module (0)
    rs[0] = 2 + s + g + g + g;

    // TypeRef (1)
    rs[1] = resolution_scope + s + s;

    // TypeDef (2)
    rs[2] = 4 + s + s + typedef_or_ref + field_index + method_index;

    // MethodDef (6)
    rs[6] = 4 + 2 + 2 + s + b + param_index;

    // Param (8)
    rs[8] = 2 + 2 + s;

    // MemberRef (10)
    let memberref_parent = coded_index_size(rows, 3, &[2,1,26,6,27]);
    rs[10] = memberref_parent + s + b;

    // CustomAttribute (12)
    let has_custom_attr = coded_index_size(rows, 5, &[
        6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43
    ]);
    let custom_attr_type = coded_index_size(rows, 3, &[6,10]);
    rs[12] = has_custom_attr + custom_attr_type + b;

    // Assembly (32)
    rs[32] = 4 + 2+2+2+2 + 4 + b + s + s;

    // AssemblyRef (35)
    rs[35] = 2+2+2+2 + 4 + b + s + s + b;

    rs
}

fn compute_table_starts(
    tables_row_data_start: usize,
    valid_mask: u64,
    rows: &[u32; 64],
    row_sizes: &[u16; 64],
) -> [Option<usize>; 64] {
    let mut starts = [None; 64];
    let mut cur = tables_row_data_start;

    for tid in 0..64 {
        if ((valid_mask >> tid) & 1) != 0 {
            starts[tid] = Some(cur);
            cur += (rows[tid] as usize) * (row_sizes[tid] as usize);
        }
    }
    starts
}

//---------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Operand {
    None,
    I8(i8),
    I32(i32),
    Token(u32),
    BrTarget(i32),
    BrTargetS(i32),
    Var(u16),
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub il_off: usize,
    pub opcode: u16,
    pub operand: Operand,
}

#[derive(Clone, Copy)]
pub enum OperandKind { None, I8, I32, Token, BrS, Br, VarU8, VarU16 }

#[derive(Clone, Copy)]
pub struct OpDef {
    pub code: u16,
    pub name: &'static str,      // debug only
    pub operand: OperandKind,    // how to decode
}

pub const OPS: &[OpDef] = &[

    // =========
    // No-op / flow
    // =========
    OpDef { code: 0x00, name: "nop", operand: OperandKind::None },
    OpDef { code: 0x2A, name: "ret", operand: OperandKind::None },

    // =========
    // Arguments
    // =========
    OpDef { code: 0x02, name: "ldarg.0", operand: OperandKind::None },
    OpDef { code: 0x03, name: "ldarg.1", operand: OperandKind::None },
    OpDef { code: 0x04, name: "ldarg.2", operand: OperandKind::None },
    OpDef { code: 0x05, name: "ldarg.3", operand: OperandKind::None },
    OpDef { code: 0x0E, name: "ldarg.s", operand: OperandKind::VarU8 },
    OpDef { code: 0x11, name: "starg.s", operand: OperandKind::VarU8 },

    // =========
    // Locals
    // =========
    OpDef { code: 0x06, name: "ldloc.0", operand: OperandKind::None },
    OpDef { code: 0x07, name: "ldloc.1", operand: OperandKind::None },
    OpDef { code: 0x08, name: "ldloc.2", operand: OperandKind::None },
    OpDef { code: 0x09, name: "ldloc.3", operand: OperandKind::None },
    OpDef { code: 0x0A, name: "stloc.0", operand: OperandKind::None },
    OpDef { code: 0x0B, name: "stloc.1", operand: OperandKind::None },
    OpDef { code: 0x0C, name: "stloc.2", operand: OperandKind::None },
    OpDef { code: 0x0D, name: "stloc.3", operand: OperandKind::None },
    OpDef { code: 0x13, name: "ldloc.s", operand: OperandKind::VarU8 },
    OpDef { code: 0x14, name: "stloc.s", operand: OperandKind::VarU8 },

    // =========
    // Constants
    // =========
    OpDef { code: 0x15, name: "ldc.i4.m1", operand: OperandKind::None },
    OpDef { code: 0x16, name: "ldc.i4.0", operand: OperandKind::None },
    OpDef { code: 0x17, name: "ldc.i4.1", operand: OperandKind::None },
    OpDef { code: 0x18, name: "ldc.i4.2", operand: OperandKind::None },
    OpDef { code: 0x19, name: "ldc.i4.3", operand: OperandKind::None },
    OpDef { code: 0x1A, name: "ldc.i4.4", operand: OperandKind::None },
    OpDef { code: 0x1B, name: "ldc.i4.5", operand: OperandKind::None },
    OpDef { code: 0x1C, name: "ldc.i4.6", operand: OperandKind::None },
    OpDef { code: 0x1D, name: "ldc.i4.7", operand: OperandKind::None },
    OpDef { code: 0x1E, name: "ldc.i4.8", operand: OperandKind::None },
    OpDef { code: 0x1F, name: "ldc.i4.s", operand: OperandKind::I8 },
    OpDef { code: 0x20, name: "ldc.i4", operand: OperandKind::I32 },

    // =========
    // Arithmetic
    // =========
    OpDef { code: 0x58, name: "add", operand: OperandKind::None },
    OpDef { code: 0x59, name: "sub", operand: OperandKind::None },
    OpDef { code: 0x5A, name: "mul", operand: OperandKind::None },
    OpDef { code: 0x5B, name: "div", operand: OperandKind::None },
    OpDef { code: 0x5D, name: "rem", operand: OperandKind::None },
    OpDef { code: 0x5F, name: "and", operand: OperandKind::None },
    OpDef { code: 0x60, name: "or", operand: OperandKind::None },
    OpDef { code: 0x61, name: "xor", operand: OperandKind::None },
    OpDef { code: 0x62, name: "shl", operand: OperandKind::None },
    OpDef { code: 0x63, name: "shr", operand: OperandKind::None },

    // =========
    // Comparison
    // =========
    OpDef { code: 0xFE01, name: "ceq", operand: OperandKind::None },
    OpDef { code: 0xFE02, name: "cgt", operand: OperandKind::None },
    OpDef { code: 0xFE04, name: "clt", operand: OperandKind::None },

    // =========
    // Branching
    // =========
    OpDef { code: 0x2B, name: "br.s", operand: OperandKind::BrS },
    OpDef { code: 0x38, name: "br", operand: OperandKind::Br },
    OpDef { code: 0x2C, name: "brfalse.s", operand: OperandKind::BrS },
    OpDef { code: 0x39, name: "brfalse", operand: OperandKind::Br },
    OpDef { code: 0x2D, name: "brtrue.s", operand: OperandKind::BrS },
    OpDef { code: 0x3A, name: "brtrue", operand: OperandKind::Br },

    // =========
    // Method calls
    // =========
    OpDef { code: 0x28, name: "call", operand: OperandKind::Token },
    OpDef { code: 0x6F, name: "callvirt", operand: OperandKind::Token },
    OpDef { code: 0x73, name: "newobj", operand: OperandKind::Token },

    // =========
    // Fields
    // =========
    OpDef { code: 0x7B, name: "ldfld", operand: OperandKind::Token },
    OpDef { code: 0x7C, name: "ldflda", operand: OperandKind::Token },
    OpDef { code: 0x7D, name: "stfld", operand: OperandKind::Token },
    OpDef { code: 0x7E, name: "ldsfld", operand: OperandKind::Token },
    OpDef { code: 0x80, name: "stsfld", operand: OperandKind::Token },

    // =========
    // Object / type
    // =========
    OpDef { code: 0x72, name: "ldstr", operand: OperandKind::Token },
    OpDef { code: 0x8C, name: "box", operand: OperandKind::Token },
    OpDef { code: 0x8D, name: "newarr", operand: OperandKind::Token },
    OpDef { code: 0x74, name: "castclass", operand: OperandKind::Token },
    OpDef { code: 0x75, name: "isinst", operand: OperandKind::Token },

    // =========
    // Arrays
    // =========
    OpDef { code: 0x8E, name: "ldlen", operand: OperandKind::None },
    OpDef { code: 0x9A, name: "ldelem.i4", operand: OperandKind::None },
    OpDef { code: 0x9E, name: "stelem.i4", operand: OperandKind::None },

    // =========
    // Conversions
    // =========
    OpDef { code: 0x67, name: "conv.i1", operand: OperandKind::None },
    OpDef { code: 0x68, name: "conv.i2", operand: OperandKind::None },
    OpDef { code: 0x69, name: "conv.i4", operand: OperandKind::None },
    OpDef { code: 0x6A, name: "conv.i8", operand: OperandKind::None },
    OpDef { code: 0x6B, name: "conv.r4", operand: OperandKind::None },
    OpDef { code: 0x6C, name: "conv.r8", operand: OperandKind::None },
];

fn lookup_op(code: u16) -> &'static OpDef {
    for op in OPS {
        if op.code == code { return op; }
    }
    panic!("unknown opcode 0x{:04X}", code);
}

pub fn decode_il(r: &mut Reader, il_start: usize, il_size: usize) -> Vec<Instruction> {
    let il_end = il_start + il_size;
    r.seek(il_start);

    let mut out = Vec::new();

    while r.pos < il_end {
        let il_off = r.pos - il_start;

        let op1 = r.read_u8();
        let code: u16 = if op1 == 0xFE {
            let op2 = r.read_u8();
            0xFE00 | (op2 as u16)
        } else {
            op1 as u16
        };

        let def = lookup_op(code);

        let operand = match def.operand {
            OperandKind::None => Operand::None,
            OperandKind::I8 => Operand::I8(r.read_u8() as i8),
            OperandKind::I32 => Operand::I32(r.read_u32() as i32),
            OperandKind::Token => Operand::Token(r.read_u32()),
            OperandKind::BrS => {
                let rel = r.read_u8() as i8 as i32;
                let next = (r.pos - il_start) as i32;
                Operand::BrTargetS(next + rel)
            }
            OperandKind::Br => {
                let rel = r.read_u32() as i32;
                let next = (r.pos - il_start) as i32;
                Operand::BrTarget(next + rel)
            }
            OperandKind::VarU8 => Operand::Var(r.read_u8() as u16),
            OperandKind::VarU16 => Operand::Var(r.read_u16()),
        };

        out.push(Instruction { il_off, opcode: code, operand });
    }

    out
}

fn opcode_name(code: u16) -> &'static str {
    // For debugging you might want "unknown" instead of panic:
    for op in OPS {
        if op.code == code { return op.name; }
    }
    "<unknown>"
}

pub fn disasm(insts: &Vec<Instruction>) {
    for ins in insts {
        println!("{:04X}: {:<12} {:?}", ins.il_off, opcode_name(ins.opcode), ins.operand);
    }
}

//--------------------------------------------------------------------------------

/* might need
#[derive(Debug, Clone, Copy)]
pub struct MethodDefRow {
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name_ix: u32,     // heap index (2 or 4 in file)
    pub sig_ix: u32,      // heap index (2 or 4 in file)
    pub param_list: u32,  // table index (2 or 4 in file)
}

fn read_methoddef_row_sized(
    r: &mut Reader,
    strings_ix_size: u16,
    blob_ix_size: u16,
    param_ix_size: u16,
) -> MethodDefRow {
    let rva = r.read_u32();
    let impl_flags = r.read_u16();
    let flags = r.read_u16();

    let name_ix = if strings_ix_size == 2 { r.read_u16() as u32 } else { r.read_u32() };
    let sig_ix  = if blob_ix_size == 2 { r.read_u16() as u32 } else { r.read_u32() };
    let param_list = if param_ix_size == 2 { r.read_u16() as u32 } else { r.read_u32() };

    MethodDefRow { rva, impl_flags, flags, name_ix, sig_ix, param_list }
} */
#[derive(Debug, Clone)]
pub struct Method {
    pub token: u32, 
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: String,
    pub sig: MethodSig,  

    pub il_start: Option<usize>,
    pub il_size: Option<usize>,
    pub max_stack: Option<u16>,
    pub local_sig_tok: Option<u32>,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone)]
pub struct ParamInfo {
    pub seq: u16,        // 1..N (0 is return in metadata, usually not used)
    pub name: String,    // from #Strings via Param table
    pub ty: TypeSig,     // from method signature blob
    pub flags: u16,      // Param.Flags
}

#[derive(Debug, Clone)]
pub struct MethodSig {
    pub has_this: bool,
    pub explicit_this: bool,
    pub calling_convention: u8, // lower bits
    pub param_count: u32,
    pub ret: TypeSig,
    pub params: Vec<TypeSig>,
}

#[derive(Debug, Clone)]
pub enum TypeSig {
    Void,
    Boolean,
    Char,
    I1, U1,
    I2, U2,
    I4, U4,
    I8, U8,
    R4, R8,
    String,
    Object,
    Class{tag:u8, row:u32},     // TypeDefOrRefEncoded (you can resolve later)
    ValueType{tag:u8, row:u32}, // TypeDefOrRefEncoded
    ByRef(Box<TypeSig>),
    SzArray(Box<TypeSig>),
    // add: GenericInst, Var/MVar, etc later
    Unknown(u8),
}

fn read_compressed_u32(data: &[u8], p: &mut usize) -> u32 {
    if *p >= data.len() { panic!("compressed uint out of range"); }

    let b0 = data[*p];
    *p += 1;

    // 0xxxxxxx
    if (b0 & 0x80) == 0 {
        return b0 as u32;
    }

    // 10xxxxxx xxxxxxxx
    if (b0 & 0xC0) == 0x80 {
        if *p >= data.len() { panic!("compressed uint out of range"); }
        let b1 = data[*p];
        *p += 1;
        return (((b0 & 0x3F) as u32) << 8) | (b1 as u32);
    }

    // 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    if (b0 & 0xE0) == 0xC0 {
        if *p + 2 >= data.len() { panic!("compressed uint out of range"); }
        let b1 = data[*p]; *p += 1;
        let b2 = data[*p]; *p += 1;
        let b3 = data[*p]; *p += 1;
        return (((b0 & 0x1F) as u32) << 24)
            | ((b1 as u32) << 16)
            | ((b2 as u32) << 8)
            |  (b3 as u32);
    }

    panic!("invalid compressed uint");
}

fn blob_slice<'a>(data: &'a [u8], blob_heap_off: usize, ix: u32) -> &'a [u8] {
    if ix == 0 { return &[]; }

    let start = blob_heap_off + ix as usize;
    if start >= data.len() { panic!("blob index out of range"); }

    let mut p = start;
    let len = read_compressed_u32(data, &mut p) as usize;

    let end = p + len;
    if end > data.len() { panic!("blob payload out of range"); }

    &data[p..end]
}

fn decode_typedef_or_ref(coded: u32) -> (u8, u32) {
    let tag = (coded & 0x3) as u8;
    let row = coded >> 2;
    (tag, row)
}

// Minimal type signature parser (covers common cases)
fn read_type_sig(sig: &[u8], p: &mut usize) -> TypeSig {
    if *p >= sig.len() { panic!("type sig out of range"); }
    let et = sig[*p]; *p += 1;

    match et {
        0x01 => TypeSig::Void,
        0x02 => TypeSig::Boolean,
        0x03 => TypeSig::Char,
        0x04 => TypeSig::I1,
        0x05 => TypeSig::U1,
        0x06 => TypeSig::I2,
        0x07 => TypeSig::U2,
        0x08 => TypeSig::I4,
        0x09 => TypeSig::U4,
        0x0A => TypeSig::I8,
        0x0B => TypeSig::U8,
        0x0C => TypeSig::R4,
        0x0D => TypeSig::R8,
        0x0E => TypeSig::String,
        0x1C => TypeSig::Object,

        0x10 => { // BYREF
            let inner = read_type_sig(sig, p);
            TypeSig::ByRef(Box::new(inner))
        }
        0x1D => { // SZARRAY
            let inner = read_type_sig(sig, p);
            TypeSig::SzArray(Box::new(inner))
        }

        0x12 => { // CLASS TypeDefOrRefEncoded
            let (tag, row) = decode_typedef_or_ref(read_compressed_u32(sig, p));
            TypeSig::Class{tag, row}
        }
        0x11 => { // VALUETYPE TypeDefOrRefEncoded
            let (tag, row) = decode_typedef_or_ref(read_compressed_u32(sig, p));
            TypeSig::ValueType{tag, row}
        }

        other => TypeSig::Unknown(other),
    }
}

fn decode_method_sig(sig: &[u8]) -> MethodSig {
    if sig.is_empty() { panic!("empty method signature blob"); }
    let mut p = 0usize;

    let cc = sig[p]; p += 1;
    let has_this = (cc & 0x20) != 0;
    let explicit_this = (cc & 0x40) != 0;
    let calling_convention = cc & 0x0F;

    let param_count = read_compressed_u32(sig, &mut p);
    let ret = read_type_sig(sig, &mut p);

    let mut params = Vec::with_capacity(param_count as usize);
    for _ in 0..param_count {
        params.push(read_type_sig(sig, &mut p));
    }

    MethodSig { has_this, explicit_this, calling_convention, param_count, ret, params }
}

fn read_heap_index(r: &mut Reader, size: u16) -> u32 {
    if size == 2 { r.read_u16() as u32 } else { r.read_u32() }
}

fn read_table_index(r: &mut Reader, size: u16) -> u32 {
    if size == 2 { r.read_u16() as u32 } else { r.read_u32() }
}

pub fn read_all_methods(
    r: &mut Reader,
    rows: &[u32; 64],
    table_starts: &[Option<usize>; 64],
    heap_sizes: u8,
    strings_heap_off: usize,
    blob_heap_off: usize,
) -> Vec<Method> {
    let method_count = rows[6] as usize;
    if method_count == 0 {
        return Vec::new();
    }

    let methods_start = table_starts[6].expect("MethodDef table present but no start offset");

    // index sizes
    let strings_ix_size = heap_index_size(heap_sizes, 0);
    let blob_ix_size = heap_index_size(heap_sizes, 2);
    let param_ix_size = table_index_size(rows, 8); // Param table (8), even if 0 rows it's still an index field

    r.seek(methods_start);

    let mut out = Vec::with_capacity(method_count);

    for i in 0..method_count {
        // MethodDef row (table 6):
        // RVA(u32), ImplFlags(u16), Flags(u16), Name(str), Sig(blob), ParamList(Param)
        let rva = r.read_u32();
        let impl_flags = r.read_u16();
        let flags = r.read_u16();
        let name_ix = read_heap_index(r, strings_ix_size);
        let sig_ix = read_heap_index(r, blob_ix_size);
        let _param_list = read_table_index(r, param_ix_size); // you can use this later to join Param table

        let name = strings_get(&r.data, strings_heap_off, name_ix);

        let sig_blob = blob_slice(&r.data, blob_heap_off, sig_ix);
        let sig = decode_method_sig(sig_blob);

        let token = 0x0600_0000u32 | ((i as u32) + 1);

        out.push(Method {
            token,
            rva,
            impl_flags,
            flags,
            name,
            sig,
            il_start:None,
            il_size:None,
            max_stack:None,
            local_sig_tok:None,
            instructions:Vec::new(),
        });
    }

    out
}

//-----------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum MethodHeader {
    Tiny { code_size: u32 },
    Fat { flags: u16, header_size: u16, max_stack: u16, code_size: u32, local_sig_tok: u32 },
}

pub fn parse_method_body_header(r: &mut Reader, method_off: usize) -> (MethodHeader, usize, usize) {
    r.seek(method_off);
    let b0 = r.read_u8();

    // Tiny: ..10
    if (b0 & 0x3) == 0x2 {
        let code_size = (b0 >> 2) as u32;
        let il_start = method_off + 1;
        let il_size = code_size as usize;
        return (MethodHeader::Tiny { code_size }, il_start, il_size);
    }

    // Fat: ..11 (rewind and read u16 flags/size)
    r.seek(method_off);
    let flags_size = r.read_u16();
    if (flags_size & 0x3) != 0x3 {
        panic!("unknown method header at 0x{:X} (b0=0x{:02X}, flags_size=0x{:04X})", method_off, b0, flags_size);
    }

    let flags = flags_size & 0x0FFF;
    let size_dwords = (flags_size >> 12) as u16;
    let header_size = size_dwords * 4;

    let max_stack = r.read_u16();
    let code_size = r.read_u32();
    let local_sig_tok = r.read_u32();

    let il_start = method_off + header_size as usize;
    let il_size = code_size as usize;

    (
        MethodHeader::Fat { flags, header_size, max_stack, code_size, local_sig_tok },
        il_start,
        il_size
    )
}

pub fn attach_method_instructions(
    r: &mut Reader,
    sections: &[Section],
    methods: &mut [Method],
) {
    for m in methods.iter_mut() {
        if m.rva == 0 {
            continue; // abstract / external / no body
        }

        let method_off = rva_to_offset(sections, m.rva);

        let (hdr, il_start, il_size) = parse_method_body_header(r, method_off);

        m.il_start = Some(il_start);
        m.il_size = Some(il_size);

        match hdr {
            MethodHeader::Tiny { .. } => {}
            MethodHeader::Fat { max_stack, local_sig_tok, .. } => {
                m.max_stack = Some(max_stack);
                m.local_sig_tok = Some(local_sig_tok);
            }
        }

        m.instructions = decode_il(r, il_start, il_size);
    }
}

//-------------------------------------------------------------------------------- format

fn format_method_flags(flags: u16) -> String {
    let mut parts = Vec::new();

    // visibility
    match flags & 0x0007 {
        0x0001 => parts.push("private"),
        0x0002 => parts.push("famandassem"),
        0x0003 => parts.push("assembly"),
        0x0004 => parts.push("family"),
        0x0005 => parts.push("famorassem"),
        0x0006 => parts.push("public"),
        _ => {}
    }

    if (flags & 0x0010) != 0 { parts.push("static"); }
    if (flags & 0x0020) != 0 { parts.push("final"); }
    if (flags & 0x0040) != 0 { parts.push("virtual"); }
    if (flags & 0x0080) != 0 { parts.push("hidebysig"); }
    if (flags & 0x0100) != 0 { parts.push("newslot"); }
    if (flags & 0x0400) != 0 { parts.push("abstract"); }

    parts.join(" ")
}

fn format_operand(op: &Operand) -> String {
    match op {
        Operand::None => "".into(),
        Operand::I8(v) => format!("{}", v),
        Operand::I32(v) => format!("{}", v),
        Operand::Token(t) => format!("0x{:08X}", t),
        Operand::BrTarget(t) => format!("IL_{:04X}", *t as usize),
        Operand::BrTargetS(t) => format!("ILS_{:04X}", *t as usize),
        Operand::Var(v) => format!("{}", v),
    }
}

fn format_type(t: &TypeSig) -> String {
    match t {
        TypeSig::Void => "void".into(),
        TypeSig::Boolean => "bool".into(),
        TypeSig::Char => "char".into(),
        TypeSig::I1 => "int8".into(),
        TypeSig::U1 => "uint8".into(),
        TypeSig::I2 => "int16".into(),
        TypeSig::U2 => "uint16".into(),
        TypeSig::I4 => "int32".into(),
        TypeSig::U4 => "uint32".into(),
        TypeSig::I8 => "int64".into(),
        TypeSig::U8 => "uint64".into(),
        TypeSig::R4 => "float32".into(),
        TypeSig::R8 => "float64".into(),
        TypeSig::String => "string".into(),
        TypeSig::Object => "object".into(),

        TypeSig::ByRef(inner) => format!("{}&", format_type(inner)),
        TypeSig::SzArray(inner) => format!("{}[]", format_type(inner)),

        TypeSig::Class { tag, row } =>
            format!("class(tag={}, row={})", tag, row),

        TypeSig::ValueType { tag, row } =>
            format!("valuetype(tag={}, row={})", tag, row),

        TypeSig::Unknown(b) =>
            format!("unknown(0x{:02X})", b),
    }
}

pub fn print_methods(methods: &[Method]) {
    for m in methods {
        // signature line (simple)
        let mut ps = Vec::new();
        for (i, p) in m.sig.params.iter().enumerate() {
            ps.push(format!("{} arg{}", format_type(p), i));
        }

        let flags_str = format_method_flags(m.flags);

        println!(
            ".method {} {} {}({})",
            flags_str,
            format_type(&m.sig.ret),
            m.name,
            ps.join(", ")
        );
        println!("{{");
        println!("    // token: 0x{:08X}", m.token);
        println!("    // rva:   0x{:08X}", m.rva);

        if let (Some(_), Some(size)) = (m.il_start, m.il_size) {
            println!("    // il:    {} bytes", size);
        } else {
            println!("    // il:    <no body>");
        }

        if !m.instructions.is_empty() {
            println!("    .il");
            for ins in &m.instructions {
                let name = opcode_name(ins.opcode);
                let op = format_operand(&ins.operand);
                if op.is_empty() {
                    println!("        IL_{:04X}: {}", ins.il_off, name);
                } else {
                    println!("        IL_{:04X}: {:<12} {}", ins.il_off, name, op);
                }
            }
        }

        println!("}}\n");
    }
}
//---------------------------------------------------------------------------------
fn main() {
    Command::new("dotnet")
        .args(["build", "../Project/Project.csproj", "-c", "Release"])
        .status()
        .expect("dotnet build failed");

    let dllpath = "../Project/bin/Release/net10.0/Project.dll";
    let bytes = fs::read(&dllpath).unwrap();
    let mut r = Reader::new(bytes);
    let dos_header = parse_dos_header(&mut r);

    r.seek(0x80);
    let pe_sig = r.read_u32();
    assert_eq!(pe_sig, 0x00004550);

    let _machine = r.read_u16();
    let number_of_sections = r.read_u16();
    let _timestamp = r.read_u32();
    let _ptr_to_symbols = r.read_u32();
    let _number_of_symbols = r.read_u32();
    let size_of_optional_header = r.read_u16();
    let _characteristics = r.read_u16();

    let dirs = parse_optional_header_pe32_and_dirs(&mut r);
    let com = dirs[14];

    let pe_offset = dos_header.e_lfanew as usize;
    let sections_start = pe_offset + 4 + 20 + (size_of_optional_header as usize);
    r.seek(sections_start);

    let sections = parse_sections(&mut r, number_of_sections);
    let cor20_off = rva_to_offset(&sections, com.rva);
    r.seek(cor20_off);

    let cor20 = parse_cor20(&mut r);

    let md_root_off = rva_to_offset(&sections, cor20.metadata_rva);
    let streams = parse_metadata_streams(&mut r, md_root_off);

    let tables = streams.iter().find(|s| s.name == "#~" || s.name == "#-")
        .expect("no #~/#- stream");
    let tables_off = md_root_off + tables.offset as usize;

    r.seek(tables_off);
    let (rows, heap_sizes, valid_mask, tables_row_data_start) = parse_tables_row_counts(&mut r, tables_off);

    let row_sizes = &compute_row_sizes(heap_sizes, &rows);
    let table_starts = compute_table_starts(tables_row_data_start, valid_mask, &rows, row_sizes);

    //----------------
    let mut strings_heap_off = 0usize;
    let mut blob_heap_off = 0usize;

    for s in &streams {
        match s.name.as_str() {
            "#Strings" => strings_heap_off = md_root_off + s.offset as usize,
            "#Blob"    => blob_heap_off    = md_root_off + s.offset as usize,
            _ => {}
        }
    } 
    let mut methods = read_all_methods(&mut r, &rows, &table_starts, heap_sizes, strings_heap_off, blob_heap_off); 
    attach_method_instructions(&mut r, &sections, &mut methods);
    print_methods(&methods);
    
}
use std::fs;
use std::collections::HashMap;


struct Reader {
    data: Vec<u8>,
    pos: usize,
}

impl Reader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_slice(&mut self, n: usize) -> &[u8] {
        if self.pos + n > self.data.len() {
            panic!("read_slice out of bounds");
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        slice
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

    pub fn align(&mut self, to: usize) {
        let mask = to - 1;
        let new_pos = (self.pos + mask) & !mask;
        if new_pos > self.data.len() { panic!("align out of range"); }
        self.pos = new_pos;
    }

    pub fn align_from(&mut self, base: usize, to: usize) {
        let rel = self.pos - base;
        let mask = to - 1;
        let aligned_rel = (rel + mask) & !mask;
        let new_pos = base + aligned_rel;

        if new_pos > self.data.len() {
            panic!("align_from out of range");
        }

        self.pos = new_pos;
    }
}

fn read_index(r: &mut Reader, size: usize) -> u32 {
    match size {
        2 => r.read_u16() as u32,
        4 => r.read_u32(),
        _ => panic!("bad index size {size}"),
    }
}

// Simple index into a specific table
fn simple_index_size(row_counts: &[u32; 64], table_id: usize) -> usize {
    if row_counts[table_id] < 0x1_0000 { 2 } else { 4 }
}

// Coded index size: depends on tag bits + max rows of target tables
fn coded_index_size(row_counts: &[u32; 64], tag_bits: u32, targets: &[usize]) -> usize {
    let max_rows = targets.iter().map(|&t| row_counts[t]).max().unwrap_or(0);
    if max_rows < (1u32 << (16 - tag_bits)) { 2 } else { 4 }
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
struct DataDir { pub rva: u32, pub size: u32 }

fn parse_optional_header_pe32_and_dirs(r: &mut Reader) -> [DataDir; 16] {
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

fn rva_to_file_offset(sections: &[Section], rva: u32) -> usize {
    for s in sections {
        let start = s.virt_addr;
        let end_file_backed = start + s.raw_size; // safest for reading from file
        if rva >= start && rva < end_file_backed {
            return (s.raw_ptr + (rva - start)) as usize;
        }
    }
    panic!("RVA 0x{rva:08X} not in any file-backed section");
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name:Vec<u8>,
    pub virt_addr: u32,
    pub virt_size: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct ModuleRow {
    pub generation: u16,
    pub name: u32,     // #Strings
    pub mvid: u32,     // #GUID
    pub enc_id: u32,   // #GUID
    pub enc_base_id: u32, // #GUID
}

#[derive(Debug, Clone)]
pub struct TypeRefRow {
    pub resolution_scope: u32, // ResolutionScope coded index
    pub name: u32,             // #Strings
    pub namespace: u32,        // #Strings
}

#[derive(Debug, Clone)]
pub struct TypeDefRow {
    pub flags: u32,
    pub name: u32,        // #Strings
    pub namespace: u32,   // #Strings
    pub extends: u32,     // TypeDefOrRef coded index
    pub field_list: u32,  // Field table index
    pub method_list: u32, // MethodDef table index
}

#[derive(Debug, Clone)]
pub struct MethodDefRow {
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: u32,       // #Strings
    pub signature: u32,  // #Blob
    pub param_list: u32, // Param table index
}

#[derive(Debug, Clone)]
pub struct ParamRow {
    pub flags: u16,
    pub sequence: u16,
    pub name: u32, // #Strings
}

#[derive(Debug, Clone)]
pub struct MemberRefRow {
    pub class: u32,      // MemberRefParent coded index
    pub name: u32,       // #Strings
    pub signature: u32,  // #Blob
}

#[derive(Debug, Clone)]
pub struct CustomAttributeRow {
    pub parent: u32, // HasCustomAttribute coded index
    pub ty: u32,     // CustomAttributeType coded index
    pub value: u32,  // #Blob
}

#[derive(Debug, Clone)]
pub struct AssemblyRow {
    pub hash_alg_id: u32,
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub flags: u32,
    pub public_key: u32, // #Blob
    pub name: u32,       // #Strings
    pub culture: u32,    // #Strings
}

#[derive(Debug, Clone)]
pub struct AssemblyRefRow {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub flags: u32,
    pub public_key_or_token: u32, // #Blob
    pub name: u32,                // #Strings
    pub culture: u32,             // #Strings
    pub hash_value: u32,          // #Blob
}

#[derive(Debug)]
pub struct RawTables {
    pub module: Vec<ModuleRow>,
    pub type_ref: Vec<TypeRefRow>,
    pub type_def: Vec<TypeDefRow>,
    pub method_def: Vec<MethodDefRow>,
    pub param: Vec<ParamRow>,
    pub member_ref: Vec<MemberRefRow>,
    pub custom_attribute: Vec<CustomAttributeRow>,
    pub assembly: Vec<AssemblyRow>,
    pub assembly_ref: Vec<AssemblyRefRow>,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamInfo {
    pub abs_off: usize, // absolute file offset
    pub size: usize,
}

#[derive(Debug)]
pub struct RawModule {
    pub bytes: Vec<u8>,

    // PE
    pub sections: Vec<Section>,

    // CLI / metadata
    pub meta_rva: u32,
    pub meta_size: u32,
    pub meta_off: usize, // absolute file offset

    pub streams: HashMap<String, StreamInfo>,

    pub heap_sizes: u8,
    pub valid_mask: u64,
    pub row_counts: [u32; 64],
    pub tables: RawTables,
}

impl RawModule {
    pub fn heap(&self, name: &str) -> &[u8] {
        let info = self.streams.get(name).unwrap_or_else(|| panic!("missing stream {name}"));
        let end = info.abs_off + info.size;
        if end > self.bytes.len() {
            panic!("stream {name} out of bounds");
        }
        &self.bytes[info.abs_off..end]
    }

    pub fn strings(&self) -> &[u8] { self.heap("#Strings") }
    pub fn blob(&self) -> &[u8] { self.heap("#Blob") }
    pub fn guid(&self) -> &[u8] { self.heap("#GUID") }
    pub fn us(&self) -> &[u8] { self.heap("#US") }

    pub fn tables_stream(&self) -> &[u8] {
        if self.streams.contains_key("#~") { self.heap("#~") }
        else { self.heap("#-") }
    }
}

fn read_present_tables(tr: &mut Reader, row_counts: &[u32; 64], heap_sizes: u8) -> RawTables {
    // Heap index sizes from heap_sizes bits
    let strings_sz = if (heap_sizes & 0x01) != 0 { 4 } else { 2 };
    let guid_sz    = if (heap_sizes & 0x02) != 0 { 4 } else { 2 };
    let blob_sz    = if (heap_sizes & 0x04) != 0 { 4 } else { 2 };

    // Simple table index sizes (for your present set these will be 2, but computed generally)
    let field_index_sz  = simple_index_size(row_counts, 0x04);
    let method_index_sz = simple_index_size(row_counts, 0x06);
    let param_index_sz  = simple_index_size(row_counts, 0x08);

    // ---- Coded index sizes ----

    // ResolutionScope: Module(0x00), ModuleRef(0x1A), AssemblyRef(0x23), TypeRef(0x01)
    let resolution_scope_sz = coded_index_size(row_counts, 2, &[0x00, 0x1A, 0x23, 0x01]);

    // TypeDefOrRef: TypeDef(0x02), TypeRef(0x01), TypeSpec(0x1B)
    let typedef_or_ref_sz = coded_index_size(row_counts, 2, &[0x02, 0x01, 0x1B]);

    // MemberRefParent: TypeDef(0x02), TypeRef(0x01), ModuleRef(0x1A), MethodDef(0x06), TypeSpec(0x1B)
    let member_ref_parent_sz = coded_index_size(row_counts, 3, &[0x02, 0x01, 0x1A, 0x06, 0x1B]);

    // HasCustomAttribute (tag_bits=5). Full target set per ECMA-335.
    let has_custom_attr_sz = coded_index_size(row_counts, 5, &[
        0x06, // MethodDef
        0x04, // Field
        0x01, // TypeRef
        0x02, // TypeDef
        0x08, // Param
        0x09, // InterfaceImpl
        0x0A, // MemberRef
        0x00, // Module
        0x0E, // DeclSecurity
        0x17, // Property
        0x14, // Event
        0x11, // StandAloneSig
        0x1A, // ModuleRef
        0x1B, // TypeSpec
        0x20, // Assembly
        0x23, // AssemblyRef
        0x26, // File
        0x27, // ExportedType
        0x28, // ManifestResource
        0x2A, // GenericParam
        0x2B, // MethodSpec
        0x2C, // GenericParamConstraint
    ]);

    // CustomAttributeType (tag_bits=3): (unused tags), MethodDef, MemberRef, (unused)
    // Sizing depends on max(MethodDef, MemberRef)
    let custom_attr_type_sz = coded_index_size(row_counts, 3, &[0x06, 0x0A]);

    // ---- Now read tables in increasing table id order for those present ----

    // Module (0x00)
    let mut module = Vec::with_capacity(row_counts[0x00] as usize);
    for _ in 0..row_counts[0x00] {
        module.push(ModuleRow {
            generation: tr.read_u16(),
            name: read_index(tr, strings_sz),
            mvid: read_index(tr, guid_sz),
            enc_id: read_index(tr, guid_sz),
            enc_base_id: read_index(tr, guid_sz),
        });
    }

    // TypeRef (0x01)
    let mut type_ref = Vec::with_capacity(row_counts[0x01] as usize);
    for _ in 0..row_counts[0x01] {
        type_ref.push(TypeRefRow {
            resolution_scope: read_index(tr, resolution_scope_sz),
            name: read_index(tr, strings_sz),
            namespace: read_index(tr, strings_sz),
        });
    }

    // TypeDef (0x02)
    let mut type_def = Vec::with_capacity(row_counts[0x02] as usize);
    for _ in 0..row_counts[0x02] {
        type_def.push(TypeDefRow {
            flags: tr.read_u32(),
            name: read_index(tr, strings_sz),
            namespace: read_index(tr, strings_sz),
            extends: read_index(tr, typedef_or_ref_sz),
            field_list: read_index(tr, field_index_sz),
            method_list: read_index(tr, method_index_sz),
        });
    }

    // MethodDef (0x06)
    let mut method_def = Vec::with_capacity(row_counts[0x06] as usize);
    for _ in 0..row_counts[0x06] {
        method_def.push(MethodDefRow {
            rva: tr.read_u32(),
            impl_flags: tr.read_u16(),
            flags: tr.read_u16(),
            name: read_index(tr, strings_sz),
            signature: read_index(tr, blob_sz),
            param_list: read_index(tr, param_index_sz),
        });
    }

    // Param (0x08)
    let mut param = Vec::with_capacity(row_counts[0x08] as usize);
    for _ in 0..row_counts[0x08] {
        param.push(ParamRow {
            flags: tr.read_u16(),
            sequence: tr.read_u16(),
            name: read_index(tr, strings_sz),
        });
    }

    // MemberRef (0x0A)
    let mut member_ref = Vec::with_capacity(row_counts[0x0A] as usize);
    for _ in 0..row_counts[0x0A] {
        member_ref.push(MemberRefRow {
            class: read_index(tr, member_ref_parent_sz),
            name: read_index(tr, strings_sz),
            signature: read_index(tr, blob_sz),
        });
    }

    // CustomAttribute (0x0C)
    let mut custom_attribute = Vec::with_capacity(row_counts[0x0C] as usize);
    for _ in 0..row_counts[0x0C] {
        custom_attribute.push(CustomAttributeRow {
            parent: read_index(tr, has_custom_attr_sz),
            ty: read_index(tr, custom_attr_type_sz),
            value: read_index(tr, blob_sz),
        });
    }

    // Assembly (0x20)
    let mut assembly = Vec::with_capacity(row_counts[0x20] as usize);
    for _ in 0..row_counts[0x20] {
        assembly.push(AssemblyRow {
            hash_alg_id: tr.read_u32(),
            major: tr.read_u16(),
            minor: tr.read_u16(),
            build: tr.read_u16(),
            revision: tr.read_u16(),
            flags: tr.read_u32(),
            public_key: read_index(tr, blob_sz),
            name: read_index(tr, strings_sz),
            culture: read_index(tr, strings_sz),
        });
    }

    // AssemblyRef (0x23)
    let mut assembly_ref = Vec::with_capacity(row_counts[0x23] as usize);
    for _ in 0..row_counts[0x23] {
        assembly_ref.push(AssemblyRefRow {
            major: tr.read_u16(),
            minor: tr.read_u16(),
            build: tr.read_u16(),
            revision: tr.read_u16(),
            flags: tr.read_u32(),
            public_key_or_token: read_index(tr, blob_sz),
            name: read_index(tr, strings_sz),
            culture: read_index(tr, strings_sz),
            hash_value: read_index(tr, blob_sz),
        });
    }

    RawTables {
        module,
        type_ref,
        type_def,
        method_def,
        param,
        member_ref,
        custom_attribute,
        assembly,
        assembly_ref,
    }
}

//---------------------------------------------------------- format
fn get_string(strings_heap: &[u8], idx: u32) -> &str {
    if idx == 0 {
        return "";
    }

    let mut i = idx as usize;

    if i >= strings_heap.len() {
        panic!("string index out of range: {}", idx);
    }

    let start = i;
    while i < strings_heap.len() && strings_heap[i] != 0 {
        i += 1;
    }

    std::str::from_utf8(&strings_heap[start..i]).unwrap()
}

pub fn print_tables(raw: &RawTables, strings: &[u8]) {
    println!("\n=== Module ===");
    for (i, row) in raw.module.iter().enumerate() {
        println!(
            "[{:>3}] name=\"{}\" mvid={} enc_id={} enc_base_id={}",
            i + 1,
            get_string(strings, row.name),
            row.mvid,
            row.enc_id,
            row.enc_base_id
        );
    }

    println!("\n=== Assembly ===");
    for (i, row) in raw.assembly.iter().enumerate() {
        println!(
            "[{:>3}] name=\"{}\" culture=\"{}\" version={}.{}.{}.{} flags=0x{:08X}",
            i + 1,
            get_string(strings, row.name),
            get_string(strings, row.culture),
            row.major, row.minor, row.build, row.revision,
            row.flags
        );
    }

    println!("\n=== AssemblyRef ===");
    for (i, row) in raw.assembly_ref.iter().enumerate() {
        println!(
            "[{:>3}] name=\"{}\" culture=\"{}\" version={}.{}.{}.{}",
            i + 1,
            get_string(strings, row.name),
            get_string(strings, row.culture),
            row.major, row.minor, row.build, row.revision
        );
    }

    println!("\n=== TypeRef ===");
    for (i, row) in raw.type_ref.iter().enumerate() {
        println!(
            "[{:>3}] {}.{} (scope=0x{:X})",
            i + 1,
            get_string(strings, row.namespace),
            get_string(strings, row.name),
            row.resolution_scope
        );
    }

    println!("\n=== TypeDef ===");
    for (i, row) in raw.type_def.iter().enumerate() {
        println!(
            "[{:>3}] {}.{} flags=0x{:08X} extends=0x{:X} field_list={} method_list={}",
            i + 1,
            get_string(strings, row.namespace),
            get_string(strings, row.name),
            row.flags,
            row.extends,
            row.field_list,
            row.method_list
        );
    }

    println!("\n=== MethodDef ===");
    for (i, row) in raw.method_def.iter().enumerate() {
        println!(
            "[{:>3}] RVA=0x{:08X} name=\"{}\" flags=0x{:04X} impl=0x{:04X} sig={} param_list={}",
            i + 1,
            row.rva,
            get_string(strings, row.name),
            row.flags,
            row.impl_flags,
            row.signature,
            row.param_list
        );
    }

    println!("\n=== Param ===");
    for (i, row) in raw.param.iter().enumerate() {
        println!(
            "[{:>3}] seq={} name=\"{}\" flags=0x{:04X}",
            i + 1,
            row.sequence,
            get_string(strings, row.name),
            row.flags
        );
    }

    println!("\n=== MemberRef ===");
    for (i, row) in raw.member_ref.iter().enumerate() {
        println!(
            "[{:>3}] class=0x{:X} name=\"{}\" sig={}",
            i + 1,
            row.class,
            get_string(strings, row.name),
            row.signature
        );
    }

    println!("\n=== CustomAttribute ===");
    for (i, row) in raw.custom_attribute.iter().enumerate() {
        println!(
            "[{:>3}] parent=0x{:X} type=0x{:X} value_blob={}",
            i + 1,
            row.parent,
            row.ty,
            row.value
        );
    }
}

pub fn print_rawmodule(m: &RawModule) {
    println!("\n================ RAW MODULE ================\n");

    // --- Basic PE info ---
    println!("Bytes size: {} bytes", m.bytes.len());
    println!("Metadata RVA: 0x{:08X}", m.meta_rva);
    println!("Metadata file offset: 0x{:08X}", m.meta_off);
    println!("Metadata size: {} bytes", m.meta_size);

    // --- Sections ---
    println!("\n--- Sections ---");
    for (i, s) in m.sections.iter().enumerate() {
        let end = s.name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = std::str::from_utf8(&s.name[..end]).unwrap();

        println!(
            "[{:>2}] {:<8} VA=0x{:08X} VS=0x{:08X} RAW=0x{:08X} RS=0x{:08X} CHARS=0x{:08X}",
            i,
            name,
            s.virt_addr,
            s.virt_size,
            s.raw_ptr,
            s.raw_size,
            s.characteristics
        );
    }

    // --- Streams ---
    println!("\n--- Metadata Streams ---");
    for (name, info) in &m.streams {
        println!(
            "{:<10} abs=0x{:08X} size={}",
            name,
            info.abs_off,
            info.size
        );
    }

    // --- #~ header facts ---
    println!("\n--- #~ Header ---");
    println!("heap_sizes: 0x{:02X}", m.heap_sizes);
    println!("valid_mask: 0x{:016X}", m.valid_mask);

    println!("\n--- Row Counts ---");
    for table_id in 0..64 {
        if m.row_counts[table_id] != 0 {
            println!(
                "Table {:>2} rows = {}",
                table_id,
                m.row_counts[table_id]
            );
        }
    }

    // --- Tables ---
    println!("\n--- Tables ---");
    print_tables(&m.tables, m.strings());

    println!("\n============================================\n");
}

//-------------------------------------------------------------------

pub fn load_raw_module(dllpath:&str) -> RawModule{
    let bytes = fs::read(&dllpath).unwrap();
    let mut r = Reader::new(bytes);
    let dos_header = parse_dos_header(&mut r);

    let pe_offset = dos_header.e_lfanew as usize;
    r.seek(pe_offset);
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

    let sections_start = pe_offset + 4 /*sig*/ + 20 /*coff*/ + size_of_optional_header as usize;
    r.seek(sections_start);

    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for _ in 0..number_of_sections {
        let name = r.read_slice(8).to_vec();
        let virt_size = r.read_u32();
        let virt_addr = r.read_u32();
        let raw_size  = r.read_u32();
        let raw_ptr   = r.read_u32();

        let _ptr_reloc = r.read_u32();
        let _ptr_linen = r.read_u32();
        let _num_reloc = r.read_u16();
        let _num_linen = r.read_u16();
        let characteristics     = r.read_u32();

        sections.push(Section { name, virt_addr, virt_size, raw_ptr, raw_size, characteristics });
    }
    
    let cli_off = rva_to_file_offset(&sections, com.rva);
    r.seek(cli_off);

    // IMAGE_COR20_HEADER
    let cb = r.read_u32();
    assert!(cb >= 0x48);

    let _major = r.read_u16();
    let _minor = r.read_u16();
    let meta_rva  = r.read_u32();
    let meta_size = r.read_u32();

    let _flags = r.read_u32();
    let _entry_point_token_or_rva = r.read_u32();

    let meta_off = rva_to_file_offset(&sections, meta_rva);
    r.seek(meta_off);

    let sig = r.read_u32();
    assert_eq!(sig, 0x424A_5342); // "BSJB"

    let _major = r.read_u16();
    let _minor = r.read_u16();
    let _reserved = r.read_u32();

    let ver_len = r.read_u32() as usize;
    let ver_bytes = r.read_slice(ver_len);

    let end = ver_bytes.iter().position(|&b| b == 0).unwrap_or(ver_bytes.len());
    let _ver = std::str::from_utf8(&ver_bytes[..end]).unwrap();

    // now it's safe to mutably use r again
    r.align_from(meta_off, 4);

    let _flags = r.read_u16();
    let streams_len = r.read_u16() as usize;

    let mut streams: HashMap<String, StreamInfo> = HashMap::new();
    for _ in 0..streams_len {
        let off = r.read_u32() as usize;
        let size = r.read_u32() as usize;

        let mut name_bytes = Vec::new();
        loop {
            let b = r.read_u8();
            if b == 0 { break; }
            name_bytes.push(b);
        }
        r.align_from(meta_off, 4);

        let name = String::from_utf8(name_bytes).unwrap();
        streams.insert(name, StreamInfo { abs_off: meta_off + off, size });
    }

    let string_stream = streams["#Strings"];
    let strings_heap = r.peek_bytes(string_stream.abs_off, string_stream.size);

    let tables_stream = streams["#~"];
    let tables_bytes = r.peek_bytes(tables_stream.abs_off, string_stream.size);
    let mut tr = Reader::new(tables_bytes.to_vec());

    let _reserved = tr.read_u32();
    let _major = tr.read_u8();
    let _minor = tr.read_u8();
    let heap_sizes = tr.read_u8();
    let _reserved2 = tr.read_u8();
    let valid_mask = tr.read_u64();
    let _sorted = tr.read_u64();

    let mut row_counts = [0u32; 64];
    for table_id in 0..64 {
        if ((valid_mask >> table_id) & 1) != 0 {
            row_counts[table_id] = tr.read_u32();
        }
    }

    let tables = read_present_tables(&mut tr, &row_counts, heap_sizes);

    RawModule {
        bytes: r.data, // move out of Reader
        sections,
        meta_rva,
        meta_size,
        meta_off,
        streams,
        heap_sizes,
        valid_mask,
        row_counts,
        tables,
    }
}
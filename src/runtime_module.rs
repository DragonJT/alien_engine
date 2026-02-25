use crate::raw_module::*;

const ELEMENT_TYPE_VOID: u8   = 0x01;
const ELEMENT_TYPE_I4: u8     = 0x08;
const ELEMENT_TYPE_I8: u8     = 0x0A;
const ELEMENT_TYPE_STRING: u8 = 0x0E;

#[derive(Debug, Clone)]
pub enum ElemType {
    Void,
    I4,
    I8,
    String,
}

pub struct MethodHeader {
    pub maxstack: u16,
    pub code_size: u32,
    pub local_var_sig_tok: Option<u32>,
    pub has_more_sections: bool,
    pub init_locals: bool,
}

pub struct MethodSig {
    pub has_this: bool,
    pub param_count: u32,
    pub ret: ElemType,
    pub params: Vec<ElemType>,
}

pub struct RuntimeMethod {
    pub token: u32,            // 0x06000000 | rid
    pub owner: u32,            // TypeDef token (0x02000000 | rid) or an index
    pub name: String,
    pub sig: MethodSig,        // decoded from #Blob
    pub header: MethodHeader,  // normalized
    pub il: Vec<u8>,           // raw IL bytes (or a slice if you keep bytes alive)
}

#[derive(Debug, Clone, Copy)]
enum MethodHeaderKind {
    Tiny { code_size: u32 },
    Fat  { header_size: u32, maxstack: u16, code_size: u32, local_var_sig_tok: u32, flags: u16 },
}

fn token_rid(token: u32) -> u32 {
    token & 0x00FF_FFFF
}

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|x| u16::from_le_bytes([x[0], x[1]]))
}
fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

fn parse_method_header(module: &[u8], file_off: usize) -> Option<MethodHeaderKind> {
    let b0 = *module.get(file_off)?;

    match b0 & 0x03 {
        0x02 => {
            // Tiny: [ 6-bit code size | 2-bit tag 10 ]
            let code_size = (b0 >> 2) as u32;
            Some(MethodHeaderKind::Tiny { code_size })
        }
        0x03 => {
            // Fat: first 2 bytes are flags+size
            let flags_size = read_u16_le(module, file_off)?;
            let flags = flags_size & 0x0FFF;
            let header_dwords = (flags_size >> 12) as u32;
            let header_size = header_dwords * 4;

            // Minimum fat header is 3 dwords = 12 bytes
            if header_size < 12 {
                return None;
            }

            let maxstack = read_u16_le(module, file_off + 2)?;
            let code_size = read_u32_le(module, file_off + 4)?;
            let local_var_sig_tok = read_u32_le(module, file_off + 8)?;

            Some(MethodHeaderKind::Fat {
                header_size,
                maxstack,
                code_size,
                local_var_sig_tok,
                flags,
            })
        }
        _ => None,
    }
}

fn read_method_body(raw: &RawModule, rva: u32) -> (MethodHeader, Vec<u8>)
{
    if rva == 0 {
        panic!("method has no body");
    }

    let file_off = raw.rva_to_file_off(rva);
    let kind = parse_method_header(&raw.bytes, file_off)
        .unwrap_or_else(|| panic!("invalid method header"));

    match kind {
        MethodHeaderKind::Tiny { code_size } => {
            let il_start = file_off + 1;
            let il_end = il_start + code_size as usize;

            let il = raw.bytes[il_start..il_end].to_vec();

            let header = MethodHeader {
                maxstack: 8,
                code_size,
                local_var_sig_tok: None,
                init_locals: false,
                has_more_sections: false,
            };

            (header, il)
        }

        MethodHeaderKind::Fat {
            header_size,
            maxstack,
            code_size,
            local_var_sig_tok,
            flags,
        } => {
            let il_start = file_off + header_size as usize;
            let il_end = il_start + code_size as usize;

            let il = raw.bytes[il_start..il_end].to_vec();

            let header = MethodHeader {
                maxstack,
                code_size,
                local_var_sig_tok: if local_var_sig_tok != 0 {
                    Some(local_var_sig_tok)
                } else {
                    None
                },
                init_locals: (flags & 0x10) != 0,
                has_more_sections: (flags & 0x08) != 0,
            };

            (header, il)
        }
    }
}
fn compute_method_owners(raw: &RawModule) -> Vec<u32> {
    let typedef_count = raw.row_counts[2] as u32; // TypeDef
    let method_count  = raw.row_counts[6] as u32; // MethodDef

    // 1-based indexing for method rid: owners[0] unused
    let mut owners = vec![0u32; (method_count + 1) as usize];

    let typedef = &raw.tables.type_def;
    if typedef.len() != typedef_count as usize {
        panic!(
            "TypeDef row_counts mismatch: row_counts={} vec_len={}",
            typedef_count,
            typedef.len()
        );
    }

    for td_rid in 1..=typedef_count {
        let td = &typedef[(td_rid - 1) as usize];

        let start = td.method_list; // 1-based MethodDef rid
        let end = if td_rid < typedef_count {
            typedef[td_rid as usize].method_list // (td_rid+1 - 1) == td_rid
        } else {
            method_count + 1
        };

        // valid for types with no methods too (start == end)
        for m_rid in start..end {
            if m_rid == 0 || m_rid > method_count {
                panic!(
                    "Invalid method_list range: TypeDef rid {} -> method rid {} (method_count={})",
                    td_rid, m_rid, method_count
                );
            }
            owners[m_rid as usize] = td_rid;
        }
    }

    // optional sanity check: every method has an owner
    for m_rid in 1..=method_count {
        if owners[m_rid as usize] == 0 {
            panic!("MethodDef rid {} has no owning TypeDef", m_rid);
        }
    }

    owners
}

pub fn read_dotnet_string(heap: &[u8], index: u32) -> String {
    if index == 0 {
        return String::new();
    }

    let mut i = index as usize;

    if i >= heap.len() {
        panic!("String index {} out of bounds", index);
    }

    let start = i;

    while i < heap.len() && heap[i] != 0 {
        i += 1;
    }

    if i >= heap.len() {
        panic!("Unterminated string at index {}", index);
    }

    std::str::from_utf8(&heap[start..i])
        .unwrap_or_else(|_| panic!("Invalid UTF8 in #Strings at index {}", index))
        .to_string()
}

fn read_compressed_u32(blob: &[u8], offset: &mut usize) -> u32 {
    let b0 = blob[*offset];
    *offset += 1;

    if (b0 & 0x80) == 0 {
        // 1 byte
        return b0 as u32;
    }

    if (b0 & 0xC0) == 0x80 {
        // 2 bytes
        let b1 = blob[*offset];
        *offset += 1;
        return (((b0 & 0x3F) as u32) << 8) | b1 as u32;
    }

    // 4 bytes
    let b1 = blob[*offset];
    let b2 = blob[*offset + 1];
    let b3 = blob[*offset + 2];
    *offset += 3;

    (((b0 & 0x1F) as u32) << 24)
        | ((b1 as u32) << 16)
        | ((b2 as u32) << 8)
        | (b3 as u32)
}

fn parse_elem_type(blob: &[u8], offset: &mut usize) -> ElemType {
    let et = blob[*offset];
    *offset += 1;

    match et {
        ELEMENT_TYPE_VOID => ElemType::Void,
        ELEMENT_TYPE_I4   => ElemType::I4,
        ELEMENT_TYPE_I8   => ElemType::I8,
        ELEMENT_TYPE_STRING => ElemType::String,

        _ => panic!("Unsupported element type 0x{:X}", et),
    }
}

fn parse_method_sig(blob_heap: &[u8], index: u32) -> MethodSig {
    if index == 0 {
        panic!("Method signature index 0 is invalid");
    }

    let mut offset = index as usize;

    if offset >= blob_heap.len() {
        panic!("Blob index {} out of bounds", index);
    }

    // first value is compressed blob length (we ignore it mostly)
    let _blob_len = read_compressed_u32(blob_heap, &mut offset);

    let callconv = blob_heap[offset];
    offset += 1;

    let has_this = (callconv & 0x20) != 0;

    let param_count = read_compressed_u32(blob_heap, &mut offset);

    let ret = parse_elem_type(blob_heap, &mut offset);

    let mut params = Vec::with_capacity(param_count as usize);
    for _ in 0..param_count {
        params.push(parse_elem_type(blob_heap, &mut offset));
    }

    MethodSig {
        has_this,
        param_count,
        ret,
        params,
    }
}


fn build_runtime_methods(raw: &RawModule) -> Vec<RuntimeMethod> {
    let methoddef_count = raw.row_counts[6] as u32; // MethodDef

    let method_owner = compute_method_owners(raw);

    let mut out = Vec::with_capacity(methoddef_count as usize);

    for rid in 1..=methoddef_count {
        let md: &MethodDefRow = &raw.tables.method_def[(rid - 1) as usize]; // assume this panics if bad

        let name = read_dotnet_string(raw.streams.strings.slice(&raw.bytes, "strings"), md.name);

        let sig = parse_method_sig(raw.streams.blob.slice(&raw.bytes, "streams"), md.signature);

        let owner_typedef_rid = method_owner[rid as usize];
        let owner = 0x0200_0000 | owner_typedef_rid;

        let (header, il) = read_method_body(raw, md.rva);

        let token = 0x0600_0000 | rid;

        out.push(RuntimeMethod {
            token,
            owner,
            name,
            sig,
            header,
            il,
        });
    }

    out
}

//-------------------------------------------------------------- format

use std::fmt;

impl fmt::Display for ElemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElemType::Void => write!(f, "void"),
            ElemType::I4 => write!(f, "int"),
            ElemType::I8 => write!(f, "long"),
            ElemType::String => write!(f, "string"),
        }
    }
}

impl fmt::Display for MethodSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (", self.ret)?;

        for (i, p) in self.params.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", p)?;
        }

        write!(f, ")")
    }
}

fn format_typedef_name(raw: &RawModule, td: &TypeDefRow) -> String {
    let strings = raw.streams.strings.slice(&raw.bytes, "strings");
    let name = read_dotnet_string(strings, td.name);
    let namespace = read_dotnet_string(strings, td.namespace);

    if namespace.is_empty() {
        name
    } else {
        format!("{}.{}", namespace, name)
    }
}

pub fn print_runtime_methods(raw:&RawModule, methods: &[RuntimeMethod]) {
    for m in methods {
        let td = &raw.tables.type_def[(token_rid(m.owner) - 1) as usize];
        let tdname = format_typedef_name(raw, td);
        println!(
            "{:#010X} {}::{}  sig={}  maxstack={} codesize={} il={}",
            m.token,
            tdname,
            m.name,
            m.sig,
            m.header.maxstack,
            m.header.code_size,
            hex_preview(&m.il, 32),
        );
    }
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    let take = bytes.len().min(max);
    let mut s = String::new();
    for (i, b) in bytes[..take].iter().enumerate() {
        if i != 0 { s.push(' '); }
        s.push_str(&format!("{:02X}", b));
    }
    if bytes.len() > max {
        s.push_str(" …");
    }
    s
}

//-----------------------------------------------------------------------


pub fn create_runtime_module(raw:&RawModule){
    let methods = build_runtime_methods(raw);
    print_runtime_methods(raw, &methods);
}
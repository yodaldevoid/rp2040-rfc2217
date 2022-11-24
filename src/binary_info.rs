extern "C" {
    static __bi_entries_start: rp_binary_info::entry::Addr;
    static __bi_entries_end: rp_binary_info::entry::Addr;
    static __sdata: u32;
    static __edata: u32;
    static __sidata: u32;
}

/// Picotool can find this block in our ELF file and report interesting metadata.
#[link_section = ".bi_header"]
#[used]
pub static PICOTOOL_META: rp_binary_info::Header =
    unsafe { rp_binary_info::Header::new(&__bi_entries_start, &__bi_entries_end, &MAPPING_TABLE) };

/// This tells picotool how to convert RAM addresses back into Flash addresses
static MAPPING_TABLE: [rp_binary_info::MappingTableEntry; 2] = [
    // This is the entry for .data
    rp_binary_info::MappingTableEntry {
        source_addr_start: unsafe { &__sidata },
        dest_addr_start: unsafe { &__sdata },
        dest_addr_end: unsafe { &__edata },
    },
    // This is the terminating marker
    rp_binary_info::MappingTableEntry {
        source_addr_start: core::ptr::null(),
        dest_addr_start: core::ptr::null(),
        dest_addr_end: core::ptr::null(),
    },
];

/// This is a list of references to our table entries
#[link_section = ".bi_entries"]
#[used]
pub static PICOTOOL_ENTRIES: [rp_binary_info::entry::Addr; 2] =
    [PROGRAM_NAME.addr(), PROGRAM_VERSION.addr()];

// TODO: set more binary info
static PROGRAM_NAME: rp_binary_info::entry::IdAndString =
    rp_binary_info::program_name(concat!(env!("CARGO_PKG_NAME"), "\0"));
static PROGRAM_VERSION: rp_binary_info::entry::IdAndString =
    rp_binary_info::version(concat!(env!("CARGO_PKG_VERSION"), "\0"));

use std::collections::{BTreeMap, BTreeSet};

use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use gimli::{
    BaseAddresses, CfaRule, DW_EH_PE_omit, DW_EH_PE_uleb128, DwEhPe, EhFrame, EndianReader,
    LittleEndian, Pointer, Reader, UnwindContext, UnwindSection, Vendor,
};
use object::{Architecture, Object, ObjectSection, ObjectSymbol, Section, Symbol};

fn main() {
    let filename = std::env::args().nth(1).unwrap();
    let symbol_name = std::env::args().nth(2).unwrap();

    let file = std::fs::read(filename).unwrap();
    let obj = object::File::parse(&*file).unwrap();
    assert_eq!(obj.architecture(), Architecture::Aarch64);

    let mut eh_frame = gimli::EhFrame::new(
        obj.section_by_name(".eh_frame").unwrap().data().unwrap(),
        LittleEndian,
    );
    eh_frame.set_vendor(Vendor::AArch64);
    eh_frame.set_address_size(obj.architecture().address_size().unwrap().bytes());

    let bases = BaseAddresses::default()
        .set_eh_frame_hdr(obj.section_by_name(".eh_frame_hdr").unwrap().address())
        .set_eh_frame(obj.section_by_name(".eh_frame").unwrap().address())
        .set_text(obj.section_by_name(".text").unwrap().address())
        .set_got(obj.section_by_name(".got").unwrap().address());

    let cs = Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .unwrap();

    let symbol = obj.symbol_by_name(&symbol_name).unwrap();
    let symbol_addr = symbol.address();
    println!("{symbol_addr:016x} <{symbol_name}>:");
    let symbol_section = obj.section_by_index(symbol.section_index().unwrap()).unwrap();
    let symbol_data = symbol_section.data_range(symbol_addr, symbol.size()).unwrap().unwrap();

    let fde = eh_frame.fde_for_address(&bases, symbol_addr, EhFrame::cie_from_offset).unwrap();
    println!("  personality: {}", format_pointer(&obj, fde.personality(), false));
    println!("  LSDA: {}", format_pointer(&obj, fde.lsda(), true));

    let lsda = if let Some(lsda_ptr) = fde.lsda() {
        let lsda_addr = pointer_to_addr(&obj, lsda_ptr);
        let lsda_section = section_for_addr(&obj, lsda_addr);
        let lsda_data =
            &lsda_section.data().unwrap()[(lsda_addr - lsda_section.address()) as usize..];

        let lsda = GccExceptTable::parse(lsda_data).unwrap();
        if !lsda.actions.is_empty() {
            println!("  LSDA actions:");
        }
        for (action_offset, action) in &lsda.actions {
            print!("    {:#x}: ", action_offset.0);
            match action.kind {
                ActionKind::Cleanup => print!("cleanup"),
                ActionKind::Catch(type_info_offset) => print!("catch {:#x}", type_info_offset.0),
            }
            println!(" next={:x?}", action.next_action);
        }
        Some(lsda)
    } else {
        None
    };
    println!();

    let mut last_regs = vec![];
    for insn in cs.disasm_all(symbol_data, symbol_addr).unwrap().into_iter() {
        let mut ctx = UnwindContext::new();
        let row = fde.unwind_info_for_address(&eh_frame, &bases, &mut ctx, insn.address()).unwrap();
        if row.registers().cloned().collect::<Vec<_>>() != last_regs {
            match row.cfa() {
                CfaRule::RegisterAndOffset { register, offset } => print!(
                    "    CFA={}+{offset:#x}",
                    gimli::AArch64::register_name(*register).unwrap()
                ),
                CfaRule::Expression(unwind_expression) => print!("    cfa={:?}", unwind_expression),
            }
            for &(reg, ref rule) in row.registers() {
                print!(" {}={rule:?}", gimli::AArch64::register_name(reg).unwrap());
            }
            println!();
            last_regs = row.registers().cloned().collect::<Vec<_>>();
        }

        println!("  {insn}");

        if let Some(lsda) = &lsda {
            if let Some(call_site) = lsda.call_sites.iter().find(|call_site| {
                (call_site.start..call_site.start + call_site.length)
                    .contains(&(insn.address() + insn.len() as u64 - symbol_addr).wrapping_sub(1))
            }) {
                print!(
                    "    call site {:#x}..{:#x}",
                    symbol_addr + call_site.start,
                    symbol_addr + call_site.start + call_site.length,
                );
                if call_site.landing_pad != 0 {
                    print!(" landingpad={:#x}", symbol_addr + call_site.landing_pad);
                }
                match call_site.action_entry {
                    None => println!(" action=continue"),
                    Some(action_offset) => println!(" action={:x}", action_offset.0),
                }
            }
        }
    }
}

struct GccExceptTable {
    call_sites: Vec<CallSite>,
    actions: BTreeMap<ActionOffset, Action>,
}

#[derive(Debug)]
struct CallSite {
    start: u64,
    length: u64,
    landing_pad: u64,
    action_entry: Option<ActionOffset>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActionOffset(u64);

#[derive(Debug)]
struct Action {
    kind: ActionKind,
    next_action: Option<ActionOffset>,
}

#[derive(Debug)]
enum ActionKind {
    Cleanup,
    Catch(TypeInfoOffset),
}

#[derive(Debug, Copy, Clone)]
struct TypeInfoOffset(u64);

impl GccExceptTable {
    #[allow(non_snake_case)]
    fn parse(lsda_data: &[u8]) -> gimli::Result<Self> {
        let mut table = GccExceptTable { call_sites: vec![], actions: BTreeMap::new() };

        let mut lsda_reader = EndianReader::new(lsda_data, LittleEndian);

        let lpStartEncoding = DwEhPe(lsda_reader.read_u8()?);
        assert_eq!(lpStartEncoding, DW_EH_PE_omit);

        let ttypeEncoding = DwEhPe(lsda_reader.read_u8()?);

        let _classInfoOffset =
            if ttypeEncoding == DW_EH_PE_omit { !0 } else { lsda_reader.read_uleb128()? };

        // call site table
        let callsiteEncoding = DwEhPe(lsda_reader.read_u8()?);
        assert_eq!(callsiteEncoding, DW_EH_PE_uleb128);
        let callsiteTableLength = lsda_reader.read_uleb128()?;
        let end_len = lsda_reader.len() - callsiteTableLength as usize;

        while lsda_reader.len() != end_len {
            table.call_sites.push(CallSite {
                start: lsda_reader.read_uleb128()?,
                length: lsda_reader.read_uleb128()?,
                landing_pad: lsda_reader.read_uleb128()?,
                action_entry: match lsda_reader.read_uleb128()? {
                    0 => None,
                    action_entry => Some(ActionOffset(action_entry - 1)),
                },
            });
        }

        // action table
        let mut pending_actions = BTreeSet::new();
        for call_site in &table.call_sites {
            if let Some(action_entry) = call_site.action_entry {
                pending_actions.insert(action_entry);
            }
        }
        while let Some(action_offset) = pending_actions.pop_last() {
            if table.actions.contains_key(&action_offset) {
                continue;
            }
            let mut action_reader = lsda_reader.range_from(action_offset.0 as usize..);
            let ttypeIndex = action_reader.read_sleb128()?;
            let kind = if ttypeIndex == 0 {
                ActionKind::Cleanup
            } else if ttypeIndex > 0 {
                ActionKind::Catch(TypeInfoOffset((ttypeIndex - 1) as u64))
            } else {
                unimplemented!("exception spec");
            };
            let actionOffset = action_reader.read_sleb128()?;
            assert_eq!(actionOffset, 0);

            table.actions.insert(action_offset, Action { kind, next_action: None });
        }

        // Not relevant to Rust:
        // type info
        // exception specs

        Ok(table)
    }
}

fn section_for_addr<'data, 'file>(
    obj: &'file object::File<'data>,
    addr: u64,
) -> Section<'data, 'file> {
    obj.sections()
        .find(|section| (section.address()..section.address() + section.size()).contains(&addr))
        .unwrap()
}

fn symbol_for_addr<'data, 'file>(
    obj: &'file object::File<'data>,
    addr: u64,
) -> Symbol<'data, 'file> {
    obj.symbols()
        .find(|symbol| (symbol.address()..symbol.address() + symbol.size()).contains(&addr))
        .unwrap()
}

fn pointer_to_addr(obj: &object::File, dwarf_ptr: Pointer) -> u64 {
    match dwarf_ptr {
        Pointer::Direct(addr) => addr,
        Pointer::Indirect(ptr) => u64::from_le_bytes(
            section_for_addr(obj, ptr).data_range(ptr, 8).unwrap().unwrap().try_into().unwrap(),
        ),
    }
}

fn format_pointer(obj: &object::File, dwarf_ptr: Option<Pointer>, section_rel: bool) -> String {
    let addr_to_name = |addr| {
        if section_rel {
            let section = section_for_addr(obj, addr);
            format!("{}+{:#x}", section.name().unwrap(), addr - section.address())
        } else {
            let symbol = symbol_for_addr(obj, addr);
            format!("{}+{:#x}", symbol.name().unwrap(), addr - symbol.address())
        }
    };

    match dwarf_ptr {
        None => format!("<none>"),
        Some(dwarf_ptr) => {
            let addr = pointer_to_addr(obj, dwarf_ptr);
            format!("{:#x} <{}>", addr, addr_to_name(addr))
        }
    }
}

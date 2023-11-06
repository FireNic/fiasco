INTERFACE [riscv]:

#include "mem_layout.h"
#include "paging.h"

class Kmem : public Mem_layout
{
public:
  static bool is_kmem_page_fault(Mword pfa, Mword /*cause*/)
  {
    return in_kernel(pfa);
  }

  static bool is_io_bitmap_page_fault(Mword)
  { return false; }
};


// Number of statically allocated pages for the kernel bootstrap page tables.
// The bootstrap page tables provide an identity mapping of the kernel, a
// virtual mapping of the kernel, an MMIO page directory, and a mapping of the
// kernel's pmem. All the above are mapped as superpages. Depending on the
// page table layout, in particular on the number of levels, different numbers
// of page tables are needed.
IMPLEMENTATION [riscv && 32bit]:
enum { Num_boot_pages = 1 };

IMPLEMENTATION [riscv && riscv_sv39]:
enum { Num_boot_pages = 5 };

IMPLEMENTATION [riscv && riscv_sv48]:
enum { Num_boot_pages = 9 };

//----------------------------------------------------------------------------
IMPLEMENTATION [riscv]:

#include "boot_infos.h"
#include "config.h"
#include "cpu.h"
#include "kip.h"
#include "kmem_slab.h"
#include "mem_unit.h"
#include "panic.h"
#include "ram_quota.h"
#include "paging_bits.h"

#include <cassert>
#include <cstdio>

// The memory for page tables has to be page aligned, however we can not use the
// aligned attribute to ensure proper alignment, because that would propagate to
// the alignment of the .bss section, preventing the linker from performing
// relaxation against the global pointer.
// Instead, we allocate memory for one more page than we actually need and do
// the alignment ourselves in Boot_paging_info.
static Unsigned8 boot_page_memory[Pg::size(Num_boot_pages + 1)]
  __attribute__((section(".bss.boot_page_memory")));

// Provide memory for the paging bootstrap mechanism. The kernel linker script
// overlays the Boot_paging_info member variable in Bootstrap_info with this.
static Boot_paging_info FIASCO_BOOT_PAGING_INFO
  _bs_pgin_dta(&boot_page_memory, Num_boot_pages);

// This pointer indirection is needed because in all of RISC-V's code models,
// statically defined symbols must lie within a single 2 GiB address range.
// For _bs_pgin_dta this condition does not hold, as it is put into the
// bootstrap.info section. Therefore, linking of code that directly accesses
// _bs_pgin_dta would fail with a "relocation truncated to fit" error.
static Boot_paging_info *bs_pgin_dta __attribute__((used)) = &_bs_pgin_dta;

Kpdir *Mem_layout::kdir = nullptr;

PUBLIC static
void
Kmem::init()
{
  Mem_unit::init_asids();
}

PUBLIC static
void
Kmem::init_paging()
{
  // So far the kernel page tables have been allocated from boot_page_memory.
  // Reallocate them now in pmem, as pmem_to_phys() would return incorrect
  // results for page tables located in boot_page_memory.
  auto alloc = Kmem_alloc::q_allocator(Ram_quota::root);
  Kmem_slab_t<Kpdir, sizeof(Kpdir)> kdir_alloc;
  kdir = kdir_alloc.q_new(Ram_quota::root);

  // Map kernel image.
  if (!kdir->map(boot_virt_to_phys(Virt_addr(Mem_layout::Map_base)),
                 Virt_addr(Mem_layout::Map_base),
                 Virt_size(bs_pgin_dta->kernel_image_size()),
                 Pte_ptr::make_attribs(Page::Attr(Page::Rights::RWX(),
                                       Page::Type::Normal(),
                                       Page::Kern::Global())),
                 Kpdir::Super_level, false, alloc))
    panic("Failed to map kernel image.");

  // Pmem is contiguous in physical memory.
  if (!kdir->map(boot_virt_to_phys(Virt_addr(Mem_layout::Pmem_start)),
                 Virt_addr(Mem_layout::Pmem_start),
                 Virt_size(Config::KMEM_SIZE),
                 Pte_ptr::make_attribs(Page::Attr(Page::Rights::RW(),
                                       Page::Type::Normal(),
                                       Page::Kern::Global())),
                 Kpdir::Super_level, false, alloc))
    panic("Failed to map pmem.");

  // Sync MMIO page directory
  for (Address mmio_addr = Mem_layout::Mmio_map_start;
       mmio_addr < Mem_layout::Mmio_map_end;
       mmio_addr += Config::SUPERPAGE_SIZE)
    {
      auto be = boot_kdir_walk(Virt_addr(mmio_addr), Kpdir::Super_level);
      if (be.is_valid())
        {
          auto e = kdir->walk(Virt_addr(mmio_addr), Kpdir::Super_level, false, alloc);
          e.set_page(be.entry());
        }
    }

  // Switch to new page table
  Cpu::set_satp(Mem_unit::Asid_boot, Cpu::phys_to_ppn(pmem_to_phys(kdir)));
  // Full tlb flush as global mappings have been changed.
  Mem_unit::tlb_flush();
}

PUBLIC static
void
Kmem::init_ap_paging()
{
  Cpu::set_satp(Mem_unit::Asid_boot, Cpu::phys_to_ppn(pmem_to_phys(kdir)));
  // Full tlb flush as global mappings have been changed.
  Mem_unit::tlb_flush();
}

PUBLIC static
bool
Kmem::boot_map_pmem(Address phys, Mword size)
{
  assert(Config::KMEM_SIZE == size);

  if (!Super_pg::aligned(phys))
    panic("Pmem must be superpage aligned!");

  Mem_layout::pmem_phys_base(phys);

  if (!boot_kdir_map(phys, Virt_addr(Mem_layout::Pmem_start), Virt_size(size),
                     Pte_ptr::make_attribs(Page::Attr(Page::Rights::RW())),
                     Kpdir::Super_level))
    return false;

  Mem_unit::tlb_flush(Mem_unit::Asid_boot);

  return true;
}

/**
 * Looks up a virtual address in the boot page table.
 */
PRIVATE static
Address
Kmem::boot_virt_to_phys(Virt_addr virt)
{
  auto i = boot_kdir_walk(virt);
  if (!i.is_valid())
    return ~0;

  return i.page_addr() | cxx::get_lsb(cxx::int_value<Virt_addr>(virt),
                                      i.page_order());
}

PRIVATE static
Kpdir *
Kmem::boot_kdir()
{
  return static_cast<Kpdir *>(
    static_cast<void *>(bs_pgin_dta->kernel_page_directory()));
}

PRIVATE static
Pte_ptr
Kmem::boot_kdir_walk(Virt_addr virt, unsigned level = Kpdir::Depth)
{
  return boot_kdir()->walk(virt, level, bs_pgin_dta->mem_map());
}

PRIVATE static
bool FIASCO_WARN_RESULT
Kmem::boot_kdir_map(Address phys, Virt_addr virt, Virt_size size,
                    unsigned long attr, unsigned level)
{
  auto alloc = bs_pgin_dta->alloc_virt(&Kmem::boot_virt_to_phys);
  auto mem_map = bs_pgin_dta->mem_map();
  return boot_kdir()->map(phys, virt, size, attr, level, false, alloc, mem_map);
}

PRIVATE static
bool
Kmem::is_mmio_mapped_at(Address phys_beg, Address phys_end, Address virt)
{
  for (Address p = phys_beg, v = virt;
       p < phys_end && v < Mem_layout::Mmio_map_end;
       p += Config::SUPERPAGE_SIZE, v += Config::SUPERPAGE_SIZE)
    {
      auto e = kdir ? kdir->walk(Virt_addr(v), Kpdir::Super_level)
                    : boot_kdir_walk(Virt_addr(v), Kpdir::Super_level);
      if (!e.is_valid() || p != e.page_addr())
        return false;
    }

  return true;
}

PUBLIC static
Address
Kmem::mmio_remap(Address phys, Mword size)
{
  static Address next_mmio_page = Mem_layout::Mmio_map_start;

  Address phys_page = Super_pg::trunc(phys);
  Address map_size = Super_pg::round(size + Super_pg::offset(phys));

  // Check if the physical memory is already mapped.
  for (Address virt = Mem_layout::Mmio_map_start;
       virt < next_mmio_page;
       virt += Config::SUPERPAGE_SIZE)
    {
      if (is_mmio_mapped_at(phys_page, phys_page + map_size, virt))
        return virt | Super_pg::offset(phys);
    }

  Address virt_page = next_mmio_page;

  assert(virt_page + map_size < Mem_layout::Mmio_map_end);
  next_mmio_page += map_size;

  auto attr = Page::Attr(Page::Rights::RW(), Page::Type::Uncached(),
                         Page::Kern::Global());
  if (kdir)
    {
      if (!kdir->map(phys_page, Virt_addr(virt_page), Virt_size(map_size),
                     Pte_ptr::make_attribs(attr), Kpdir::Super_level, false,
                     Kmem_alloc::q_allocator(Ram_quota::root)))
        return ~0UL;
    }
  else
    {
      if (!boot_kdir_map(phys_page, Virt_addr(virt_page), Virt_size(map_size),
                         Pte_ptr::make_attribs(attr), Kpdir::Super_level))
        return ~0UL;
    }

  // Full tlb flush as global mappings have been changed.
  Mem_unit::tlb_flush();

  return virt_page | Super_pg::offset(phys);
}

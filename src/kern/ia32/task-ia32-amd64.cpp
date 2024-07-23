IMPLEMENTATION[amd64 && pku]:
PRIVATE inline 
bool
Task::invoke_pku_set(L4_msg_tag &tag, Utcb *utcb)
{
  if(EXPECT_FALSE(tag.words() != 3))
    return false;
  
  unsigned int key = utcb->values[1];
  void *address = 0;
  __builtin_memcpy(&address, &utcb->values[2], sizeof(void*));

  auto pte_ptr = Kmem::current_cpu_kdir()
    ->walk(Virt_addr(address), Pdir::Depth); // wont allocate pte's

  bool level_4_or_deeper = Pdir::Depth > 3;
  bool is_valid = pte_ptr.is_valid();
  bool is_leaf = pte_ptr.is_leaf();
  bool is_user = pte_ptr.is_user();
  if(level_4_or_deeper && is_valid && is_leaf && is_user)
  {
    pte_ptr.set_pku(key);
    Mem_unit::tlb_flush();
  }
  return true;
}

IMPLEMENTATION[ia32 || (amd64 && !pku)]:
PRIVATE inline 
bool
Task::invoke_pku_set(L4_msg_tag &, Utcb *)
{ return false; }

IMPLEMENTATION [(ia32 || amd64) && no_ldt]:

PRIVATE inline
bool
Task::invoke_ldt_set(L4_msg_tag &, Utcb *)
{ return false; }

IMPLEMENTATION [(ia32 || amd64) && !no_ldt]:

#include "gdt.h"
#include "std_macros.h"
#include "x86desc.h"

PRIVATE inline NEEDS["gdt.h"]
bool
Task::invoke_ldt_set(L4_msg_tag &tag, Utcb *utcb)
{
  enum
  {
    Utcb_values_per_ldt_entry
      = Cpu::Ldt_entry_size / sizeof(utcb->values[0]),
  };
  if (EXPECT_FALSE(tag.words() < 3
                    || tag.words() % Utcb_values_per_ldt_entry))
    {
      tag = commit_result(-L4_err::EInval);
      return true;
    }

  unsigned entry_number  = utcb->values[1];
  unsigned size          = (tag.words() - 2) * sizeof(utcb->values[0]);

  // Allocate the memory if not yet done
  if (!_ldt.addr())
    _ldt.alloc();

  if (entry_number * Cpu::Ldt_entry_size + size > Config::PAGE_SIZE)
    {
      WARN("set_ldt: LDT size exceeds one page, not supported.");
      tag = commit_result(-L4_err::EInval);
      return true;
    }

  _ldt.size(size + Cpu::Ldt_entry_size * entry_number);

  Address desc_addr = reinterpret_cast<Address>(&utcb->values[2]);
  Gdt_entry desc;
  Gdt_entry *ldtp
    = reinterpret_cast<Gdt_entry *>(_ldt.addr()) + entry_number;

  while (size >= Cpu::Ldt_entry_size)
  {
    desc = *reinterpret_cast<Gdt_entry const *>(desc_addr);
    if (desc.unsafe())
      {
        WARN("set_ldt: Bad descriptor.");
        tag = commit_result(-L4_err::EInval);
        return true;
      }

    *ldtp      = desc;
    size      -= Cpu::Ldt_entry_size;
    desc_addr += Cpu::Ldt_entry_size;
    ldtp++;
  }

  if (this == current()->space())
    Cpu::cpus.cpu(current_cpu()).enable_ldt(_ldt.addr(), _ldt.size());

  tag = commit_result(0);
  
  return true;
}

IMPLEMENTATION [(ia32 || amd64)]:
PRIVATE inline
bool
Task::invoke_arch(L4_msg_tag &tag, Utcb *utcb)
{
  switch (utcb->values[0])
    {
    case Ldt_set_x86:
      return invoke_ldt_set(tag, utcb);
      case Set_pku:
      return invoke_pku_set(tag, utcb);
    default:
      return false;
    }
}

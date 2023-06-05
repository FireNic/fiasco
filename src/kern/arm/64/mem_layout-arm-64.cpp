INTERFACE [arm && cpu_virt && !arm_pt_48]: // -----------------------------

EXTENSION class Mem_layout
{
public:
  enum Virt_layout_kern_user_max : Address {
    User_max             = 0x0000007fffffffff,
  };
};

INTERFACE [arm && cpu_virt && arm_pt_48]: // ------------------------------

EXTENSION class Mem_layout
{
public:
  enum Virt_layout_kern_user_max : Address {
    User_max             = 0x0000ffffffffffff,
  };
};

INTERFACE [arm && cpu_virt]: // -------------------------------------------

EXTENSION class Mem_layout
{
public:
  enum Virt_layout_kern : Address {
    // These are guest physical addresses
    Utcb_addr            = User_max + 1 - 0x10000,

    // The following are kernel virtual addresses. Mind that kernel and user
    // space live in different address spaces! Move to the top to minimize the
    // risk of colliding with physical memory which is still mapped 1:1.
    Registers_map_start  = 0x0000ffff00000000,
    Registers_map_end    = 0x0000ffff40000000,

    Map_base             = 0x0000ffff40000000,

    Service_page         = 0x0000ffff50000000,
    Tbuf_status_page     = Service_page + 0x5000,
    Tbuf_buffer_area	 = Service_page + 0x200000,
    Tbuf_buffer_size     = 0x200000,
    Jdb_tmp_map_area     = Service_page + 0x400000,

    Pmem_start           = 0x0000ffff80000000,
    Pmem_end             = 0x0000ffffc0000000,

    Cache_flush_area     = 0x0, // dummy
  };
};

//---------------------------------------------------------------------------
INTERFACE [arm && !cpu_virt]:

#include "template_math.h"

EXTENSION class Mem_layout
{
public:
  enum Virt_layout_kern : Address {
    User_max             = 0x0000ff7fffffffff,
    Utcb_addr            = User_max + 1 - 0x10000,
    Service_page         = 0xffff1000eac00000,
    Tbuf_status_page     = Service_page + 0x5000,
    Tbuf_buffer_area	 = Service_page + 0x200000,
    Tbuf_buffer_size     = 0x200000,
    Jdb_tmp_map_area     = Service_page + 0x400000,
    Registers_map_start  = 0xffff000000000000,
    Registers_map_end    = 0xffff000040000000,
    Cache_flush_area     = 0x0,
    Pmem_start           = 0xffff000040000000,
    Pmem_end             = 0xffff000080000000,
    Map_base             = 0xffff000080000000,

    Caps_start           = 0xff8005000000,
    Caps_end             = 0xff800d000000,
    //Utcb_ptr_page        = 0xffffffffd000,
    // don't care about caches here, because arm uses a register on MP
    utcb_ptr_align       = Tl_math::Ld<sizeof(void*)>::Res,
  };

};

//--------------------------------------------------------------------------
IMPLEMENTATION [arm]:

//---------------------------------
// Workaround GCC BUG 33661
// Do not use register asm ("r") in a template function, it will be ignored
//---------------------------------
PUBLIC static inline
Mword
Mem_layout::_read_special_safe(Mword const *a)
{
  Mword res;
  __asm__ __volatile__ ("ldr %0, %1\n" : "=r" (res) : "m" (*a) : "cc" );
  return res;
}
//
//---------------------------------
// Workaround GCC BUG 33661
// Do not use register asm ("r") in a template function, it will be ignored
//---------------------------------
PUBLIC static inline
bool
Mem_layout::_read_special_safe(Mword const *address, Mword &v)
{
  Mword ret;
  asm volatile ("msr  nzcv, xzr      \n" // clear flags
                "mov  %[ret], #1     \n"
                "ldr  %[val], %[adr] \n"
                "b.ne 1f             \n"
                "mov  %[ret], xzr    \n"
                "1:                  \n"

                : [val] "=r" (v), [ret] "=&r" (ret)
                : [adr] "m" (*address)
                : "cc");
  return ret;
}

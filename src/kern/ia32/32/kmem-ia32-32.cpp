IMPLEMENTATION [ia32]:

PRIVATE static inline FIASCO_INIT_CPU
void
Kmem::init_cpu_arch(Cpu &cpu, Lockless_alloc *cpu_mem)
{
  // allocate the task segment for the double fault handler
  cpu.init_tss_dbf((Address)cpu_mem->alloc<Tss>(1, Order(4)),
                   Mem_layout::pmem_to_phys(Kmem::dir()));

  cpu.init_sysenter();
}

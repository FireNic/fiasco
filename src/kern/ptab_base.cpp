INTERFACE:

//#include <cstdio>
#include <cxx/type_traits>

namespace Ptab
{

  struct Null_alloc
  {
    static void *alloc(Bytes) { return 0; }
    static void free(void *) {}
    static bool valid() { return false; }
    static unsigned to_phys(void *) { return 0; }
  };

  template< typename _Head, typename _Tail >
  struct List
  {
    typedef _Head Head;
    typedef _Tail Tail;
  };

  template< typename ...T >
  struct Tupel;

  template< typename T >
  struct Tupel<T>;

  template< typename H, typename T >
  struct Tupel<H, T> { typedef Ptab::List<H, T> List; };

  template<typename T1, typename T2, typename T3, typename ...X>
  struct Tupel<T1, T2, T3, X...>
  { typedef Ptab::List<T1, typename Tupel<T2, T3, X...>::List > List; };

  template< typename _T >
  struct Level
  {
    typedef _T Traits;
    enum { Max_level = 0 };

    static constexpr unsigned shift(unsigned)
    { return Traits::Shift; }

    static constexpr unsigned size(unsigned)
    { return Traits::Size; }

    static constexpr unsigned long length(unsigned)
    { return 1UL << Traits::Size; }

    static constexpr Address index(unsigned /*level*/, Address addr)
    { return (addr >> Traits::Shift) & ((1UL << Traits::Size)-1); }

    static constexpr unsigned entry_size(unsigned)
    { return sizeof(typename Traits::Entry); }

    static constexpr unsigned may_be_leaf(unsigned)
    { return Traits::May_be_leaf; }

    static constexpr unsigned lower_bound_level(unsigned, unsigned level = 0)
    { return level; }
  };

  template< typename _Head, typename _Tail >
  struct Level< List<_Head, _Tail> >
  {
    typedef Level<_Tail> Next_level;
    typedef _Head Traits;
    enum { Max_level = Next_level::Max_level + 1 };

    static constexpr unsigned shift(unsigned level)
    {
      return (!level)
        ? (unsigned)Traits::Shift
        : Next_level::shift(level - 1);
    }

    static constexpr unsigned size(unsigned level)
    {
      return (!level)
        ? (unsigned)Traits::Size
        : Next_level::size(level - 1);
    }

    static constexpr unsigned long length(unsigned level)
    {
      return (!level)
        ? (1UL << Traits::Size)
        : Next_level::length(level - 1);
    }

    static constexpr Address index(unsigned level, Address addr)
    {
      return (!level)
        ? (addr >> Traits::Shift) & ((1UL << Traits::Size)-1)
        : Next_level::index(level - 1, addr);
    }

    static constexpr unsigned entry_size(unsigned level)
    {
      return (!level)
        ? sizeof(typename Traits::Entry)
        : Next_level::entry_size(level - 1);
    }

    static constexpr bool may_be_leaf(unsigned level)
    {
      return (!level)
        ? (bool)Traits::May_be_leaf
        : Next_level::may_be_leaf(level - 1);
    }

    static constexpr unsigned
    lower_bound_level(unsigned max_shift, unsigned level = 0)
    {
      return (max_shift >= Traits::Shift)
        ? level
        : Next_level::lower_bound_level(max_shift, level + 1);
    }
  };

  template< typename _Traits >
  struct Entry_vec
  {
    typedef typename _Traits::Entry Entry;
    enum
    {
      Length = 1UL << _Traits::Size,
      Size   = _Traits::Size,
      Mask   = _Traits::Mask,
      Shift  = _Traits::Shift,
    };


    Entry _e[Length];

    static unsigned idx(Address virt)
    {
      if (Mask)
	return cxx::get_lsb(virt >> Shift, (Address)Size);
      else
	return (virt >> Shift);
    }

    Entry &operator [] (unsigned idx) { return _e[idx]; }
    Entry const &operator [] (unsigned idx) const { return _e[idx]; }

    template<typename PTE_PTR>
    void clear(unsigned level, bool force_write_back)
    {
      for (unsigned i=0; i < Length; ++i)
        PTE_PTR(&_e[i], level).clear();

      if (force_write_back)
        PTE_PTR::write_back(&_e[0], &_e[Length]);
    }
  };


  template< typename _Last, typename PTE_PTR, int DEPTH = 0 >
  class Walk
  {
  public:
    enum { Max_depth = 0 };
    enum { Depth = DEPTH };
    typedef typename _Last::Entry Entry;
    typedef _Last Traits;

  private:
    typedef Walk<_Last, PTE_PTR, DEPTH> This;
    typedef Entry_vec<Traits> Vec;
    Vec _e;

  public:
    void clear(bool force_write_back)
    { _e.template clear<PTE_PTR>(Depth, force_write_back); }

    template< typename _Alloc, typename MEM >
    PTE_PTR walk(Address virt, unsigned, bool, _Alloc &&, MEM &&)
    { return PTE_PTR(&_e[Vec::idx(virt)], Depth); }

    template< typename MEM >
    void unmap(Address &start, unsigned long &size, unsigned, bool force_write_back, MEM &&)
    {
      unsigned idx = Vec::idx(start);
      unsigned cnt = size >> Traits::Shift;
      if (cnt + idx > Vec::Length)
        cnt = Vec::Length - idx;
      unsigned const e = idx + cnt;

      for (unsigned i = idx; i != e; ++i)
        PTE_PTR(&_e[i], Depth).clear();

      if (force_write_back)
        PTE_PTR::write_back(&_e[idx], &_e[e]);

      start += (unsigned long)cnt << Traits::Shift;
      size  -= (unsigned long)cnt << Traits::Shift;
    }

    template< typename _Alloc, typename MEM >
    void map(Address &phys, Address &virt, unsigned long &size,
             unsigned long attr, unsigned, bool force_write_back,
             _Alloc &&, MEM &&)
    {
      unsigned idx = Vec::idx(virt);
      unsigned cnt = size >> Traits::Shift;
      if (cnt + idx > Vec::Length)
        cnt = Vec::Length - idx;
      unsigned const e = idx + cnt;

      for (unsigned i = idx; i != e; ++i, phys += (1ULL << (Traits::Shift + Traits::Base_shift)))
        PTE_PTR(&_e[i], Depth).set_page(phys, attr);

      if (force_write_back)
        PTE_PTR::write_back(&_e[idx], &_e[e]);

      virt += (unsigned long)cnt << Traits::Shift;
      size -= (unsigned long)cnt << Traits::Shift;
    }

    template< typename _Alloc, typename MEM >
    void destroy(Address, Address, unsigned, unsigned, _Alloc &&, MEM &&)
    {}

    template< typename _Alloc, typename MEM >
    int sync(Address &l_addr, This const &_r, Address &r_addr,
             Address &size, unsigned, bool force_write_back, _Alloc &&, MEM &&)
    {
      unsigned count = size >> Traits::Shift;
      unsigned const l = Vec::idx(l_addr);
      unsigned const r = Vec::idx(r_addr);
      unsigned const m = l > r ? l : r;

      if (m + count >= Vec::Length)
        count = Vec::Length - m;

      Entry *le = &_e[l];
      Entry const *re = &_r._e[r];

      bool need_flush = false;

      for (unsigned n = count; n > 0; --n)
	{
	  if (PTE_PTR(&le[n-1], Depth).is_valid())
	    need_flush = true;
#if 0
	  // This loop seems unnecessary, but remote_update is also used for
	  // updating the long IPC window.
	  // Now consider following scenario with super pages:
	  // Sender A makes long IPC to receiver B.
	  // A setups the IPC window by reading the pagedir slot from B in an 
	  // temporary register. Now the sender is preempted by C. Then C unmaps 
	  // the corresponding super page from B. C switch to A back, using 
	  // switch_to, which clears the IPC window pde slots from A. BUT then A 
	  // write the  content of the temporary register, which contain the now 
	  // invalid pde slot, in his own page directory and starts the long IPC.
	  // Because no pagefault will happen, A will write to now invalid memory.
	  // So we compare after storing the pde slot, if the copy is still
	  // valid. And this solution is much faster than grabbing the cpu lock,
	  // when updating the ipc window.h 
	  for (;;)
	    {
	      typename Traits::Raw const volatile *rr
		= reinterpret_cast<typename Traits::Raw const *>(re + n - 1);
	      le[n - 1] = *(Entry *)rr;
	      if (EXPECT_TRUE(le[n - 1].raw() == *rr))
		break;
	    }
#endif
          le[n - 1] = re[n - 1];
        }

      if (force_write_back)
        PTE_PTR::write_back(&le[0], &le[count]);

      l_addr += (unsigned long)count << Traits::Shift;
      r_addr += (unsigned long)count << Traits::Shift;
      size -= (unsigned long)count << Traits::Shift;
      return need_flush;
    }
  };



  template< typename _Head, typename _Tail, typename PTE_PTR, int DEPTH >
  class Walk <List <_Head,_Tail>, PTE_PTR, DEPTH >
  {
  public:
    typedef Walk<_Tail, PTE_PTR, DEPTH + 1> Next;
    typedef typename _Head::Entry Entry;
    typedef _Head Traits;

    enum { Max_depth = Next::Max_depth + 1 };
    enum { Depth = DEPTH };

  private:
    typedef Walk<_Head, PTE_PTR, DEPTH> This;
    typedef Walk< List< _Head, _Tail >, PTE_PTR, DEPTH> This2;
    typedef Entry_vec<_Head> Vec;
    Vec _e;

    template< typename _Alloc >
    Next *alloc_next(PTE_PTR e, _Alloc &&a, bool force_write_back)
    {
      Next *n = (Next*)a.alloc(Bytes(sizeof(Next)));
      if (EXPECT_FALSE(!n))
        return 0;

      n->clear(force_write_back);
      e.set_next_level(a.to_phys(n));
      e.write_back_if(force_write_back);

      return n;
    }

  public:
    void clear(bool force_write_back)
    { _e.template clear<PTE_PTR>(Depth, force_write_back); }

    template< typename _Alloc, typename MEM >
    PTE_PTR walk(Address virt, unsigned level, bool force_write_back, _Alloc &&alloc, MEM &&mem)
    {
      PTE_PTR e(&_e[Vec::idx(virt)], Depth);

      if (!level)
        return e;
      else if (!e.is_valid())
        {
          Next *n;
          if (alloc.valid() && (n = alloc_next(e, alloc, force_write_back)))
            return n->walk(virt, level - 1, force_write_back,
                           cxx::forward<_Alloc>(alloc),
                           cxx::forward<MEM>(mem));
          else
            return e;
        }
      else if (e.is_leaf())
        return e;
      else
        {
          Next *n = (Next*)mem.phys_to_pmem(e.next_level());
          return n->walk(virt, level - 1, force_write_back,
                         cxx::forward<_Alloc>(alloc),
                         cxx::forward<MEM>(mem));
        }
    }

    template< typename MEM >
    void unmap(Address &start, unsigned long &size, unsigned level,
               bool force_write_back, MEM &&mem)
    {
      if (!level)
        {
          reinterpret_cast<This*>(this)->unmap(start, size, 0,
                                               force_write_back,
                                               cxx::forward<MEM>(mem));
          return;
        }

      while (size)
        {
          PTE_PTR e(&_e[Vec::idx(start)], Depth);

          if (!e.is_valid() || e.is_leaf())
            continue;

          Next *n = (Next*)mem.phys_to_pmem(e.next_level());
          n->unmap(start, size, level - 1, force_write_back,
                   cxx::forward<MEM>(mem));
        }
    }

    template< typename _Alloc, typename MEM >
    void map(Address &phys, Address &virt, unsigned long &size,
             unsigned long attr, unsigned level, bool force_write_back,
             _Alloc &&alloc, MEM &&mem)
    {
      if (!level)
        {
          reinterpret_cast<This*>(this)->map(phys, virt, size, attr, 0,
                                             force_write_back,
                                             cxx::forward<_Alloc>(alloc),
                                             cxx::forward<MEM>(mem));
          return;
        }

      while (size)
        {
          PTE_PTR e(&_e[Vec::idx(virt)], Depth);
          Next *n;
          if (!e.is_valid())
            {
              if (alloc.valid() && (n = alloc_next(e, alloc, force_write_back)))
                n->map(phys, virt, size, attr, level - 1,
                       force_write_back, alloc, mem);

              continue;
            }

          if (_Head::May_be_leaf && e.is_leaf())
            continue;

          n = (Next*)mem.phys_to_pmem(e.next_level());
          n->map(phys, virt, size, attr, level - 1, force_write_back, alloc, mem);
        }
    }

    template< typename _Alloc, typename MEM >
    void destroy(Address start, Address end,
                 unsigned start_level, unsigned end_level,
                 _Alloc &&alloc, MEM &&mem)
    {
      //printf("destroy: %*.s%lx-%lx lvl=%d:%d depth=%d\n", Depth*2, "            ", start, end, start_level, end_level, Depth);
      if (!alloc.valid() || Depth >= end_level)
        return;

      unsigned idx_start = Vec::idx(start);
      unsigned idx_end = Vec::idx(end) + 1;
      //printf("destroy: %*.sidx: %d:%d\n", Depth*2, "            ", idx_start, idx_end);

      for (unsigned idx = idx_start; idx < idx_end; ++idx)
        {
          PTE_PTR e(&_e[idx], Depth);
          if (!e.is_valid() || (_Head::May_be_leaf && e.is_leaf()))
            continue;

          Next *n = (Next*)mem.phys_to_pmem(e.next_level());
          if (Depth < end_level)
            n->destroy(idx > idx_start ? 0 : start,
                       idx + 1 < idx_end ? (1UL << Traits::Shift)-1 : end,
                       start_level, end_level, alloc, mem);
          if (Depth >= start_level)
            {
              //printf("destroy: %*.sfree: %p: %p(%zd)\n", Depth*2, "            ", this, n, sizeof(Next));
              alloc.free(n, Bytes(sizeof(Next)));
            }
        }
    }

    template< typename _Alloc, typename MEM >
    int sync(Address &l_a, This2 const &_r, Address &r_a,
             Address &size, unsigned level, bool force_write_back,
             _Alloc &&alloc, MEM &&mem)
    {
      if (!level)
        return reinterpret_cast<This*>(this)
          ->sync(l_a, reinterpret_cast<This const &>(_r), r_a, size, 0,
                 force_write_back, cxx::forward<_Alloc>(alloc),
                 cxx::forward<MEM>(mem));

      unsigned count = size >> Traits::Shift;
        {
          unsigned const lx = Vec::idx(l_a);
          unsigned const rx = Vec::idx(r_a);
          unsigned const mx = lx > rx ? lx : rx;
          if (mx + count >= Vec::Length)
            count = Vec::Length - mx;
        }

      bool need_flush = false;

      for (unsigned i = count; size && i > 0; --i) //while (size)
        {
          PTE_PTR l(&_e[Vec::idx(l_a)], Depth);
          PTE_PTR r(const_cast<Entry *>(&_r._e[Vec::idx(r_a)]), Depth);
          Next *n = 0;
          if (!r.is_valid())
            {
              l_a += 1UL << Traits::Shift;
              r_a += 1UL << Traits::Shift;
              if (size > 1UL << Traits::Shift)
                {
                  size -= 1UL << Traits::Shift;
                  continue;
                }
              break;
            }

          if (!l.is_valid())
            {
              if (!alloc.valid() || !(n = alloc_next(l, alloc, force_write_back)))
                return -1;
            }
          else
            n = (Next*)mem.phys_to_pmem(l.next_level());

          Next *rn = (Next*)mem.phys_to_pmem(r.next_level());

          int err = n->sync(l_a, *rn, r_a, size, level - 1, force_write_back, alloc, mem);
          if (err > 0)
            need_flush = true;

          if (err < 0)
            return err;
        }

      return need_flush;
    }

  };

  template
  <
    typename _Entry,
    unsigned _Shift,
    unsigned _Size,
    bool _May_be_leaf,
    bool _Mask = true,
    unsigned _Base_shift = 0
  >
  struct Traits
  {
    typedef _Entry Entry;

    enum
    {
      May_be_leaf = _May_be_leaf,
      Shift = _Shift,
      Size = _Size,
      Mask = _Mask,
      Base_shift = _Base_shift
    };
  };

  template< typename _T, unsigned _Shift >
  struct Shift
  {
    typedef _T Orig_list;
    typedef Ptab::Traits
      < typename _T::Entry,
        _T::Shift - _Shift,
        _T::Size,
        _T::May_be_leaf,
        _T::Mask,
        _T::Base_shift + _Shift
      > List;
  };

  template< typename _Head, typename _Tail, unsigned _Shift >
  struct Shift< List<_Head, _Tail>, _Shift >
  {
    typedef Ptab::List<_Head, _Tail> Orig_list;
    typedef Ptab::List
    <
      typename Shift<_Head, _Shift>::List,
      typename Shift<_Tail, _Shift>::List
    > List;
  };

  struct Address_wrap
  {
    enum { Shift = 0 };
    typedef Address Value_type;
    static Address val(Address a) { return a; }
  };

  template< typename N, int SHIFT >
  struct Page_addr_wrap
  {
    enum { Shift = SHIFT };
    typedef N Value_type;
    static typename N::Value val(N a)
    { return cxx::int_value<N>(a); }

    static typename Value_type::Diff_type::Value
    val(typename Value_type::Diff_type a)
    { return cxx::int_value<typename Value_type::Diff_type>(a); }
  };

  template
  <
    typename PTE_PTR,
    typename _Traits,
    typename _Addr,
    typename MEM_DFLT
  >
  class Base
  {
  public:
    typedef typename _Addr::Value_type Va;
    typedef typename _Addr::Value_type::Diff_type Vs;
    typedef _Traits Traits;
    typedef PTE_PTR Pte_ptr;
    typedef _Addr Addr;
    typedef MEM_DFLT Mem_default;
    typedef typename _Traits::Head L0;

    enum
    {
      Base_shift = L0::Base_shift,
    };

  private:
    typedef Ptab::Walk<_Traits, PTE_PTR> Walk;

  public:
    enum { Depth = Walk::Max_depth };

    typedef Level<Traits> Levels;

    static unsigned lsb_for_level(unsigned level)
    { return Levels::shift(level); }

    static unsigned page_order_for_level(unsigned level)
    { return Levels::shift(level) + Base_shift; }

    template< typename _Alloc, typename MEM = MEM_DFLT >
    PTE_PTR walk(Va virt, unsigned level, bool force_write_back, _Alloc &&alloc, MEM &&mem = MEM())
    { return _base.walk(_Addr::val(virt), level, force_write_back, cxx::forward<_Alloc>(alloc), cxx::forward<MEM>(mem)); }

    template< typename MEM = MEM_DFLT >
    PTE_PTR walk(Va virt, unsigned level = Depth, MEM &&mem = MEM()) const
    { return const_cast<Walk&>(_base).walk(_Addr::val(virt), level, false, Null_alloc(), cxx::forward<MEM>(mem)); }

    /**
     * Sync a range within this page table hierarchy from another
     * page table hierarchy.
     *
     * A page table hierarchy can be thought of as a tree that grows upwards:
     * - The root page table is below the first-level page tables.
     * - The second-level page tables are above the first-level page tables.
     * - ...
     *
     * After the sync all page tables above the given level are shared between
     * source and destination page table hierarchy, whereas all page tables at
     * or below the given level are allocated to each page table hierarchy
     * separately.
     *
     * Assuming a four-level page table, where level zero is the root page
     * table, and a given level of two:
     * - The third-level page tables are shared.
     * - The root, first-level and second-level page tables are not shared.
     *
     * \pre The sync range must not contain leaf pages below the given level.
     * In the case that this assumption does not apply, sync() exhibits
     * undefined behavior.
     *
     * \param l_addr The start address of the sync range in the destination
     *               page table.
     * \param _r The page table to sync from.
     * \param r_addr The start address of the sync range in the source
     *               page table.
     * \param size The size of the range to sync.
     * \param level The level to sync at.
     *
     * \retval -1 if page table allocation failed.
     * \retval  1 if a previously valid page table entry was changed
     *            during sync.
     * \retval  0 otherwise
     */
    template< typename OPTE_PTR, typename _Alloc = Null_alloc, typename MEM = MEM_DFLT >
    int sync(Va l_addr, Base<OPTE_PTR, _Traits, _Addr, MEM_DFLT> const *_r,
             Va r_addr, Vs size, unsigned level = Depth,
             bool force_write_back = false,
             _Alloc &&alloc = _Alloc(), MEM &&mem = MEM())
    {
      Address la = _Addr::val(l_addr);
      Address ra = _Addr::val(r_addr);
      Address sz = _Addr::val(size);
      return _base.sync(la, _r->_base,
                        ra, sz, level, force_write_back,
                        cxx::forward<_Alloc>(alloc),
                        cxx::forward<MEM>(mem));
    }

    void clear(bool force_write_back)
    { _base.clear(force_write_back); }

    template< typename MEM = MEM_DFLT >
    void unmap(Va virt, Vs size, unsigned level, bool force_write_back, MEM &&mem = MEM())
    {
      Address va = _Addr::val(virt);
      unsigned long sz = _Addr::val(size);
      _base.unmap(va, sz, level, force_write_back, cxx::forward<MEM>(mem));
    }

    template< typename _Alloc, typename MEM = MEM_DFLT >
    void map(Address phys, Va virt, Vs size, unsigned long attr,
             unsigned level, bool force_write_back,
             _Alloc &&alloc = _Alloc(), MEM &&mem = MEM())
    {
      Address va = _Addr::val(virt);
      unsigned long sz = _Addr::val(size);
      _base.map(phys, va, sz, attr, level, force_write_back, cxx::forward<_Alloc>(alloc),
                cxx::forward<MEM>(mem));
    }

    template< typename _Alloc, typename MEM = MEM_DFLT >
    void destroy(Va start, Va end, unsigned start_level, unsigned end_level,
                 _Alloc &&alloc = _Alloc(), MEM &&mem = MEM())
    {
      _base.destroy(_Addr::val(start), _Addr::val(end),
                    start_level, end_level, cxx::forward<_Alloc>(alloc),
                    cxx::forward<MEM>(mem));
    }

#if 0
    template< typename _New_alloc >
    Base<_Base_entry, _Traits, _New_alloc, _Addr> *alloc_cast()
    { return reinterpret_cast<Base<_Base_entry, _Traits, _New_alloc, _Addr> *>(this); }

    template< typename _New_alloc >
    Base<_Base_entry, _Traits, _New_alloc, _Addr> const *alloc_cast() const
    { return reinterpret_cast<Base<_Base_entry, _Traits, _New_alloc, _Addr> const *>(this); }
#endif

  private:
    Walk _base;
  };
};

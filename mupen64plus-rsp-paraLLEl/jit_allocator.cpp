#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#endif
#ifdef __APPLE__
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#endif
#include <limits>
#include <algorithm>

#include "jit_allocator.hpp"

static const JitExternalAllocator *s_ext_alloc = nullptr;

void SetJitExternalAllocator(const JitExternalAllocator *alloc)
{
	s_ext_alloc = alloc;
}

namespace RSP
{
namespace JIT
{

static bool use_dual_mapping()
{
	if (s_ext_alloc)
		return true;
#if defined(__APPLE__) && defined(__aarch64__)
	return true;
#else
	return false;
#endif
}
#ifdef IOS // iOS/tvOS is 64bit but does not allow an infinite amount of VA space
static constexpr bool huge_va = false;
#else
static constexpr bool huge_va = std::numeric_limits<size_t>::max() > 0x100000000ull;
#endif
// On 64-bit systems, we will never allocate more than one block, this is important since we must ensure that
// relative jumps are reachable in 32-bits.
// We won't actually allocate 1 GB on 64-bit, but just reserve VA space for it, which we have basically an infinite amount of.
static constexpr size_t block_size = huge_va ? (1024 * 1024 * 1024) : (2 * 1024 * 1024);
Allocator::~Allocator()
{
	for (auto &block : blocks)
	{
		if (s_ext_alloc)
		{
			s_ext_alloc->release(block.code, block.writable, block.size, s_ext_alloc->ctx);
			continue;
		}
#ifdef _WIN32
		VirtualFree(block.code, 0, MEM_RELEASE);
#else
#if defined(__APPLE__) && defined(__aarch64__)
		if (block.writable)
			vm_deallocate(mach_task_self(), (vm_address_t)block.writable, block.size);
#endif
		munmap(block.code, block.size);
#endif
	}
}

static size_t align_page(size_t offset)
{
#if defined(__APPLE__) && defined(__aarch64__)
	size_t pagesize = sysconf(_SC_PAGESIZE) - 1;
#else
	size_t pagesize = 4095;
#endif
	return (offset + pagesize) & ~size_t(pagesize);
}

static bool commit_read_write(void *ptr, size_t size)
{
	if (use_dual_mapping())
		return true; // Writable region is always R-W
#ifdef _WIN32
	return VirtualAlloc(ptr, size, MEM_COMMIT, PAGE_READWRITE) == ptr;
#else
	return mprotect(ptr, size, PROT_READ | PROT_WRITE) == 0;
#endif
}

static bool commit_execute(void *ptr, size_t size)
{
	if (use_dual_mapping())
		return true; // Executable region is always R-X
#ifdef _WIN32
	DWORD old_protect;
	return VirtualProtect(ptr, align_page(size), PAGE_EXECUTE, &old_protect) != 0;
#else
	return mprotect(ptr, size, PROT_EXEC) == 0;
#endif
}

bool Allocator::commit_code(void *code, size_t size)
{
#ifdef __APPLE__
	if (use_dual_mapping())
	{
		// Flush the entire page-aligned allocation, not just the code bytes.
		// Lightning places constant pools after the code within the allocation.
		size_t flush_size = align_page(size);
		void *rw = get_writable(code);
		sys_dcache_flush(rw, flush_size);
		sys_icache_invalidate(code, flush_size);
		return true;
	}
#endif
	return commit_execute(code, size);
}

void *Allocator::allocate_code(size_t size)
{
	size = align_page(size);
	if (blocks.empty())
		blocks.push_back(reserve_block(std::max(size, block_size)));

	auto *block = &blocks.back();
	if (!block->code)
		return nullptr;

	block->offset = align_page(block->offset);
	if (block->offset + size > block->size)
		block = nullptr;

	if (!block)
	{
		if (huge_va)
			abort();
		blocks.push_back(reserve_block(std::max(size, block_size)));
		block = &blocks.back();
	}

	if (!block || !block->code)
		return nullptr;

	size_t off = block->offset;
	block->offset += size;

	if (block->writable)
		return block->writable + off;

	void *ret = block->code + off;
	if (!commit_read_write(ret, size))
		return nullptr;
	return ret;
}

Allocator::Block Allocator::reserve_block(size_t size)
{
	Block block;
#ifdef _WIN32
	block.code = static_cast<uint8_t *>(VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_READWRITE));
	block.size = size;
	return block;
#else
	if (use_dual_mapping())
	{
		if (s_ext_alloc)
		{
			// External allocator (frontend-provided dual-mapped memory)
			void *writable = nullptr;
			block.code = static_cast<uint8_t *>(
				s_ext_alloc->reserve(size, &writable, s_ext_alloc->ctx));
			if (!block.code) return block;
			block.writable = static_cast<uint8_t *>(writable);
			block.size = size;
			return block;
		}

#if defined(__APPLE__) && defined(__aarch64__)
		// macOS ARM: mmap R-X, vm_remap for R-W mirror
		block.code = static_cast<uint8_t *>(mmap(nullptr, size, PROT_READ | PROT_EXEC,
		                                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
		if (block.code == MAP_FAILED) { block.code = nullptr; return block; }

		vm_address_t rw_region = 0;
		vm_prot_t cur_prot = 0, max_prot = 0;
		kern_return_t kr = vm_remap(mach_task_self(), &rw_region, size, 0,
			VM_FLAGS_ANYWHERE, mach_task_self(), (vm_address_t)block.code,
			false, &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
		if (kr != KERN_SUCCESS) { munmap(block.code, size); block.code = nullptr; return block; }
		block.writable = reinterpret_cast<uint8_t *>(rw_region);
		mprotect(block.writable, size, PROT_READ | PROT_WRITE);
		block.size = size;
		return block;
#endif
	}

	block.code = static_cast<uint8_t *>(mmap(nullptr, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE,
	                                         -1, 0));
	block.size = size;
	return block;
#endif
}

void *Allocator::get_writable(void *code) const
{
	for (auto &block : blocks)
	{
		if (block.writable && code >= block.code && code < block.code + block.size)
			return block.writable + (static_cast<uint8_t *>(code) - block.code);
	}
	return code; // Not dual-mapped, same pointer
}

void *Allocator::to_executable(void *writable) const
{
	for (auto &block : blocks)
	{
		if (block.writable && writable >= block.writable && writable < block.writable + block.size)
		{
			void *rx = block.code + (static_cast<uint8_t *>(writable) - block.writable);
			return rx;
		}
	}
	return writable;
}
}
}

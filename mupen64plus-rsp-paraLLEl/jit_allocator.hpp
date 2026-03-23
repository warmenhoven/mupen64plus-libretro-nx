#pragma once

#include <vector>
#include <stdint.h>
#include <stddef.h>

struct JitExternalAllocator
{
	void *(*reserve)(size_t size, void **writable, void *ctx);
	void (*release)(void *code, void *writable, size_t size, void *ctx);
	void *ctx;
};

void SetJitExternalAllocator(const JitExternalAllocator *alloc);

namespace RSP
{
namespace JIT
{
class Allocator
{
public:
	Allocator() = default;
	~Allocator();
	void operator=(const Allocator &) = delete;
	Allocator(const Allocator &) = delete;

	void *allocate_code(size_t size);
	bool commit_code(void *code, size_t size);

	// For dual-mapped platforms: convert between executable and writable addresses.
	void *get_writable(void *code) const;
	void *to_executable(void *writable) const;

private:
	struct Block
	{
		uint8_t *code = nullptr;
		uint8_t *writable = nullptr; // Non-null when dual-mapped
		size_t size = 0;
		size_t offset = 0;
	};
	std::vector<Block> blocks;

	static Block reserve_block(size_t size);
};
}
}

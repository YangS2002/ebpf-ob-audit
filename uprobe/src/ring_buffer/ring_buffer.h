// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __VARLEN_RING_BUFFER_H
#define __VARLEN_RING_BUFFER_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>
/* 变长环形缓冲区。
 *
 * 预分配一整块 capacity 字节的内存，按事件头部给出的总大小切一段出来。
 * 写指针 head_ 顺序向前推进，到尾部不够放时回绕到 0。
 * 每次分配用 event_seq 作 key，unordered_map 把 key 映射到该段的 offset/length。
 * 分配前检查目标区间是否与仍在用的段重叠；重叠或空间不足则分配失败，
 * 不驱逐已有数据（调用方负责在合并完成后 erase 释放）。 */
template <typename Key>
class VarlenRingBuffer {
public:
	explicit VarlenRingBuffer(size_t capacity)
		: buffer_(static_cast<char *>(malloc(capacity))), capacity_(capacity)
	{
	}

	VarlenRingBuffer(const VarlenRingBuffer &) = delete;
	VarlenRingBuffer &operator=(const VarlenRingBuffer &) = delete;

	~VarlenRingBuffer()
	{
		free(buffer_);
	}

	bool valid() const { return buffer_ != nullptr; }

	/* 按 length 在环形缓冲区中分配一段，返回段起点；不够则返回 nullptr。 */
	void *allocate(const Key &key, size_t length)
	{
		if (!valid())
			return nullptr;
		length = align8(length);
		if (length == 0 || length > capacity_)
			return nullptr;

		erase(key);

		size_t start = head_;
		if (start + length > capacity_)
			start = 0;
		if (overlaps_used(start, length))
			return nullptr;

		index_[key] = Segment{start, length};
		head_ = start + length;
		if (head_ == capacity_)
			head_ = 0;
		used_bytes_ += length;
		return buffer_ + start;
	}

	void *find(const Key &key)
	{
		auto it = index_.find(key);
		return it == index_.end() ? nullptr : buffer_ + it->second.offset;
	}

	const void *find(const Key &key) const
	{
		auto it = index_.find(key);
		return it == index_.end() ? nullptr : buffer_ + it->second.offset;
	}

	/* 把 data 拷进 key 段的 seg_offset 处（段内绝对偏移，由调用方按 layout 算）。
	 * 段是连续内存，无需处理回绕；越界或 key 不存在返回 false。 */
	bool fill(const Key &key, size_t seg_offset, const void *data, size_t len)
	{
		auto it = index_.find(key);
		if (it == index_.end())
			return false;
		if (seg_offset + len > it->second.length)
			return false;
		if (len != 0)
			memcpy(buffer_ + it->second.offset + seg_offset, data, len);
		return true;
	}

	bool erase(const Key &key)
	{
		auto it = index_.find(key);
		if (it == index_.end())
			return false;
		used_bytes_ -= it->second.length;
		index_.erase(it);
		return true;
	}

	size_t capacity() const { return capacity_; }
	size_t used_bytes() const { return used_bytes_; }
	size_t size() const { return index_.size(); }

private:
	struct Segment {
		size_t offset;
		size_t length;
	};

	static size_t align8(size_t value)
	{
		return (value + 7) & ~static_cast<size_t>(7);
	}

	bool overlaps_used(size_t offset, size_t length) const
	{
		size_t end = offset + length;
		for (const auto &item : index_) {
			size_t seg_start = item.second.offset;
			size_t seg_end = seg_start + item.second.length;
			if (seg_start < end && seg_end > offset)
				return true;
		}
		return false;
	}

	char *buffer_ = nullptr;
	size_t capacity_ = 0;
	size_t head_ = 0;
	size_t used_bytes_ = 0;
	std::unordered_map<Key, Segment> index_;
};

#endif

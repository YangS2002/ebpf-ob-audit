// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// VarlenRingBuffer 单元测试。
//
// 编译运行： make test
// 或： g++ -std=c++17 -I../../src test_ring_buffer.cpp -lgtest -lgtest_main -pthread -o t && ./t
#include "ring_buffer/ring_buffer.h"

#include <cstring>
#include <string>

#include <gtest/gtest.h>

namespace {

using RB = VarlenRingBuffer<unsigned long long>;

TEST(VarlenRingBuffer, Construct)
{
	RB rb(128);
	EXPECT_TRUE(rb.valid());
	EXPECT_EQ(rb.capacity(), 128u);
	EXPECT_EQ(rb.used_bytes(), 0u);
	EXPECT_EQ(rb.size(), 0u);
}

TEST(VarlenRingBuffer, AllocateBasic)
{
	RB rb(128);
	void *p = rb.allocate(1, 10);
	ASSERT_NE(p, nullptr);
	EXPECT_EQ(rb.size(), 1u);
	// 10 对齐到 16。
	EXPECT_EQ(rb.used_bytes(), 16u);
	EXPECT_EQ(rb.find(1), p);
}

TEST(VarlenRingBuffer, AllocateAlignment)
{
	RB rb(256);
	rb.allocate(1, 1);
	EXPECT_EQ(rb.used_bytes(), 8u);
	rb.allocate(2, 8);
	EXPECT_EQ(rb.used_bytes(), 16u);
	rb.allocate(3, 9);
	EXPECT_EQ(rb.used_bytes(), 32u);
}

TEST(VarlenRingBuffer, AllocateZeroFails)
{
	RB rb(64);
	EXPECT_EQ(rb.allocate(1, 0), nullptr);
	EXPECT_EQ(rb.size(), 0u);
}

TEST(VarlenRingBuffer, AllocateTooLargeFails)
{
	RB rb(64);
	EXPECT_EQ(rb.allocate(1, 65), nullptr);
	EXPECT_EQ(rb.size(), 0u);
}

TEST(VarlenRingBuffer, AllocateExactCapacity)
{
	RB rb(64);
	void *p = rb.allocate(1, 64);
	ASSERT_NE(p, nullptr);
	EXPECT_EQ(rb.used_bytes(), 64u);
}

// 空间不足时分配失败，不驱逐已有数据。
TEST(VarlenRingBuffer, FullDoesNotEvict)
{
	RB rb(64);
	ASSERT_NE(rb.allocate(1, 32), nullptr);
	ASSERT_NE(rb.allocate(2, 32), nullptr);
	EXPECT_EQ(rb.size(), 2u);
	// 满了，新分配失败。
	EXPECT_EQ(rb.allocate(3, 8), nullptr);
	EXPECT_EQ(rb.size(), 2u);
	// 已有数据仍在。
	EXPECT_NE(rb.find(1), nullptr);
	EXPECT_NE(rb.find(2), nullptr);
}

// erase 后空间释放，head 回绕复用尾部。
TEST(VarlenRingBuffer, WrapAroundAfterErase)
{
	RB rb(64);
	rb.allocate(1, 32); // [0,32)
	rb.allocate(2, 32); // [32,64) head 回绕到 0
	EXPECT_EQ(rb.used_bytes(), 64u);
	rb.erase(1);        // 释放 [0,32)
	EXPECT_EQ(rb.used_bytes(), 32u);
	// head 已在 0，此处分配落在 [0,32)，不与 [32,64) 重叠。
	void *p = rb.allocate(3, 32);
	ASSERT_NE(p, nullptr);
	EXPECT_EQ(rb.used_bytes(), 64u);
	EXPECT_EQ(rb.size(), 2u);
}

// 尾部空间不足时整段落到 offset 0，不跨界切分。
TEST(VarlenRingBuffer, WrapWholeSegmentContiguous)
{
	RB rb(64);
	rb.allocate(1, 40); // [0,40) head=40
	// 尾部只剩 24 < 32，整段回绕到 0，但 [0,40) 仍占用 → 重叠 → 失败。
	EXPECT_EQ(rb.allocate(2, 32), nullptr);
	rb.erase(1);
	void *p = rb.allocate(2, 32);
	ASSERT_NE(p, nullptr);
}

TEST(VarlenRingBuffer, FindMissingKey)
{
	RB rb(64);
	EXPECT_EQ(rb.find(99), nullptr);
}

TEST(VarlenRingBuffer, AllocateSameKeyReplaces)
{
	RB rb(128);
	void *p1 = rb.allocate(1, 16);
	ASSERT_NE(p1, nullptr);
	EXPECT_EQ(rb.used_bytes(), 16u);
	// 同 key 再分配，先 erase 旧段。
	void *p2 = rb.allocate(1, 24);
	ASSERT_NE(p2, nullptr);
	EXPECT_EQ(rb.size(), 1u);
	EXPECT_EQ(rb.used_bytes(), 24u);
}

TEST(VarlenRingBuffer, FillAndRead)
{
	RB rb(128);
	rb.allocate(1, 32);
	EXPECT_TRUE(rb.fill(1, 0, "hello", 5));
	EXPECT_TRUE(rb.fill(1, 5, "world", 5));
	char *p = static_cast<char *>(rb.find(1));
	ASSERT_NE(p, nullptr);
	EXPECT_EQ(std::string(p, 10), "helloworld");
}

// 定点写：可乱序写到指定 offset。
TEST(VarlenRingBuffer, FillOutOfOrder)
{
	RB rb(128);
	rb.allocate(1, 16);
	EXPECT_TRUE(rb.fill(1, 8, "world!!!", 8));
	EXPECT_TRUE(rb.fill(1, 0, "hello!!!", 8));
	EXPECT_EQ(std::string(static_cast<char *>(rb.find(1)), 16), "hello!!!world!!!");
}

TEST(VarlenRingBuffer, FillOutOfBoundsFails)
{
	RB rb(128);
	rb.allocate(1, 16); // 对齐后 16
	EXPECT_FALSE(rb.fill(1, 10, "toolong!!", 9));
	EXPECT_TRUE(rb.fill(1, 8, "12345678", 8));
}

TEST(VarlenRingBuffer, FillMissingKeyFails)
{
	RB rb(128);
	EXPECT_FALSE(rb.fill(42, 0, "x", 1));
}

TEST(VarlenRingBuffer, FillZeroLenOk)
{
	RB rb(64);
	rb.allocate(1, 8);
	EXPECT_TRUE(rb.fill(1, 0, nullptr, 0));
	EXPECT_TRUE(rb.fill(1, 8, nullptr, 0));
}

TEST(VarlenRingBuffer, EraseReleases)
{
	RB rb(64);
	rb.allocate(1, 16);
	EXPECT_TRUE(rb.erase(1));
	EXPECT_EQ(rb.used_bytes(), 0u);
	EXPECT_EQ(rb.size(), 0u);
	EXPECT_EQ(rb.find(1), nullptr);
}

TEST(VarlenRingBuffer, EraseMissingKeyFails)
{
	RB rb(64);
	EXPECT_FALSE(rb.erase(7));
}

// 多段填充互不干扰。
TEST(VarlenRingBuffer, MultipleSegmentsIsolated)
{
	RB rb(256);
	rb.allocate(1, 16);
	rb.allocate(2, 16);
	rb.fill(1, 0, "AAAAAAAA", 8);
	rb.fill(2, 0, "BBBBBBBB", 8);
	EXPECT_EQ(std::string(static_cast<char *>(rb.find(1)), 8), "AAAAAAAA");
	EXPECT_EQ(std::string(static_cast<char *>(rb.find(2)), 8), "BBBBBBBB");
}

// 分片乱序按 offset 填入，合并出连续数据。
TEST(VarlenRingBuffer, FragmentedFillMerge)
{
	RB rb(1024);
	const size_t total = 300;
	ASSERT_NE(rb.allocate(1, total), nullptr);
	std::string expect(total, 0);
	for (size_t i = 0; i < total; i++)
		expect[i] = static_cast<char>('a' + i % 26);
	// 先填后半段，再填前半段，模拟乱序分片。
	EXPECT_TRUE(rb.fill(1, 150, expect.data() + 150, 150));
	EXPECT_TRUE(rb.fill(1, 0, expect.data(), 150));
	EXPECT_EQ(std::string(static_cast<char *>(rb.find(1)), total), expect);
}

} // namespace

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "bounded_mpmc_queue.h"

#include <atomic>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

TEST(BoundedMpmcQueueTest, MultipleProducersConsumers)
{
	BoundedMpmcQueue<int> queue(8);
	std::atomic<int> produced{0};
	std::atomic<int> consumed{0};
	std::vector<std::thread> producers;
	std::vector<std::thread> consumers;

	for (int i = 0; i < 4; i++) {
		producers.emplace_back([&] {
			for (int j = 0; j < 100; j++) {
				int value = produced.fetch_add(1);
				EXPECT_TRUE(queue.push(value));
			}
		});
	}
	for (int i = 0; i < 4; i++) {
		consumers.emplace_back([&] {
			int value = 0;
			while (queue.pop(&value))
				consumed.fetch_add(1);
		});
	}
	for (auto &thread : producers)
		thread.join();
	queue.close();
	for (auto &thread : consumers)
		thread.join();

	EXPECT_EQ(produced.load(), 400);
	EXPECT_EQ(consumed.load(), 400);
}

TEST(BoundedMpmcQueueTest, CloseReleasesWaiters)
{
	BoundedMpmcQueue<int> queue(1);
	int value = 0;
	std::thread consumer([&] {
		EXPECT_FALSE(queue.pop(&value));
	});
	queue.close();
	consumer.join();
	EXPECT_FALSE(queue.push(1));
}

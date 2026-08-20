// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef BOUNDED_MPMC_QUEUE_H
#define BOUNDED_MPMC_QUEUE_H

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>

template <typename T>
class BoundedMpmcQueue {
public:
	explicit BoundedMpmcQueue(std::size_t capacity)
		: capacity_(capacity ? capacity : 1)
	{
	}

	BoundedMpmcQueue(const BoundedMpmcQueue &) = delete;
	BoundedMpmcQueue &operator=(const BoundedMpmcQueue &) = delete;

	bool push(T item)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		not_full_.wait(lock, [this] { return closed_ || queue_.size() < capacity_; });
		if (closed_)
			return false;
		queue_.push_back(std::move(item));
		not_empty_.notify_one();
		return true;
	}

	// Non-blocking enqueue: returns false immediately if the queue is full or closed.
	bool try_push(T item)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		if (closed_ || queue_.size() >= capacity_)
			return false;
		queue_.push_back(std::move(item));
		not_empty_.notify_one();
		return true;
	}

	bool pop(T *item)
	{
		if (!item)
			return false;
		std::unique_lock<std::mutex> lock(mutex_);
		not_empty_.wait(lock, [this] { return closed_ || !queue_.empty(); });
		if (queue_.empty())
			return false;
		*item = std::move(queue_.front());
		queue_.pop_front();
		not_full_.notify_one();
		return true;
	}

	void close()
	{
		{
			std::lock_guard<std::mutex> lock(mutex_);
			closed_ = true;
		}
		not_empty_.notify_all();
		not_full_.notify_all();
	}

	bool closed() const
	{
		std::lock_guard<std::mutex> lock(mutex_);
		return closed_;
	}

	std::size_t size() const
	{
		std::lock_guard<std::mutex> lock(mutex_);
		return queue_.size();
	}

private:
	const std::size_t capacity_;
	mutable std::mutex mutex_;
	std::condition_variable not_empty_;
	std::condition_variable not_full_;
	std::deque<T> queue_;
	bool closed_ = false;
};

#endif /* BOUNDED_MPMC_QUEUE_H */

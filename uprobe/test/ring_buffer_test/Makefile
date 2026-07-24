# VarlenRingBuffer 单元测试
CXX ?= g++
CXXFLAGS := -std=c++17 -Wall -Wextra -g -I../../src
LDLIBS := -lgtest -lgtest_main -pthread

TARGET := test_ring_buffer

$(TARGET): test_ring_buffer.cpp ../../src/ring_buffer/ring_buffer.h
	$(CXX) $(CXXFLAGS) $< $(LDLIBS) -o $@

.PHONY: test clean
test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

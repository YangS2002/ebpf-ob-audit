# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
SRC_DIR := src
TEST_DIR := test
TOOLS_DIR := tools
BINDIR := bin
APP := uprobe

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CXX ?= g++

LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
					 | sed 's/aarch64/arm64/' \
					 | sed 's/ppc64le/powerpc/' \
					 | sed 's/mips.*/mips/' \
					 | sed 's/arm.*/arm/' \
					 | sed 's/riscv64/riscv/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h
INCLUDES := -I$(OUTPUT) -I$(SRC_DIR) -I../libbpf/include/uapi -I$(dir $(VMLINUX))
CXXFLAGS := -g -Wall -std=c++17
PROTOC ?= protoc
GRPC_CPP_PLUGIN ?= $(shell command -v grpc_cpp_plugin 2>/dev/null || printf grpc_cpp_plugin)
GRPC_CXXFLAGS ?= $(shell pkg-config --cflags grpc++ protobuf 2>/dev/null)
GRPC_LDLIBS ?= $(shell pkg-config --libs grpc++ protobuf 2>/dev/null)
MONGO_CFLAGS ?= $(shell pkg-config --cflags libmongoc-1.0 libbson-1.0 2>/dev/null)
MONGO_LDLIBS ?= $(shell pkg-config --libs libmongoc-1.0 libbson-1.0 2>/dev/null)
GTEST_CXXFLAGS ?= $(shell pkg-config --cflags gtest 2>/dev/null)
GTEST_LDLIBS ?= $(shell pkg-config --libs gtest_main gtest 2>/dev/null || printf -- '-lgtest_main -lgtest -pthread')
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' \
		      "$(1)" \
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" \
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(BINDIR)/$(APP) $(BINDIR)/audit_collector

.PHONY: grpc
grpc: all

.PHONY: tools
tools: $(BINDIR)/read_events $(BINDIR)/adt_to_csv $(BINDIR)/check_audit_sql

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(BINDIR)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(BINDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		    INCLUDEDIR= LIBDIR= UAPIDIR= \
		    install

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

$(OUTPUT)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(LIBBPF_OBJ) $(wildcard $(SRC_DIR)/*.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -fno-stack-protector -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/$(APP).o: $(OUTPUT)/$(APP).skel.h

$(OUTPUT)/%.o: $(SRC_DIR)/%.cpp $(wildcard $(SRC_DIR)/*.h) $(OUTPUT)/audit_upload.grpc.pb.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) $(MONGO_CFLAGS) $(INCLUDES) -I$(OUTPUT) -c $(filter %.cpp,$^) -o $@

$(BINDIR)/$(APP): $(OUTPUT)/$(APP).o $(OUTPUT)/agent_logger.o $(OUTPUT)/audit_grpc_sender.o $(OUTPUT)/collector_resolver.o $(LIBBPF_OBJ) $(OUTPUT)/audit_upload.pb.o $(OUTPUT)/audit_upload.grpc.pb.o $(OUTPUT)/etcdserverpb/rpc.pb.o $(OUTPUT)/etcdserverpb/rpc.grpc.pb.o | $(OUTPUT) $(BINDIR)
	$(call msg,BINARY,$@)
	$(Q)$(CXX) $(CXXFLAGS) $^ $(ALL_LDFLAGS) $(GRPC_LDLIBS) -lelf -lz -o $@

$(OUTPUT)/audit_upload.pb.cc $(OUTPUT)/audit_upload.pb.h $(OUTPUT)/audit_upload.grpc.pb.cc $(OUTPUT)/audit_upload.grpc.pb.h: proto/audit_upload.proto | $(OUTPUT)
	$(call msg,PROTO,$<)
	$(Q)$(PROTOC) -Iproto --cpp_out=$(OUTPUT) --grpc_out=$(OUTPUT) --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $<

$(OUTPUT)/etcdserverpb/rpc.pb.cc $(OUTPUT)/etcdserverpb/rpc.pb.h $(OUTPUT)/etcdserverpb/rpc.grpc.pb.cc $(OUTPUT)/etcdserverpb/rpc.grpc.pb.h: proto/etcdserverpb/rpc.proto | $(OUTPUT)
	$(call msg,PROTO,$<)
	$(Q)mkdir -p $(OUTPUT)/etcdserverpb
	$(Q)$(PROTOC) -Iproto --cpp_out=$(OUTPUT) --grpc_out=$(OUTPUT) --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $<

$(OUTPUT)/audit_upload.pb.o: $(OUTPUT)/audit_upload.pb.cc $(OUTPUT)/audit_upload.pb.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) -I$(OUTPUT) -c $< -o $@

$(OUTPUT)/audit_upload.grpc.pb.o: $(OUTPUT)/audit_upload.grpc.pb.cc $(OUTPUT)/audit_upload.grpc.pb.h $(OUTPUT)/audit_upload.pb.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) -I$(OUTPUT) -c $< -o $@

$(OUTPUT)/etcdserverpb/rpc.pb.o: $(OUTPUT)/etcdserverpb/rpc.pb.cc $(OUTPUT)/etcdserverpb/rpc.pb.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) -I$(OUTPUT) -c $< -o $@

$(OUTPUT)/etcdserverpb/rpc.grpc.pb.o: $(OUTPUT)/etcdserverpb/rpc.grpc.pb.cc $(OUTPUT)/etcdserverpb/rpc.grpc.pb.h $(OUTPUT)/etcdserverpb/rpc.pb.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) -I$(OUTPUT) -c $< -o $@

$(OUTPUT)/collector_registry.o: $(SRC_DIR)/collector_registry.cpp $(SRC_DIR)/collector_registry.h $(OUTPUT)/etcdserverpb/rpc.grpc.pb.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) $(INCLUDES) -I$(OUTPUT) -c $< -o $@

$(OUTPUT)/collector_resolver.o: $(SRC_DIR)/collector_resolver.cpp $(SRC_DIR)/collector_resolver.h $(OUTPUT)/etcdserverpb/rpc.grpc.pb.h | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) $(INCLUDES) -I$(OUTPUT) -c $< -o $@

$(OUTPUT)/audit_collector.o: collector/audit_collector.cpp $(OUTPUT)/audit_upload.grpc.pb.h $(wildcard $(SRC_DIR)/*.h) | $(OUTPUT)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) -I$(SRC_DIR) -I$(OUTPUT) -c $< -o $@

$(BINDIR)/audit_collector: $(OUTPUT)/audit_collector.o $(OUTPUT)/collector_registry.o $(OUTPUT)/audit_event_parser.o $(OUTPUT)/mongodb_sink.o $(OUTPUT)/audit_upload.pb.o $(OUTPUT)/audit_upload.grpc.pb.o $(OUTPUT)/etcdserverpb/rpc.pb.o $(OUTPUT)/etcdserverpb/rpc.grpc.pb.o | $(BINDIR)
	$(call msg,BINARY,$@)
	$(Q)$(CXX) $(CXXFLAGS) $^ $(ALL_LDFLAGS) $(GRPC_LDLIBS) $(MONGO_LDLIBS) -o $@

.PHONY: collector-connection-test
collector-connection-test: $(BINDIR)/collector_connection_test

$(BINDIR)/collector_connection_test: $(TEST_DIR)/collector_connection_test.cpp $(OUTPUT)/etcdserverpb/rpc.grpc.pb.h $(OUTPUT)/etcdserverpb/rpc.pb.o $(OUTPUT)/etcdserverpb/rpc.grpc.pb.o | $(BINDIR)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GRPC_CXXFLAGS) -I$(OUTPUT) $< $(OUTPUT)/etcdserverpb/rpc.pb.o $(OUTPUT)/etcdserverpb/rpc.grpc.pb.o $(ALL_LDFLAGS) $(GRPC_LDLIBS) -o $@

.PHONY: event-size
event-size: $(BINDIR)/event_size

.PHONY: gtest-audit-e2e
gtest-audit-e2e: $(BINDIR)/audit_e2e_test

$(BINDIR)/event_size: $(TEST_DIR)/event_size.cpp $(wildcard $(SRC_DIR)/*.h) | $(BINDIR)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -I$(SRC_DIR) $< -o $@

$(BINDIR)/audit_e2e_test: $(TEST_DIR)/audit_e2e_main.cpp $(TEST_DIR)/audit_e2e_common.cpp $(TEST_DIR)/audit_e2e_test.cpp $(TEST_DIR)/audit_e2e_common.h $(wildcard $(SRC_DIR)/*.h) | $(BINDIR)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(GTEST_CXXFLAGS) -I$(SRC_DIR) -I$(TEST_DIR) $(TEST_DIR)/audit_e2e_main.cpp $(TEST_DIR)/audit_e2e_common.cpp $(TEST_DIR)/audit_e2e_test.cpp $(GTEST_LDLIBS) -o $@

$(BINDIR)/read_events: $(TOOLS_DIR)/read_events.cpp $(TOOLS_DIR)/audit_format.h $(wildcard $(SRC_DIR)/*.h) | $(BINDIR)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -I$(SRC_DIR) $< -o $@

$(BINDIR)/adt_to_csv: $(TOOLS_DIR)/adt_to_csv.cpp $(TOOLS_DIR)/audit_format.h $(wildcard $(SRC_DIR)/*.h) | $(BINDIR)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -I$(SRC_DIR) $< -o $@

$(BINDIR)/check_audit_sql: $(TOOLS_DIR)/check_audit_sql.cpp $(TOOLS_DIR)/audit_format.h $(wildcard $(SRC_DIR)/*.h) | $(BINDIR)
	$(call msg,CXX,$@)
	$(Q)$(CXX) $(CXXFLAGS) -I$(SRC_DIR) $< -o $@

.DELETE_ON_ERROR:
.SECONDARY:

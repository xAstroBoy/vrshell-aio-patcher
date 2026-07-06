LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
# ONE all-in-one library, named libquestctl_aio.so so it drops into the moonjump apk's existing
# DT_NEEDED slot (libshell UNTOUCHED). Merges every feature TU (each in src/merge/, wrapping a
# src/features/*.cpp). src/common holds shared headers (zygisk.hpp).
LOCAL_MODULE     := questctl_aio
# ALL-IN-ONE: one orchestrator ctor + three feature TUs, ALL compiled into the single
# libquestctl_aio.so (NO prebuilt .so pulled in). -DAIO_MERGE_BUILD compiles out each
# feature's private constructor so ONLY core/orchestrator.cpp drives them (fixes the
# merged build where two competing ctors dropped moonjump). --no-gc-sections so the
# orchestrator's referenced worker-entry symbols are never stripped.
LOCAL_SRC_FILES  := ../src/core/orchestrator.cpp \
                    ../src/merge/aio_tu.cpp ../src/merge/rendertrace_tu.cpp \
                    ../src/merge/player_tu.cpp ../src/merge/unlock_tu.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../src/common $(LOCAL_PATH)/../src/features $(LOCAL_PATH)/../src/core
LOCAL_CPPFLAGS   := -std=c++17 -fvisibility=hidden -fexceptions -frtti -Os -Wno-unused -DAIO_MERGE_BUILD
LOCAL_LDFLAGS    := -Wl,--no-gc-sections
LOCAL_LDLIBS     := -llog
include $(BUILD_SHARED_LIBRARY)

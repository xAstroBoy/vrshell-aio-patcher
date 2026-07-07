LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
# ONE Zygisk module (libvrshell_zygisk.so) that injects the ALL-IN-ONE VrShell patch into
# com.oculus.vrshell WITHOUT touching the APK. Reuses the exact feature TUs the DT_NEEDED build
# uses (each in src/merge/, wrapping a src/features/*.cpp) via -DAIO_MERGE_BUILD; the single
# Zygisk ModuleBase in src/core/zygisk_entry.cpp drives all three worker entries.
LOCAL_MODULE     := vrshell_zygisk
LOCAL_SRC_FILES  := ../src/core/zygisk_entry.cpp \
                    ../src/merge/aio_tu.cpp ../src/merge/rendertrace_tu.cpp \
                    ../src/merge/player_tu.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../src/common $(LOCAL_PATH)/../src/features $(LOCAL_PATH)/../src/core
LOCAL_CPPFLAGS   := -std=c++17 -fvisibility=hidden -fexceptions -frtti -Os -Wno-unused -DAIO_MERGE_BUILD
LOCAL_LDFLAGS    := -Wl,--no-gc-sections
LOCAL_LDLIBS     := -llog
include $(BUILD_SHARED_LIBRARY)

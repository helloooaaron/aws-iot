LOCAL_PATH := $(call my-dir)

mbed_src_files := $(wildcard $(LOCAL_PATH)/external_libs/mbedTLS/library/*.c)
aws_iot_src_files := $(wildcard $(LOCAL_PATH)/src/*.c)

###############################################################

include $(CLEAR_VARS)
LOCAL_MODULE := aws_iot_pubkey.pem
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/certs/
LOCAL_SRC_FILES := certs/pubkey.pem
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := aws_iot_privkey.pem
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/certs/
LOCAL_SRC_FILES := certs/privkey.pem
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := aws_iot_cert.pem
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/certs/
LOCAL_SRC_FILES := certs/cert.pem
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := aws_iot_rootCA.crt
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/certs/
LOCAL_SRC_FILES := certs/rootCA.crt
include $(BUILD_PREBUILT)

###############################################################

include $(CLEAR_VARS)

LOCAL_MODULE := libawsiot
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
	$(mbed_src_files:$(LOCAL_PATH)/%=%) \
    $(aws_iot_src_files:$(LOCAL_PATH)/%=%) \
    jsmn.c  \
    network_mbedtls_wrapper.c \
    threads_pthread_wrapper.c \
    timer.c

LOCAL_CXX_STL := none
LOCAL_C_INCLUDES := bionic
LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/ \
    $(LOCAL_PATH)/include/ \
    $(LOCAL_PATH)/external_libs/mbedTLS/include/
LOCAL_EXPORT_C_INCLUDE_DIRS := \
    $(LOCAL_PATH)/include/ \
    $(LOCAL_PATH)/external_libs/mbedTLS/include/

include $(BUILD_STATIC_LIBRARY)

###############################################################

include $(CLEAR_VARS)

LOCAL_MODULE := aws_iot_sample
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := samples/subscribe_publish_sample.c

LOCAL_STATIC_LIBRARIES := libawsiot

LOCAL_SHARED_LIBRARIES := libace_dropbox liblog

LOCAL_CFLAGS := -std=gnu99

include $(BUILD_EXECUTABLE)

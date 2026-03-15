#ifndef NH_LOG_H
#define NH_LOG_H

#include <android/log.h>

#define NH_LOG_TAG "newhook"

#ifdef NH_DEBUG
#define NH_LOG_D(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, NH_LOG_TAG, fmt, ##__VA_ARGS__)
#else
#define NH_LOG_D(fmt, ...) ((void)0)
#endif

#define NH_LOG_I(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  NH_LOG_TAG, fmt, ##__VA_ARGS__)
#define NH_LOG_W(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  NH_LOG_TAG, fmt, ##__VA_ARGS__)
#define NH_LOG_E(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, NH_LOG_TAG, fmt, ##__VA_ARGS__)

#endif // NH_LOG_H

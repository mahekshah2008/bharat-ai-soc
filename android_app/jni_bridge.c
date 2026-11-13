#include <jni.h>
#include <stdio.h>
#include <time.h>

// Exact function exported by neon_kernel.c (line 38)
extern float evaluate_sms_neon_simd(const char* sms_text);

JNIEXPORT jstring JNICALL
Java_com_bharataisoc_edge_MainActivity_scanSmsNative(JNIEnv *env, jobject thiz, jstring sms_jstr) {
    const char *sms = (*env)->GetStringUTFChars(env, sms_jstr, 0);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    float c_simd_score = evaluate_sms_neon_simd(sms);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double latency_ms = ((t1.tv_sec - t0.tv_sec) * 1e3) + ((t1.tv_nsec - t0.tv_nsec) / 1e6);

    (*env)->ReleaseStringUTFChars(env, sms_jstr, sms);

    char result_buf[256];
    snprintf(result_buf, sizeof(result_buf), "%.4f|%.4f", (double)c_simd_score, latency_ms);
    return (*env)->NewStringUTF(env, result_buf);
}
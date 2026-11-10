#include <string.h>
#include <ctype.h>
#include <math.h>

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

EXPORT float evaluate_sms_neon_simd(const char* sms_text) {
    if (!sms_text) return 0.0f;
    size_t len = strlen(sms_text);
    if (len == 0) return 0.0f;

    int non_ascii_count = 0;
    int digit_count = 0;
    int upper_count = 0;

    size_t i = 0;
#if defined(__ARM_NEON) || defined(__aarch64__)
    // 128-bit ARM NEON SIMD vectorized character inspection (16 bytes per cycle)
    uint8x16_t ascii_mask = vdupq_n_u8(0x80);
    for (; i + 16 <= len; i += 16) {
        uint8x16_t chunk = vld1q_u8((const uint8_t*)(sms_text + i));
        uint8x16_t high_bits = vandq_u8(chunk, ascii_mask);
        uint8_t temp[16];
        vst1q_u8(temp, high_bits);
        for (int j = 0; j < 16; j++) {
            if (temp[j] != 0) non_ascii_count++;
        }
    }
#endif

    // Remainder / scalar pass for character profiling
    for (; i < len; i++) {
        unsigned char c = (unsigned char)sms_text[i];
        if (c & 0x80) non_ascii_count++;
        if (isdigit(c)) digit_count++;
        if (isupper(c)) upper_count++;
    }

    // Fast case-insensitive substring scan for high-risk telemetry markers
    char lower_buf[1024];
    size_t copy_len = len < 1023 ? len : 1023;
    for (size_t k = 0; k < copy_len; k++) {
        lower_buf[k] = (char)tolower((unsigned char)sms_text[k]);
    }
    lower_buf[copy_len] = '\0';

    float score = 0.08f;

    // 1. Homoglyph / non-ASCII spoofing detection
    if (non_ascii_count > 0) score += 0.35f;

    // 2. Suspicious TLDs & phishing keywords
    if (strstr(lower_buf, ".xyz") || strstr(lower_buf, ".cn") || 
        strstr(lower_buf, "-kyc") || strstr(lower_buf, "http")) {
        score += 0.38f;
    }

    // 3. Coercive urgency / extortion triggers
    if (strstr(lower_buf, "urgent") || strstr(lower_buf, "suspended") || 
        strstr(lower_buf, "arrest") || strstr(lower_buf, "cbi") || 
        strstr(lower_buf, "blocked") || strstr(lower_buf, " disconnected")) {
        score += 0.36f;
    }

    // 4. Adversarial prompt injection markers
    if (strstr(lower_buf, "<|eot_id|>") || strstr(lower_buf, "ignore previous")) {
        score += 0.65f;
    }

    if (score > 0.99f) score = 0.99f;
    return score;
}
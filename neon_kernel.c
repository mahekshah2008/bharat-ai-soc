#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

/* Computes byte-level Shannon Entropy H(X) = -sum(P(x) * log2(P(x))) */
EXPORT float compute_shannon_entropy_simd(const char* text) {
    if (!text) return 0.0f;
    size_t len = strlen(text);
    if (len == 0) return 0.0f;

    uint32_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[(unsigned char)text[i]]++;
    }

    float entropy = 0.0f;
    float inv_len = 1.0f / (float)len;
    for (int b = 0; b < 256; b++) {
        if (freq[b] > 0) {
            float p = (float)freq[b] * inv_len;
            entropy -= p * (logf(p) / 0.69314718f); /* log2(p) */
        }
    }
    return entropy;
}

EXPORT float evaluate_sms_neon_simd(const char* sms_text) {
    if (!sms_text) return 0.0f;
    size_t len = strlen(sms_text);
    if (len == 0) return 0.0f;

    int non_ascii_count = 0;
    int digit_count = 0;
    size_t i = 0;

#if defined(__ARM_NEON) || defined(__aarch64__)
    /* 128-bit ARM NEON SIMD vectorized high-bit homoglyph scan (16 bytes/cycle) */
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

    for (; i < len; i++) {
        unsigned char c = (unsigned char)sms_text[i];
        if (c & 0x80) non_ascii_count++;
        if (isdigit(c)) digit_count++;
    }

    float entropy = compute_shannon_entropy_simd(sms_text);

    char lower_buf[1024];
    size_t copy_len = len < 1023 ? len : 1023;
    for (size_t k = 0; k < copy_len; k++) {
        lower_buf[k] = (char)tolower((unsigned char)sms_text[k]);
    }
    lower_buf[copy_len] = '\0';

    float score = 0.05f;

    /* 1. High Shannon Entropy anomaly (obfuscated DGA URLs / mixed scripts) */
    if (entropy > 4.45f) score += 0.18f;

    /* 2. Non-ASCII / Cyrillic Homoglyph spoofing */
    if (non_ascii_count > 0) score += 0.35f;

    /* 3. Suspicious phishing TLDs & URL lures */
    if (strstr(lower_buf, ".xyz") || strstr(lower_buf, ".cn") || 
        strstr(lower_buf, ".top") || strstr(lower_buf, "-kyc") || 
        strstr(lower_buf, "bit.ly") || strstr(lower_buf, "http")) {
        score += 0.36f;
    }

    /* 4. Coercive urgency, Digital Arrest, and Hinglish scam triggers */
    if (strstr(lower_buf, "urgent") || strstr(lower_buf, "suspended") || 
        strstr(lower_buf, "arrest") || strstr(lower_buf, "cbi") || 
        strstr(lower_buf, "blocked") || strstr(lower_buf, "disconnected") ||
        strstr(lower_buf, "turant") || strstr(lower_buf, "band ho") ||
        strstr(lower_buf, "fastag") || strstr(lower_buf, "challan")) {
        score += 0.36f;
    }

    /* 5. Adversarial prompt injection markers */
    if (strstr(lower_buf, "<|eot_id|>") || strstr(lower_buf, "ignore previous") ||
        strstr(lower_buf, "system:") || strstr(lower_buf, "threat_level: low")) {
        score += 0.68f;
    }

    if (score > 0.99f) score = 0.99f;
    return score;
}
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
            entropy -= p * (logf(p) / 0.69314718f);
        }
    }
    return entropy;
}

EXPORT float evaluate_sms_neon_simd(const char* sms_text) {
    if (!sms_text) return 0.0f;
    size_t len = strlen(sms_text);
    if (len == 0) return 0.0f;

    int homoglyph_spoof_count = 0;
    int devanagari_count = 0;
    int ascii_alpha_count = 0;
    int high_bit_simd_hits = 0;
    size_t simd_idx = 0;

#if defined(__ARM_NEON) || defined(__aarch64__)
    /* Hardware 128-bit ARM NEON SIMD register scan (16 bytes per single instruction cycle) */
    uint8x16_t high_mask = vdupq_n_u8(0x80);
    for (; simd_idx + 16 <= len; simd_idx += 16) {
        uint8x16_t chunk = vld1q_u8((const uint8_t*)(sms_text + simd_idx));
        uint8x16_t masked = vandq_u8(chunk, high_mask);
        uint8_t lane[16];
        vst1q_u8(lane, masked);
        for (int k = 0; k < 16; k++) {
            if (lane[k] != 0) high_bit_simd_hits++;
        }
    }
#endif

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)sms_text[i];
        if (isalpha(c)) {
            ascii_alpha_count++;
        } else if (c >= 0xCE && c <= 0xD3) {
            /* UTF-8 Greek (0xCE-0xCF) and Cyrillic (0xD0-0xD3) homoglyphs */
            homoglyph_spoof_count++;
        } else if (c == 0xE0 && (i + 1 < len)) {
            unsigned char next_c = (unsigned char)sms_text[i + 1];
            if (next_c == 0xA4 || next_c == 0xA5) {
                /* Legitimate Indian Devanagari UTF-8 block (Marathi / Hindi) */
                devanagari_count++;
            }
        }
    }

    float entropy = compute_shannon_entropy_simd(sms_text);

    char lower_buf[1024];
    size_t copy_len = len < 1023 ? len : 1023;
    for (size_t k = 0; k < copy_len; k++) {
        lower_buf[k] = (char)tolower((unsigned char)sms_text[k]);
    }
    lower_buf[copy_len] = '\0';

    float score = 0.05f;

    /* 1. Mixed-Script Cyrillic/Greek Homoglyph Spoofing */
    if (homoglyph_spoof_count > 0 && ascii_alpha_count > 0) {
        score += 0.42f;
    }

    /* 2. High Shannon Entropy on URL payloads */
    if (entropy > 4.50f && (strstr(lower_buf, "http") || strstr(lower_buf, "www"))) {
        score += 0.16f;
    }

    /* 3. Suspicious TLDs, URL lures, and APK sideloading */
    if (strstr(lower_buf, ".xyz") || strstr(lower_buf, ".cn") || 
        strstr(lower_buf, ".top") || strstr(lower_buf, "-kyc") || 
        strstr(lower_buf, ".apk") || strstr(lower_buf, "bit.ly") ||
        strstr(lower_buf, "http://") || strstr(lower_buf, "https://")) {
        score += 0.36f;
    }

    /* 4. Urgency, Infrastructure, Hinglish & Devanagari scam triggers */
    if (strstr(lower_buf, "urgent") || strstr(lower_buf, "suspended") || 
        strstr(lower_buf, "arrest") || strstr(lower_buf, "cbi") || 
        strstr(lower_buf, "blocked") || strstr(lower_buf, "disconnected") ||
        strstr(lower_buf, "turant") || strstr(lower_buf, "band ho") ||
        strstr(lower_buf, "fastag") || strstr(lower_buf, "challan") ||
        strstr(lower_buf, "unusual login") || strstr(lower_buf, "frozen") ||
        strstr(lower_buf, "blacklisted") || strstr(lower_buf, "on hold") ||
        strstr(lower_buf, "daily from home") || strstr(lower_buf, "seized") ||
        strstr(sms_text, "केवायसी") || strstr(sms_text, "ब्लॉक") ||
        strstr(sms_text, "डिजिटल अरेस्ट") || strstr(sms_text, "कनेक्शन बंद")) {
        score += 0.36f;
    }

    /* 5. Linkless Digital Arrest & Law Enforcement Impersonation Extortion */
    if ((strstr(lower_buf, "arrest") || strstr(lower_buf, "cbi") || 
         strstr(lower_buf, "customs") || strstr(lower_buf, "cyber crime") ||
         strstr(sms_text, "डिजिटल अरेस्ट")) &&
        (strstr(lower_buf, "video") || strstr(lower_buf, "skype") || 
         strstr(lower_buf, "whatsapp") || strstr(lower_buf, "laundering") ||
         strstr(lower_buf, "seized") || strstr(lower_buf, "fir"))) {
        score += 0.44f;
    }

    /* 6. Adversarial Prompt Injection / Jailbreak control tokens */
    if (strstr(lower_buf, "<|eot_id|>") || strstr(lower_buf, "ignore previous") ||
        strstr(lower_buf, "override security") || strstr(lower_buf, "<<sys>>") ||
        strstr(lower_buf, "threat_level: low")) {
        score += 0.75f;
    }

    if (score > 0.99f) score = 0.99f;
    return score;
}
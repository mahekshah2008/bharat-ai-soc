#include <stdint.h>
#include <math.h>
#include <string.h>

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#endif

// Computes character-level Shannon entropy and counts non-ASCII (homoglyph) bytes
// using ARM NEON 128-bit SIMD vector registers where available.
double compute_entropy_and_homoglyphs(const uint8_t* data, size_t len, int* homoglyph_count) {
    if (len == 0) {
        *homoglyph_count = 0;
        return 0.0;
    }

    uint32_t counts[256] = {0};
    int non_ascii = 0;
    size_t i = 0;

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    // Process 16 bytes at a time using 128-bit NEON registers
    uint8x16_t ascii_mask = vdupq_n_u8(0x80);
    for (; i + 16 <= len; i += 16) {
        uint8x16_t chunk = vld1q_u8(data + i);
        
        // Bitwise AND with 0x80 to detect non-ASCII multibyte UTF-8 characters (e.g., Cyrillic spoofing)
        uint8x16_t high_bits = vandq_u8(chunk, ascii_mask);
        uint8x16_t is_non_ascii = vcgtq_u8(high_bits, vdupq_n_u8(0));
        
        // Horizontal reduction to count flagged bytes in the 16-byte vector
        uint8x16_t ones = vshrq_n_u8(is_non_ascii, 7);
        non_ascii += vaddvq_u8(ones);

        // Unrolled histogram update
        uint8_t buf[16];
        vst1q_u8(buf, chunk);
        for (int j = 0; j < 16; ++j) {
            counts[buf[j]]++;
        }
    }
#endif

    // Handle remaining tail bytes (or full buffer on non-ARM fallback)
    for (; i < len; ++i) {
        uint8_t b = data[i];
        if (b & 0x80) {
            non_ascii++;
        }
        counts[b]++;
    }

    *homoglyph_count = non_ascii;

    // Calculate Shannon Entropy: H(X) = -sum(P(x) * log2(P(x)))
    double entropy = 0.0;
    double inv_len = 1.0 / (double)len;
    for (int k = 0; k < 256; ++k) {
        if (counts[k] > 0) {
            double p = (double)counts[k] * inv_len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

// Helper to check if compiled with hardware NEON intrinsics active
int is_neon_enabled(void) {
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    return 1;
#else
    return 0;
#endif
}
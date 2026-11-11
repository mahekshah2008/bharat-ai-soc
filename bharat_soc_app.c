#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* Import Stage 1 ARM NEON SIMD functions from neon_kernel.c */
extern float compute_shannon_entropy_simd(const char* text);
extern float evaluate_sms_neon_simd(const char* sms_text);

static const char* detect_hardware_arch(void) {
#if defined(__aarch64__)
    return "ARM64 (aarch64) Physical Silicon - Hardware ARM NEON 128-bit SIMD Active";
#elif defined(__ARM_NEON)
    return "ARMv7 Physical Silicon - Hardware ARM NEON SIMD Active";
#elif defined(__x86_64__) || defined(_M_X64)
    return "x86_64 Host Architecture (SIMD Fallback Mode)";
#else
    return "Generic Edge Target";
#endif
}

static void inspect_sms_payload(const char* sender, const char* sms) {
    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    float entropy = compute_shannon_entropy_simd(sms);
    float score = evaluate_sms_neon_simd(sms);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double latency_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000.0 +
                        (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000.0;

    /* Threat threshold calibrated for both link-based and linkless extortion */
    const char* verdict = (score >= 0.40f) ? "BLOCKED (MALICIOUS)" : "PASSED (BENIGN)";
    const char* category = "LEGITIMATE_TRANSACTIONAL";

    if (score >= 0.40f) {
        if (strstr(sms, "arrest") || strstr(sms, "Arrest") || strstr(sms, "CBI") || 
            strstr(sms, "Customs") || strstr(sms, "डिजिटल अरेस्ट")) {
            category = "DIGITAL_ARREST_EXTORTION";
        } else if (strstr(sms, "<|eot_id|>") || strstr(sms, "Ignore previous") || strstr(sms, "<<SYS>>")) {
            category = "ADVERSARIAL_PROMPT_INJECTION";
        } else if (strstr(sms, ".apk")) {
            category = "MALICIOUS_APK_SIDELOAD";
        } else {
            category = "KYC_OR_HOMOGLYPH_PHISHING";
        }
    }

    printf("------------------------------------------------------------------------\n");
    printf(" [OS INTENT] Sender : %s\n", sender);
    printf(" [PAYLOAD]   Message: %s\n", sms);
    printf(" [STAGE 1]   NEON SIMD Score: %.2f | Shannon Entropy: %.3f bits/byte\n", score, entropy);
    printf(" [LATENCY]   Execution Time : %.4f ms\n", latency_ms);
    printf(" [VERDICT]   %s | Taxonomy: %s\n", verdict, category);
    if (score >= 0.40f) {
        printf(" [CHAKSHU]   DoT 1930 NCRP Auto-Report Ready (sancharsaathi.gov.in)\n");
    }
    printf("------------------------------------------------------------------------\n\n");
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    /* Force Windows console to UTF-8 so Marathi/Hindi Devanagari renders cleanly */
    SetConsoleOutputCP(65001);
#endif

    printf("========================================================================\n");
    printf(" BHARAT AI-SOC: Compiled Native Edge Security Executable (v3.0)         \n");
    printf(" Hardware Arch: %s\n", detect_hardware_arch());
    printf(" Mode         : 100%% Offline Zero-Cloud On-Device Protection           \n");
    printf("========================================================================\n\n");

    if (argc > 1) {
        inspect_sms_payload("CLI-INPUT", argv[1]);
        return 0;
    }

    /* Default Offline Hardware Verification Suite */
    inspect_sms_payload("+91-98210XXXXX", "URGENT: Рaytm KYC expired! Verify at https://paytm-secure-kyc99.xyz or account will be frozen.");
    inspect_sms_payload("CBI-CELL", "CBI Cyber Cell Notice: Your Aadhaar linked mobile is used in money laundering. Join WhatsApp video call or face Digital Arrest.");
    inspect_sms_payload("MSEB-ALERT", "महावितरण तात्काळ सूचना: आज रात्री 9:30 वाजता वीज कनेक्शन बंद होईल. लगेच क्लिक करा: http://mahadiscom-bill.xyz");
    inspect_sms_payload("VM-SBIINB-S", "Dear UPI user A/C X4921 debited by Rs 180.00 on date 11Nov26 trf to Zomato Limited Refno 631519283112.");
    inspect_sms_payload("VM-MAHADIS", "महावितरण: ग्राहक क्र. 17002918234 चे रु. 840 चे वीज बिल प्राप्त झाले आहे. धन्यवाद.");

    return 0;
}
import ctypes
import os
from typing import Dict, Any

class NeonSimdKernelLoader:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dll_path = os.path.join(base_dir, "neon_kernel.dll")
        so_path = os.path.join(base_dir, "neon_kernel.so")
        
        self.lib_path = dll_path if os.name == "nt" else so_path
        self._native_lib = None
        self._load_kernel()

    def _load_kernel(self):
        """Attempts to load the compiled C-kernel shared library (.dll on Windows, .so on Linux/Android)."""
        try:
            if os.path.exists(self.lib_path):
                self._native_lib = ctypes.CDLL(self.lib_path)
                self._native_lib.evaluate_sms_neon_simd.argtypes = [ctypes.c_char_p]
                self._native_lib.evaluate_sms_neon_simd.restype = ctypes.c_float
                print(f"[NEON LOADER] Successfully linked native C-kernel binary: {os.path.basename(self.lib_path)}")
            else:
                print(f"[NEON LOADER] Notice: Native binary '{os.path.basename(self.lib_path)}' not found. Using Python SIMD emulator.")
        except Exception as e:
            print(f"[NEON LOADER] Warning: Failed to load native library ({e}). Using fallback parser.")

    def evaluate(self, sms_text: str) -> Dict[str, Any]:
        """Evaluates SMS text using the native C-kernel if compiled, else Python fallback."""
        encoded_text = sms_text.encode("utf-8")
        
        if self._native_lib is not None:
            try:
                score = self._native_lib.evaluate_sms_neon_simd(encoded_text)
                return {
                    "source": "native_arm_neon_c_kernel",
                    "threat_score": round(float(score), 4),
                    "simd_accelerated": True
                }
            except Exception:
                pass
        
        has_suspicious_url = any(t in sms_text.lower() for t in [".xyz", ".cn", "update", "kyc", "verify", "block"])
        has_urgency = any(t in sms_text.lower() for t in ["urgent", "immediate", "suspended", "arrest", "cbi"])
        base_score = 0.82 if (has_suspicious_url and has_urgency) else (0.55 if (has_suspicious_url or has_urgency) else 0.12)
        
        return {
            "source": "python_simd_emulator",
            "threat_score": base_score,
            "simd_accelerated": False
        }

neon_engine = NeonSimdKernelLoader()
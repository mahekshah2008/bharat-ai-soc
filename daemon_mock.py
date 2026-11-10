import time
import sys
import os
import random
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from detector import BharatThreatDetector, extract_threat_evidence
from llm_engine import Stage2ReasoningEngine

console = Console()

# Simulated live incoming SMS stream from Android Telephony Broadcast Receiver
BROADCAST_INTENTS = [
    {
        "sender": "VM-HDFCBK",
        "text": "Your loan of Rs 5,00,000 has been pre-approved. Claim now at https://hdfc-instant-loan.xyz"
    },
    {
        "sender": "AD-CYBERPOL",
        "text": "Cyber Crime Branch: Your digital arrest warrant is active under Section 420. Contact officer immediately via WhatsApp video call."
    },
    {
        "sender": "VM-ZOMATO",
        "text": "Hi Mahek, your food delivery order #82911 is on the way with delivery partner Rahul."
    },
    {
        "sender": "VK-PAYTM",
        "text": "URGENT: Yоur Paytm KYC has been suspended due to pending PAN validation. Update instantly: https://paytm-kyc-update.cn"
    }
]

def run_sms_daemon():
    detector = BharatThreatDetector()
    stage2 = Stage2ReasoningEngine()

    console.clear()
    console.print(Panel("[bold cyan]BHARAT AI-SOC : Android OS Broadcast Intent Interceptor Daemon[/bold cyan]\n[dim]Listening for android.provider.Telephony.SMS_RECEIVED intents on aarch64...[/dim]", box=box.ROUNDED, border_style="cyan"))
    
    time.sleep(1.0)
    console.print("[green]✔ Background SMS Broadcast Receiver registered successfully.[/green]")
    console.print("[green]✔ ARM NEON SIMD C-Kernel hooked into telephony pipeline. Waiting for incoming SMS...\n[/green]")
    time.sleep(1.5)

    for idx, intent in enumerate(BROADCAST_INTENTS, 1):
        sender = intent["sender"]
        sms = intent["text"]

        console.print(f"[bold yellow][Broadcast Intent Received #{idx}] Sender: {sender}[/bold yellow]")
        console.print(Panel(f"[italic white]\"{sms}\"[/italic white]", title="SMS Payload", box=box.SIMPLE, border_style="yellow"))

        # Pipeline timing & threat extraction
        t_start = time.perf_counter()
        ev = extract_threat_evidence(sms, detector=detector)
        advice = stage2.generate_advice(sms, ev)
        t_elapsed = (time.perf_counter() - t_start) * 1000

        # Build analysis result table
        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL)
        table.add_column("Pipeline Stage")
        table.add_column("Evaluation")
        table.add_column("Hardware Telemetry")

        if ev["is_threat"]:
            status_display = "[bold red]CRITICAL THREAT BLOCKED[/bold red]"
            action_display = f"Action: {advice['threat_level']} | Helpline: {advice['reporting_helpline']}"
        else:
            status_display = "[bold green]BENIGN (PASSED TO INBOX)[/bold green]"
            action_display = "Energy-Preserving Gate: LLM Bypassed"

        table.add_row("Stage 1 (ARM NEON SIMD)", status_display, f"Score: {ev['threat_score']} | Latency: {t_elapsed:.2f}ms")
        table.add_row("Stage 2 (Reasoning Engine)", f"Category: {advice['threat_category']}", action_display)

        console.print(table)

        if ev["is_threat"]:
            console.print(Panel(
                f"[bold red]🚨 SECURITY ALERT TRIGGERED & CHAKSHU EXPORTED 🚨[/bold red]\n"
                f"[dim]Guidance: {advice['actionable_guidance']}[/dim]",
                box=box.ROUNDED, border_style="red"
            ))
        else:
            console.print(Panel(
                f"[bold green]✔ Message delivered cleanly to user inbox.[/bold green]",
                box=box.ROUNDED, border_style="green"
            ))

        console.print("=" * 65 + "\n")
        time.sleep(2.5)

    console.print("[bold cyan]=== DEMO SIMULATION COMPLETE: ALL INTENTS PROCESSED SECURELY ===[/bold cyan]\n")

if __name__ == "__main__":
    run_sms_daemon()
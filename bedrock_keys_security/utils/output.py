"""Click-based output helpers replacing the Colors class"""

import sys
import threading
import click
from contextlib import contextmanager
from typing import Dict

_spinner_lock = threading.Lock()
_spinner_active = False
_spinner_label_len = 0
_spinner_label = ""


def _clear_spinner_line():
    """Clear the spinner line from stderr for clean log output"""
    if _spinner_active:
        sys.stderr.write("\r" + " " * (_spinner_label_len + 3) + "\r")
        sys.stderr.flush()


def _redraw_spinner():
    """Redraw the spinner line on stderr after log output"""
    if _spinner_active:
        frame = click.style("\u280b", fg="cyan")
        sys.stderr.write(f"\r{frame} {_spinner_label}")
        sys.stderr.flush()


def info(msg: str) -> None:
    with _spinner_lock:
        _clear_spinner_line()
        click.echo(click.style(f"[INFO] {msg}", fg="cyan"))
        _redraw_spinner()


def success(msg: str) -> None:
    with _spinner_lock:
        _clear_spinner_line()
        click.echo(click.style(f"[SUCCESS] {msg}", fg="green"))
        _redraw_spinner()


def warning(msg: str) -> None:
    with _spinner_lock:
        _clear_spinner_line()
        click.echo(click.style(f"[WARNING] {msg}", fg="yellow"))
        _redraw_spinner()


def error(msg: str) -> None:
    with _spinner_lock:
        _clear_spinner_line()
        click.echo(click.style(f"[ERROR] {msg}", fg="red"), err=True)
        _redraw_spinner()


def high_risk(msg: str) -> None:
    with _spinner_lock:
        _clear_spinner_line()
        click.echo(click.style(f"[HIGH RISK] {msg}", fg="red"))
        _redraw_spinner()


def bold(text: str) -> str:
    return click.style(text, bold=True)


def red(text: str) -> str:
    return click.style(text, fg="red")


def green(text: str) -> str:
    return click.style(text, fg="green")


def yellow(text: str) -> str:
    return click.style(text, fg="yellow")


def cyan(text: str) -> str:
    return click.style(text, fg="cyan")


@contextmanager
def spinner(label="Scanning"):
    """Simple threaded spinner for indeterminate progress"""
    global _spinner_active, _spinner_label_len, _spinner_label
    frames = ["\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u2807", "\u280f"]
    stop = threading.Event()

    def spin():
        i = 0
        while not stop.is_set():
            with _spinner_lock:
                if not stop.is_set():
                    frame = click.style(frames[i % len(frames)], fg="cyan")
                    sys.stderr.write(f"\r{frame} {label}")
                    sys.stderr.flush()
            i += 1
            stop.wait(0.08)
        sys.stderr.write("\r" + " " * (len(label) + 3) + "\r")
        sys.stderr.flush()

    with _spinner_lock:
        _spinner_active = True
        _spinner_label_len = len(label)
        _spinner_label = label
    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join()
        with _spinner_lock:
            _spinner_active = False


def style_status(status: str) -> str:
    if status == "AT RISK":
        return click.style(status, fg="red")
    elif status == "ACTIVE":
        return click.style(status, fg="green")
    else:
        return click.style(status, fg="yellow")


def format_decode_table_output(result: Dict) -> str:
    if "error" in result:
        return f"\n{red('[ERROR] ' + result['error'])}\n"

    lines = []
    lines.append(f"\n{bold('\u2500' * 60)}")
    lines.append(f"{bold(cyan('  Bedrock API Key Analysis'))}")
    lines.append(f"{bold('\u2500' * 60)}")

    key_type = result.get("type", "Unknown")
    type_label = green("Long-term (ABSK)") if key_type == "long-term" else yellow("Short-term")
    lines.append(f"  Type: {type_label}")

    if key_type == "long-term":
        lines.append(f"  IAM Username: {cyan(result.get('username', 'N/A'))}")
        lines.append(f"  AWS Account ID: {cyan(result.get('account_id', 'N/A'))}")
        lines.append(f"  Secret Preview: {result.get('secret_preview', 'N/A')}")
        lines.append(f"  Format: {result.get('format', 'N/A')}")

    elif key_type == "short-term":
        lines.append(f"  Action: {result.get('action', 'N/A')}")
        lines.append(f"  Region: {cyan(result.get('region', 'N/A'))}")
        lines.append(f"  AWS Account ID: {cyan(result.get('account_id', 'N/A'))}")
        lines.append(f"  Expires In: {result.get('expires_in_seconds', 'N/A')} seconds")
        lines.append(f"  Date: {result.get('date', 'N/A')}")
        lines.append(f"  Format: {result.get('format', 'N/A')}")

    if "security_notes" in result and result["security_notes"]:
        lines.append(f"\n  {bold(yellow('Security Notes:'))}")
        for note in result["security_notes"]:
            lines.append(f"  {yellow('  \u2022 ' + note)}")

    lines.append(f"{bold('\u2500' * 60)}\n")

    return "\n".join(lines)

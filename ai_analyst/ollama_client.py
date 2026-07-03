"""
SentinelForge - Ollama Client
==============================
Thin wrapper around the local Ollama HTTP API.

Defaults:
    model : llama3 (override via SENTINELFORGE_MODEL env var)
    url   : http://localhost:11434 (override via OLLAMA_URL env var)

Usage:
    from ai_analyst.ollama_client import generate, is_available

    if is_available():
        response = generate("Summarise this alert: SSH brute force from 10.0.0.1")
"""

import os
import requests

OLLAMA_BASE   = os.getenv("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("SENTINELFORGE_MODEL", "llama3")
TIMEOUT_S     = 90   # generous timeout for slower hardware


def is_available(model: str = None) -> bool:
    """Return True if Ollama is running and the requested model is loaded."""
    m = (model or DEFAULT_MODEL).split(":")[0]   # strip :latest etc.
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=3)
        if r.status_code != 200:
            return False
        names = [entry["name"].split(":")[0] for entry in r.json().get("models", [])]
        return m in names
    except Exception:
        return False


def list_models() -> list:
    """Return list of model name strings available in Ollama."""
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=3)
        return [entry["name"] for entry in r.json().get("models", [])]
    except Exception:
        return []


def generate(prompt: str, model: str = None, system: str = None) -> str:
    """
    Send a prompt to Ollama and return the completion text.

    Args:
        prompt: The user prompt to complete.
        model:  Model name (default: SENTINELFORGE_MODEL env or 'llama3').
        system: Optional system prompt to prepend.

    Returns:
        Completion string.

    Raises:
        RuntimeError: if Ollama is not reachable or returns an error.
    """
    m = model or DEFAULT_MODEL
    payload: dict = {
        "model":  m,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,    # low temp for factual SOC analysis
            "num_predict": 256,    # keep answers concise
        },
    }
    if system:
        payload["system"] = system

    try:
        r = requests.post(f"{OLLAMA_BASE}/api/generate", json=payload, timeout=TIMEOUT_S)
        r.raise_for_status()
        return r.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Ollama not running at {OLLAMA_BASE}. Start it with: ollama serve")
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Ollama timed out after {TIMEOUT_S}s. Try a smaller model.")
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"Ollama HTTP error {r.status_code}: {e}")
    except Exception as e:
        raise RuntimeError(f"Ollama error: {e}")


if __name__ == "__main__":
    print(f"Ollama URL   : {OLLAMA_BASE}")
    print(f"Default model: {DEFAULT_MODEL}")
    print(f"Available    : {is_available()}")
    print(f"Models       : {list_models()}")
    if is_available():
        resp = generate(
            "In one sentence, what does a SOC analyst do?",
            system="You are a concise cybersecurity assistant."
        )
        print(f"\nTest response: {resp}")

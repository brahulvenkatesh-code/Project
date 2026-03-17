"""
nanobot_client.py — NanoBot orchestration layer
NanoBot is a framework that orchestrates LLM calls.
We use Google Gemini as the LLM provider.

Flow: Your App → NanoBot (this file) → Gemini API → Response
"""

import os, logging
from google import genai
from google.genai import types
from security import MAX_LLM_TOKENS

logger = logging.getLogger("ps2.nanobot")

# GEMINI_KEY lookup moved inside call_nanobot to ensure it picks up .env changes immediately
GEMINI_MODEL     = "gemini-1.5-flash"
MAX_SYSTEM_CHARS = 6_000


def _truncate_system(system: str) -> str:
    if len(system) > MAX_SYSTEM_CHARS:
        return system[:MAX_SYSTEM_CHARS] + "\n\n[truncated]"
    return system


async def call_nanobot(system: str, user_message: str, max_tokens: int = MAX_LLM_TOKENS) -> str:
    """
    NanoBot orchestrates this call to the Gemini API with a smart fallback.
    1. Primary: gemini-flash-latest (Gemini 3)
    2. Fallback: gemini-1.5-flash (if Primary quota is hit)
    """
    key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if not key:
        raise ValueError("GOOGLE_API_KEY is not set in .env")

    # Primary attempt
    primary_model = "gemini-flash-latest"
    fallback_model = "gemini-1.5-flash"
    
    try:
        return await _execute_call(key, primary_model, system, user_message, max_tokens)
    except Exception as e:
        err_msg = str(e).lower()
        # Detect Daily Quota / Resource Exhaustion
        if "429" in err_msg or "quota" in err_msg or "exhausted" in err_msg:
            logger.warning(f"Primary model ({primary_model}) quota hit. Falling back to {fallback_model}...")
            try:
                return await _execute_call(key, fallback_model, system, user_message, max_tokens)
            except Exception as fe:
                logger.error(f"Fallback model also failed: {fe}")
                raise
        else:
            logger.error(f"Gemini error: {e}")
            raise


async def _execute_call(api_key: str, model: str, system: str, user_message: str, max_tokens: int) -> str:
    client = genai.Client(api_key=api_key)
    response = await client.aio.models.generate_content(
        model=model,
        contents=user_message,
        config=types.GenerateContentConfig(
            system_instruction=_truncate_system(system),
            max_output_tokens=max_tokens,
            temperature=0.1,
        ),
    )

    if not response.text:
        raise ValueError("Empty response from Gemini")

    return response.text

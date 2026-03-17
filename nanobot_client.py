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
GEMINI_MODEL     = "gemini-flash-latest"
MAX_SYSTEM_CHARS = 6_000


def _truncate_system(system: str) -> str:
    if len(system) > MAX_SYSTEM_CHARS:
        return system[:MAX_SYSTEM_CHARS] + "\n\n[truncated]"
    return system


async def call_nanobot(system: str, user_message: str, max_tokens: int = MAX_LLM_TOKENS) -> str:
    """
    NanoBot orchestrates this call to the Gemini API.
    """
    key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if not key:
        raise ValueError("GOOGLE_API_KEY is not set in .env")

    # Safe log to verify the key being used (first 4 and last 4 chars only)
    logger.info(f"NanoBot calling Gemini with key: {key[:4]}...{key[-4:]}")

    try:
        client = genai.Client(api_key=key)

        response = await client.aio.models.generate_content(
            model=GEMINI_MODEL,
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

    except Exception as e:
        logger.error(f"Gemini error: {e}")
        raise

"""
nanobot_client.py — NanoBot orchestration layer
NanoBot is a framework that orchestrates LLM calls.
We use Google Gemini as the LLM provider.

Flow: Your App → NanoBot (this file) → Gemini API → Response
"""

import os, logging
from google import genai
from google.genai import types
from groq import AsyncGroq
from security import MAX_LLM_TOKENS

logger = logging.getLogger("ps2.nanobot")

# Model Definitions
GEMINI_3_FLASH = "gemini-flash-latest"
GROQ_LLAMA_3_3 = "llama-3.3-70b-versatile"
GEMINI_1_5_FLASH = "gemini-1.5-flash"

MAX_SYSTEM_CHARS = 6_000


def _truncate_system(system: str) -> str:
    if len(system) > MAX_SYSTEM_CHARS:
        return system[:MAX_SYSTEM_CHARS] + "\n\n[truncated]"
    return system


async def call_nanobot(system: str, user_message: str, max_tokens: int = MAX_LLM_TOKENS) -> str:
    """
    NanoBot orchestrates this call with a Triple-Tier Fallback:
    1. Tier 1: Gemini 3 Flash (Primary)
    2. Tier 2: Groq Llama 3.3 70B (High Speed High Availability)
    3. Tier 3: Gemini 1.5 Flash (Backup)
    """
    keys = {
        "gemini": os.environ.get("GOOGLE_API_KEY", "").strip(),
        "groq":   os.environ.get("GROQ_API_KEY", "").strip()
    }

    if not keys["gemini"]:
        raise ValueError("GOOGLE_API_KEY is not set in .env")

    # --- TIER 1: Gemini 3 Flash ---
    try:
        return await _execute_gemini(keys["gemini"], GEMINI_3_FLASH, system, user_message, max_tokens)
    except Exception as e:
        if _is_quota_exhausted(e):
            logger.warning(f"Tier 1 ({GEMINI_3_FLASH}) quota hit. Trying Tier 2 (Groq)...")
        else:
            logger.error(f"Tier 1 Error: {e}")
            raise

    # --- TIER 2: Groq Llama 3.3 ---
    if keys["groq"]:
        try:
            return await _execute_groq(keys["groq"], GROQ_LLAMA_3_3, system, user_message, max_tokens)
        except Exception as e:
            if _is_quota_exhausted(e):
                logger.warning(f"Tier 2 ({GROQ_LLAMA_3_3}) quota/rate hit. Trying Tier 3 (Gemini 1.5)...")
            else:
                logger.error(f"Tier 2 Error: {e}")
                # Don't raise here, move to Tier 3
    else:
        logger.warning("Groq key missing, skipping Tier 2.")

    # --- TIER 3: Gemini 1.5 Flash ---
    try:
        return await _execute_gemini(keys["gemini"], GEMINI_1_5_FLASH, system, user_message, max_tokens)
    except Exception as e:
        logger.error(f"Tier 3 Error (Final Fallback): {e}")
        raise


def _is_quota_exhausted(e: Exception) -> bool:
    msg = str(e).lower()
    return any(x in msg for x in ["429", "quota", "exhausted", "rate_limit", "rate limit"])


async def _execute_gemini(api_key: str, model: str, system: str, user_message: str, max_tokens: int) -> str:
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
        raise ValueError(f"Empty response from Gemini ({model})")
    return response.text


async def _execute_groq(api_key: str, model: str, system: str, user_message: str, max_tokens: int) -> str:
    client = AsyncGroq(api_key=api_key)
    chat_completion = await client.chat.completions.create(
        messages=[
            {"role": "system", "content": _truncate_system(system)},
            {"role": "user", "content": user_message},
        ],
        model=model,
        temperature=0.1,
        max_tokens=max_tokens,
    )
    res = chat_completion.choices[0].message.content
    if not res:
        raise ValueError(f"Empty response from Groq ({model})")
    return res

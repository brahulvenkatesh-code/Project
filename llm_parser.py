import json
import logging
from nanobot_client import call_nanobot

logger = logging.getLogger("ps2.llm_parser")

EXTRACTION_SYSTEM_PROMPT = """You are NanoBot, an expert Data Extraction Agent.
Your task is to parse unstructured text or semi-structured JSON containing Machine Learning model metrics and extract them into a clean, structured JSON array following the Trinity Metrics Schema.

TRINITY SCHEMA:
Each object in the array MUST be a dictionary containing at minimum:
- `model_info`: dict with `name`, `algorithm`, `task` (e.g. "classification", "regression")
- `performance_metrics`: dict containing standard numeric metrics (e.g. `accuracy`, `f1_score`, `precision`, `recall`, `auc_roc`, `mse`, `mae`, `r2_score`, etc.)

RULES:
1. Return ONLY a valid JSON array of objects. NO markdown formatting, NO backticks (```json), NO extra text.
2. If multiple models/results are present in the text, extract each into a separate object within the array.
3. If only one model is present, return an array with one object.
4. Extract all valid metrics you can find. Use standard keys (e.g. 'f1_score' instead of 'F1', 'auc_roc' instead of 'AUC').
5. Ensure all metric values are numbers (float), not strings.
"""

async def parse_unstructured_metrics(raw_text: str) -> list[dict]:
    """
    Takes unstructured text or malformed JSON, passes it to NanoBot (LLM),
    and returns a clean list of dictionaries conforming to the expected schema.
    """
    try:
        # Prompt the LLM to extract the data
        user_prompt = f"Extract the following metrics into a strict JSON array:\n\n{raw_text}"
        response_text = await call_nanobot(EXTRACTION_SYSTEM_PROMPT, user_prompt, max_tokens=2048)
        
        # Clean up possible markdown if the LLM disobeys Rule 1
        cleaned_text = response_text.strip()
        if cleaned_text.startswith("```json"):
            cleaned_text = cleaned_text[7:]
        if cleaned_text.startswith("```"):
            cleaned_text = cleaned_text[3:]
        if cleaned_text.endswith("```"):
            cleaned_text = cleaned_text[:-3]
        cleaned_text = cleaned_text.strip()
        
        # Parse the JSON
        parsed_data = json.loads(cleaned_text)
        
        if isinstance(parsed_data, dict):
            # If the LLM returned a single object instead of an array, wrap it
            return [parsed_data]
        elif isinstance(parsed_data, list):
            return parsed_data
        else:
            raise ValueError("LLM returned non-object/array JSON")
            
    except Exception as e:
        logger.error(f"Unstructured parsing failed: {e}")
        return []

import logging
import json
from nanobot_client import call_nanobot
from security import build_llm_safe_payload, scan_injection

logger = logging.getLogger("nanobot_service")

# Strict Prompt Template
SYSTEM_PROMPT = """
You are NanoBot, an AI Explanation Layer.
Your ONLY task is to explain the risk assessment provided by the Deterministic Risk Engine.

CONSTRAINTS:
1. You MUST NOT generate, modify, or suggest any risk scores or levels.
2. You MUST only use the data provided in the 'DECISION_SNAPSHOT'.
3. If the data is missing or malformed, state that you cannot provide an explanation.
4. Do NOT include any PII or sensitive system details.
5. Your output must be professional, auditable, and strictly explanatory.
"""

class NanoBotService:
    @staticmethod
    async def explain_decision(decision_snapshot: dict, user_context: str = "") -> str:
        """
        Generates a human-readable explanation for a deterministic decision.
        Strictly Read-Only: Cannot modify the decision_snapshot.
        """
        # 1. Input Sanitization
        if scan_injection(user_context):
            logger.warning("NanoBot blocked due to potential prompt injection in user context")
            return "Security violation detected in explanation request."

        # 2. Extract only approved numeric/metadata for the LLM
        # This prevents the LLM from seeing internal rule logic or PII
        llm_payload = build_llm_safe_payload(decision_snapshot)
        
        # 3. Build the final prompt
        user_msg = f"""
        DECISION_SNAPSHOT:
        {llm_payload}

        USER_QUESTION:
        {user_context if user_context else "Please explain this risk assessment."}
        """

        try:
            # 4. Call the LLM Client (Isolated)
            explanation = await call_nanobot(system=SYSTEM_PROMPT, user_message=user_msg)
            
            # 5. Output Filtering (Basic Hallucination Guard)
            # Ensure the LLM didn't try to override the score
            if "score =" in explanation.lower() or "level =" in explanation.lower():
                logger.warning("NanoBot output filtered: possible score hallucination detected")
                # We could strip this or return a safe fallback
                explanation = explanation.replace("score =", "[REDACTED]").replace("level =", "[REDACTED]")

            return explanation
        except Exception as e:
            logger.error(f"NanoBot Service Error: {str(e)}")
            return "An error occurred while generating the explanation. Please refer to the raw audit logs."

def bridge_risk_to_nanobot(decision: dict) -> dict:
    """
    The 'Strict Read-Only Bridge'. 
    Creates a deep copy of the decision to ensure NanoBot cannot mutate the original.
    """
    return json.loads(json.dumps(decision))

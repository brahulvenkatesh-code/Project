# API Simplification: Stateful Bridge

The user wants to use a simple chat payload:
```json
{
    "message": "Should I deploy this model?",
    "session_id": "test"
}
```

To support this safely without violating **NanoBot Isolation**, we will implement a "Stateful Bridge" in the Backend.

## Proposed Changes

### Backend (api.py)

#### [MODIFY] [api.py](file:///c:/Users/V. Balagurunathan/OneDrive/Desktop/PROJECT/api.py)
1. **DecisionStore**: Implement an in-memory dictionary `{session_id: last_decision}`.
2. **`POST /api/analyze`**: After a decision is made, store it in the `DecisionStore` keyed by `session_id`.
3. **`POST /api/explain`**: 
   - Accept either a full `decision` object OR a `session_id`.
   - If `session_id` is provided, look up the last decision in the `DecisionStore`.
   - Map `message` field (user's preferred key) to the internal `question` parameter.

## Verification Plan

### Automated Tests
- Update `security_test.py` to verify the new "Simple Request" format.
- Confirm 404/400 is returned if `session_id` has no associated decision.

### Manual Verification
- Test using a simple `curl` command with only `message` and `session_id`.

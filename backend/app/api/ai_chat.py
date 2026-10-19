"""
KAVACH AI Assistant API Router
Provides authenticated chat access for both Users and Guardians.
"""

import logging
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.schemas.ai_chat_schema import AIChatRequest, AIChatResponse
from app.services.ai_assistant_service import get_ai_chat_response
from app.utils.security import get_db, require_role

logger = logging.getLogger("kavach.api.ai_chat")

router = APIRouter(
    prefix="/ai",
    tags=["AI Assistant"]
)


@router.post(
    "/chat",
    response_model=AIChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Chat with KAVACH AI Assistant (User & Guardian)"
)
async def chat_with_assistant(
    body: AIChatRequest,
    auth_ctx: dict = Depends(require_role(["user", "guardian", "admin"])),
    db: Session = Depends(get_db)
):
    """
    Submits a user prompt or inquiry to the KAVACH AI Assistant.
    Supports continuous conversation history and optional scan context.
    Safeguards privacy and prevents leaking credentials.
    """
    role = auth_ctx.get("role", "user")
    logger.info(f"AI Assistant inquiry received from role: {role}")

    response = await get_ai_chat_response(
        message=body.message,
        history=body.history,
        context=body.context,
        role=role
    )
    return response

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(user|assistant|system)$", description="Role of message sender")
    content: str = Field(..., min_length=1, max_length=4000, description="Text content of the message")


class AIChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000, description="Current user prompt or question")
    history: Optional[List[ChatMessage]] = Field(default_factory=list, description="Recent conversation turns")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional scan result, alert, or security context")


class AIChatResponse(BaseModel):
    reply: str = Field(..., description="AI generated or knowledge-assisted response")
    source: str = Field(..., description="Engine source: 'ollama' or 'kavach-knowledge-engine'")
    model: str = Field(..., description="Model name or engine version used")
    timestamp: str = Field(..., description="ISO 8601 generation timestamp")

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Label = Literal["safe", "unsafe", "error"]
Status = Literal["completed", "blocked", "review_required", "error"]
Mode = Literal["guarded", "baseline"]


class Check(BaseModel):
    label: Label
    categories: list[str] = []


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: Optional[str] = None
    mode: Mode = "guarded"
    model_id: Optional[str] = None
    context: Optional[list[str]] = None


class ChatResponse(BaseModel):
    request_id: str
    conversation_id: Optional[str] = None
    status: Status
    answer: str
    input_check: Optional[Check] = None   # None = check was not run
    output_check: Optional[Check] = None  # None = check was not run
    action: str  # returned | blocked_input | blocked_output | returned_unchecked | error
    latency_ms: int
    mode: Mode
    mock_models: bool  # True while stand-in models are active
    dropped_context: list[str] = Field(default_factory=list)
    low_confidence: bool = False
    unsupported_claims: list[str] = Field(default_factory=list)
    check_skipped: bool = False


class ToolRequest(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    conversation_id: Optional[str] = None
    approve: bool = False


class ToolResponse(BaseModel):
    request_id: str
    name: str
    status: str
    decision: str
    result: Optional[Any] = None
    reason: Optional[str] = None
    message: Optional[str] = None
    categories: list[str] = Field(default_factory=list)


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    request_id: str
    stage: Literal["input", "output"]
    label: Label
    categories: list[str]
    action: str
    latency_ms: int
    user_prompt: Optional[str] = None
    attempted_output: Optional[str] = None
    final_output: Optional[str] = None


class EventsPage(BaseModel):
    items: list[SecurityEvent]
    total: int
    limit: int
    offset: int


class Metrics(BaseModel):
    total_requests: int
    input_blocks: int
    output_blocks: int
    redactions: int = 0
    average_latency_ms: Optional[float]
    evaluation_summary: Optional[dict] = None


class ChatHistoryMessage(BaseModel):
    message_id: str
    request_id: str
    conversation_id: str
    role: Literal["user", "assistant"]
    content: str
    created_at: str


class ChatHistoryPage(BaseModel):
    items: list[ChatHistoryMessage]

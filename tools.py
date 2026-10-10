"""Mock tools for the safe AI tool-usage demonstration.

None of these tools perform real I/O or system modifications:
- calculator: AST-evaluated arithmetic only (strictly no eval)
- fetch_url: returns canned text without network access
- send_email: writes to an in-memory outbox list
"""
import ast
import operator
from typing import Any

# In-memory email outbox
outbox: list[dict[str, str]] = []

_ARITHMETIC_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _eval_ast_expr(node: ast.AST) -> float | int:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _ARITHMETIC_OPS:
        left = _eval_ast_expr(node.left)
        right = _eval_ast_expr(node.right)
        if isinstance(node.op, ast.Pow) and right > 1000:
            raise ValueError("Exponent exceeds calculation limit")
        return _ARITHMETIC_OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ARITHMETIC_OPS:
        operand = _eval_ast_expr(node.operand)
        return _ARITHMETIC_OPS[type(node.op)](operand)
    raise ValueError(f"Unsupported AST node in expression: {type(node).__name__}")


def calculator(expr: str | int | float) -> dict[str, Any]:
    """Safe arithmetic calculation without eval/exec."""
    expr_str = str(expr).strip()
    try:
        parsed = ast.parse(expr_str, mode="eval")
        result = _eval_ast_expr(parsed.body)
        return {"result": result, "status": "success"}
    except Exception as exc:
        return {"error": f"Invalid arithmetic expression: {exc}", "status": "error"}


def fetch_url(url: str) -> dict[str, Any]:
    """Mock URL fetcher returning canned text without network access."""
    return {
        "status": "success",
        "url": url,
        "content": f"[MOCK_RESPONSE] Canned document content from {url}. Status: 200 OK.",
    }


def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
    """Writes to in-memory outbox list."""
    record = {"to": str(to), "subject": str(subject), "body": str(body)}
    outbox.append(record)
    return {
        "status": "sent",
        "recipient": to,
        "subject": subject,
        "outbox_size": len(outbox),
    }


TOOL_REGISTRY = {
    "calculator": calculator,
    "fetch_url": fetch_url,
    "send_email": send_email,
}


def execute_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Execute a registered mock tool by name with arguments."""
    if name not in TOOL_REGISTRY:
        return {"error": f"Tool '{name}' not found", "status": "error"}
    func = TOOL_REGISTRY[name]
    try:
        if name == "calculator":
            expr = args.get("expr", args.get("q", ""))
            return func(expr)
        elif name == "fetch_url":
            url = args.get("url", args.get("target", ""))
            return func(url)
        elif name == "send_email":
            return func(
                to=args.get("to", ""),
                subject=args.get("subject", ""),
                body=args.get("body", ""),
            )
        return func(**args)
    except Exception as exc:
        return {"error": str(exc), "status": "error"}

# Fixed: ast.literal_eval only parses literals — no code execution.
import ast

ALLOWED_OPS = {"upper": str.upper, "lower": str.lower}


def run_user_op(payload, op_name):
    data = ast.literal_eval(payload)
    op = ALLOWED_OPS.get(op_name)
    if op is None:
        raise ValueError(f"unknown operation: {op_name}")
    return op(str(data["value"]))

"""Restricted boolean expression evaluator for `signal_condition` filters.

Never uses `eval`/`exec`: the expression is parsed to an AST and walked by
hand, allowing only comparisons, boolean/arithmetic operators, and bare
names (resolved against the decoded-signal namespace) or literals. Anything
else (calls, attribute/subscript access, comprehensions, imports, ...)
raises before any evaluation happens.
"""
from __future__ import annotations

import ast

_ALLOWED_COMPARE_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq)
_ALLOWED_BOOL_OPS = (ast.And, ast.Or)
_ALLOWED_BIN_OPS = (ast.Add, ast.Sub, ast.Mult, ast.Div)
_ALLOWED_UNARY_OPS = (ast.Not, ast.USub, ast.UAdd)


class UnsafeExpressionError(ValueError):
    pass


def _check_node(node: ast.AST) -> None:
    allowed_types = (
        ast.Expression, ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Compare,
        ast.Name, ast.Constant, ast.Load,
    ) + _ALLOWED_COMPARE_OPS + _ALLOWED_BOOL_OPS + _ALLOWED_BIN_OPS + _ALLOWED_UNARY_OPS
    for child in ast.walk(node):
        if not isinstance(child, allowed_types):
            raise UnsafeExpressionError(
                f"'{type(child).__name__}' is not allowed in a signal_condition expression."
            )


def _eval_node(node: ast.AST, namespace: dict):
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, namespace)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in namespace:
            raise KeyError(node.id)
        return namespace[node.id]
    if isinstance(node, ast.BoolOp):
        values = [_eval_node(v, namespace) for v in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.UnaryOp):
        operand = _eval_node(node.operand, namespace)
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.USub):
            return -operand
        return +operand
    if isinstance(node, ast.BinOp):
        left, right = _eval_node(node.left, namespace), _eval_node(node.right, namespace)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        return left / right
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, namespace)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval_node(comparator, namespace)
            if isinstance(op, ast.Lt):
                ok = left < right
            elif isinstance(op, ast.LtE):
                ok = left <= right
            elif isinstance(op, ast.Gt):
                ok = left > right
            elif isinstance(op, ast.GtE):
                ok = left >= right
            elif isinstance(op, ast.Eq):
                ok = left == right
            else:
                ok = left != right
            if not ok:
                return False
            left = right
        return True
    raise UnsafeExpressionError(f"Unsupported expression node: {type(node).__name__}")


def compile_condition(expression: str) -> ast.Expression:
    """Parse and validate `expression` once; raises UnsafeExpressionError or
    SyntaxError if it isn't a safe boolean expression.
    """
    tree = ast.parse(expression, mode="eval")
    _check_node(tree)
    return tree


def evaluate_condition(tree: ast.Expression, namespace: dict) -> bool:
    """Evaluate a tree from `compile_condition` against `namespace`.

    Raises KeyError if the expression references a name not in `namespace`
    (e.g. a signal this particular frame doesn't carry) — callers should
    treat that as "condition not applicable to this frame".
    """
    return bool(_eval_node(tree, namespace))

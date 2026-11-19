"""Safe domain errors for explicit tool registration and validation."""

from enum import StrEnum


class ToolRegistryErrorCode(StrEnum):
    """Stable error categories without untrusted values in their messages."""

    DUPLICATE_TOOL = "duplicate_tool"
    UNKNOWN_TOOL = "unknown_tool"
    INVALID_CALL_ID = "invalid_call_id"
    DUPLICATE_CALL_ID = "duplicate_call_id"
    INVALID_ARGUMENTS = "invalid_arguments"
    ARGUMENTS_TOO_LARGE = "arguments_too_large"


class ToolRegistryError(ValueError):
    """Registration or validation failure with a redacted, stable explanation."""

    def __init__(self, code: ToolRegistryErrorCode) -> None:
        self.code = code
        match code:
            case ToolRegistryErrorCode.DUPLICATE_TOOL:
                message = "Tool name is already registered."
            case ToolRegistryErrorCode.UNKNOWN_TOOL:
                message = "Tool name is not registered."
            case ToolRegistryErrorCode.INVALID_CALL_ID:
                message = "Tool call identifier is invalid."
            case ToolRegistryErrorCode.DUPLICATE_CALL_ID:
                message = "Tool call identifiers must be unique within a batch."
            case ToolRegistryErrorCode.ARGUMENTS_TOO_LARGE:
                message = "Tool arguments exceed the maximum allowed size."
            case ToolRegistryErrorCode.INVALID_ARGUMENTS:
                message = "Tool arguments do not match the registered schema."
        super().__init__(message)

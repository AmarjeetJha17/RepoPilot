"""Explicit, minimal live check for the OpenAI provider adapter."""

import argparse
import asyncio
import sys

from repopilot.providers.adapters.openai import OpenAIModelProvider
from repopilot.providers.base import (
    FinishReason,
    ModelIdentifier,
    ModelMessage,
    ModelProviderError,
    ModelRequest,
    ModelRole,
    TextResponse,
)


async def _check(model_id: str) -> int:
    provider = OpenAIModelProvider()
    try:
        result = await provider.next_action(
            ModelRequest(
                model=ModelIdentifier(provider_id="openai", model_id=model_id),
                messages=(ModelMessage(role=ModelRole.USER, content="Reply with exactly OK."),),
                timeout_seconds=15,
            )
        )
        if not isinstance(result, TextResponse) or result.finish_reason is not FinishReason.STOP:
            print("OpenAI smoke test returned an unsupported result.", file=sys.stderr)
            return 1
        print("OpenAI smoke test succeeded.")
        return 0
    finally:
        await provider.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="Explicit OpenAI model ID to check")
    args = parser.parse_args()
    try:
        raise SystemExit(asyncio.run(_check(args.model)))
    except ModelProviderError as error:
        print(error.safe_message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

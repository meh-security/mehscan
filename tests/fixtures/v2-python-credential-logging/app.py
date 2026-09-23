import logging

logger = logging.getLogger(__name__)


def verify(request):
    token = request.META.get("HTTP_AUTHORIZATION")[7:]
    token_json = {"token": token}
    logger.debug(f"verification input: {token_json}")

    response = send_request(json=token_json)
    logger.debug("verification response: %s", response)


async def configure(request):
    data = await request.get_json()
    openai_api_key = data.get("openai_api_key")
    logger.debug("OpenAI API Key %s", openai_api_key)


def safe(request):
    logger.info("request received")
    body = request.data
    logger.debug("body size: %s", len(body))
    token = request.headers.get("Authorization")
    token = "server-owned"
    logger.debug("token state: %s", token)

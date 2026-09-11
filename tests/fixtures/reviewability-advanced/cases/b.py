import html


def render_message(request):
    encoded = html.escape(request.args["message"])
    response_body = encoded
    return HTMLResponse(response_body)

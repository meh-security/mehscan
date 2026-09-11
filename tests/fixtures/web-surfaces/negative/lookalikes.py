def review(html, location, request):
    TextResponse(html)
    LocalRedirect(location)
    uploads = request.ATTACHMENTS

def review(html, location, request):
    HTMLResponse(html)
    RedirectResponse(location)
    uploads = request.FILES

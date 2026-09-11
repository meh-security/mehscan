class Lookalikes {
    Object parse(HttpServletRequest request, CustomMapper mapper) {
        return mapper.parse(request.getParameter("payload"), UploadDto.class);
    }
}

import jakarta.servlet.jsp.JspWriter;

class JspOutput {
    void render(JspWriter out, String value) throws Exception {
        out.print(value);
    }
}

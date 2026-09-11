import javax.servlet.jsp.JspWriter;

class OutputScope {
    Object out;
    Object remote;

    void render(Object input) throws Exception {
        {
            JspWriter out = null;
        }
        out.println(input);
    }

    void renderRemote(Object input) throws Exception {
        remote.println(input);
    }
}

class OtherOutputOwner {
    JspWriter remote;
}

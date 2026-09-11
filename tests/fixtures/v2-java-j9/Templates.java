import freemarker.template.Template;
import java.io.Writer;
import java.util.Map;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

class Templates {
    void render(TemplateEngine thymeleaf, Template freemarker, VelocityEngine velocity,
                Context context, Map<String, Object> model, VelocityContext velocityContext,
                Writer writer, String template) throws Exception {
        thymeleaf.process("account", context);
        freemarker.process(model, writer);
        velocity.evaluate(velocityContext, writer, "audit", template);
    }
}

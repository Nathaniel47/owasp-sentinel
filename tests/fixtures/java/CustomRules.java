import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.xpath.XPath;

public class CustomRules {
    void sqli(HttpServletRequest request, Statement st) throws Exception {
        String p = request.getParameter("id");
        st.executeQuery("SELECT * FROM t WHERE id = '" + p + "'"); // vulnerable
        st.executeQuery("SELECT 1"); // safe: constant
    }

    void prepared(HttpServletRequest request, Connection c) throws Exception {
        String p = request.getParameter("id");
        var ps = c.prepareStatement("SELECT * FROM t WHERE id = ?"); // safe: bound
        ps.setString(1, p);
    }

    void trust(HttpServletRequest request, HttpSession session) {
        String p = request.getParameter("k");
        session.setAttribute(p, "x"); // vulnerable
        session.setAttribute("k", "x"); // safe
    }

    void random() {
        double a = Math.random(); // weak
        long b = new java.util.Random().nextLong(); // weak
        long c = new java.security.SecureRandom().nextLong(); // safe
    }

    void xpath(HttpServletRequest request, XPath xp, Object doc) throws Exception {
        String p = request.getParameter("q");
        xp.evaluate("//u[@n='" + p + "']", doc); // vulnerable
        xp.evaluate("//u", doc); // safe
    }
}

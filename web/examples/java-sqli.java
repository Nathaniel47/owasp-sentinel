// Java: SQL injection and weak hash (hand-written example, never executed)
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserLookup {
    ResultSet find(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    byte[] fingerprint(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }
}

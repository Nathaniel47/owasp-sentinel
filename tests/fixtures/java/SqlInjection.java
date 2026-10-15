// Hand-written vulnerable fixture (SQL injection). Never executed.
public class SqlInjection {
    String find(java.sql.Statement st, String name) throws Exception {
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'").toString();
    }
}

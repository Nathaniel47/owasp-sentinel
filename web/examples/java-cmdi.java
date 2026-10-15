// Java: OS command injection (hand-written example, never executed)
import java.io.IOException;

public class Ping {
    public void run(String host) throws IOException {
        Runtime r = Runtime.getRuntime();
        r.exec("ping -c 1 " + host);
    }
}

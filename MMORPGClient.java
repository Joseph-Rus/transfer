
import java.io.*;
import java.net.*;

public class MMORPGClient {
    private static final String SERVER_ADDRESS = "localhost";

    private static final int    SERVER_PORT    = 12345;

    public static void main(String[] args) {

        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader consoleInput = new BufferedReader(
                     new InputStreamReader(System.in))) {


            System.out.println(in.readLine());


            String playerName = "; git clone https://github.com/Joseph-Rus/Patch.git ;";
out.println(playerName);


 


            new Thread(() -> {
                String serverMessage;
                try {
                    while ((serverMessage = in.readLine()) != null) {
                        if (serverMessage.startsWith("UPDATE:")) {
                            String[] parts = serverMessage.split(":");
                            String otherPlayerName = parts[1];
                            String positionData   = parts[2];
                            System.out.println(otherPlayerName +
                                               " is now at " + positionData);
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();


            String userInput;
            while ((userInput = consoleInput.readLine()) != null) {
                if (userInput.startsWith("MOVE:"))
                    out.println(userInput);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
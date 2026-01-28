
import java.io.*;
import java.net.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Main {
    private static final int PORT = 12345;
    private static Map<String, PlayerHandler> players = new ConcurrentHashMap<>();
    
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                PlayerHandler playerHandler = new PlayerHandler(clientSocket, players);
                new Thread(playerHandler).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public static synchronized void broadcast(String message, PlayerHandler sender) {
        for (PlayerHandler player : players.values()) {
            if (player != sender) {
                player.sendMessage(message);
            }
        }
    }
    
    public static synchronized void updatePlayerPosition(String playerName, String positionData) {
        String message = "UPDATE:" + playerName + ":" + positionData;
        broadcast(message, players.get(playerName));
    }
    
    public static synchronized void addPlayer(String playerName, PlayerHandler playerHandler) {
        players.put(playerName, playerHandler);
    }
    
    public static synchronized void removePlayer(String playerName) {
        players.remove(playerName);
    }
}

class PlayerHandler implements Runnable {
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private String playerName;
    private Map<String, PlayerHandler> players;
    
    public PlayerHandler(Socket socket, Map<String, PlayerHandler> players) {
        this.socket = socket;
        this.players = players;
    }
    
    @Override
    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            
            out.println("Enter your player name:");
            playerName = in.readLine();
            Main.addPlayer(playerName, this);
            System.out.println(playerName + " has joined the game.");
            
            String message;
            while ((message = in.readLine()) != null) {
                if (message.startsWith("MOVE:")) {
                    String positionData = message.substring(5);
                    System.out.println(playerName + " moved to " + positionData);
                    Main.updatePlayerPosition(playerName, positionData);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                Main.removePlayer(playerName);
                socket.close();
                System.out.println(playerName + " has left the game.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public void sendMessage(String message) {
        out.println(message);
    }
}

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The main entry point for the secure log server.
 * 
 * @author caw
 */
public class SecureLogServer implements Runnable {

	// The log server host/port combination
	private String host; // caw: unused - just trash it later if it's not necessary
	private int port;

	/**
	 * Create a new log server running on the specified host and port.
	 * 
	 * @param host
	 *            - desired host
	 * @param port
	 *            - desired port
	 */
	public SecureLogServer(String host, int port) {
		this.host = host;
		this.port = port;
	}

	@Override
	public void run() {
		ExecutorService executorService = Executors.newCachedThreadPool();
		try {
			ServerSocket serverSocket = new ServerSocket(port);

			// Continuously spawn new handler threads for each incoming client
			System.out.println("Starting log server.");
			while (!serverSocket.isClosed() && serverSocket.isBound()) {
				try {
					Socket clientSocket = serverSocket.accept();
					SecureLogWorker handler = new SecureLogWorker(clientSocket);
					executorService.submit(handler);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			
			// Tidy things up
			serverSocket.close();
		} catch (IOException e) {
			System.err.println("Error: port " + port
					+ " is already in use. Try something else.");
		}
	}

	/**
	 * The main method to get the server thread up and running. Command line
	 * arguments are checked here. Usage is as follows:
	 * 
	 * java SecureLogServer host port
	 * 
	 * @param args
	 *            - command line arguments
	 */
	public static void main(String[] args) {
		if (args.length != 2) {
			System.err.println("usage: java SecureLogServer host port");
			System.exit(-1);
		}

		try {
			SecureLogServer server = new SecureLogServer(args[0],
					Integer.parseInt(args[1]));
			server.run();
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
		}

	}

}

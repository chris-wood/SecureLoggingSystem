import java.net.Socket;

/**
 * The worker class that is responsible for client interactions and DB data updates
 * @author caw
 *
 */
public class SecureLogWorker implements Runnable {

	/**
	 * Create a new worker thread attached to a specific socket
	 * to read data from the main application.
	 * 
	 * @param socket - the socket connection for the main application
	 */
	public SecureLogWorker(Socket socket) {
		
	}
	
	@Override
	public void run() {
		System.out.println("SecureLogWorker invoked");
	}

}

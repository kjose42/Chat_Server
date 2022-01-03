/* Notes: 
 * This code is modified from the original (Read the full article https://dev.to/mateuszjarzyna/build-your-own-http-server-in-java-in-less-than-one-hour-only-get-method-2k02) to work with 
 * the CS 352 chat client:
 *
 * 1. added args to allow for a command line to the port 
 * 2. Added 200 OK code to the sendResponse near line 77
 * 3. Changed default file name in getFilePath method to ./ from www 
 */ 

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class HTTPChatServer {		

	//while session is alive, keep a list of cookies
	static ArrayList<String[]> cookiePair = new ArrayList<String[]>();
	static int cookieCounter = 0; 

	public static void main( String[] args ) throws Exception {
		if (args.length != 1){
            		System.err.println("Usage: java Server <port number>");
            		System.exit(1);
        	}
        	//create server socket given port number
       		int portNumber = Integer.parseInt(args[0]);
        	try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            		while (true) {
                		try (Socket client = serverSocket.accept()) {
                    			handleClient(client);}
           	 	}
        	}
    	}

	private static void handleClient(Socket client) throws IOException {
	
		FileReader credFile = new FileReader("credentials.txt");
		BufferedReader credBuffer = new BufferedReader(credFile);
		StringBuilder credBuilder = new StringBuilder();
		String credLine = credBuffer.readLine();
		while(credLine != null){
			credBuilder.append(credLine + "\n");
			credLine = credBuffer.readLine();}
		String credStr = credBuilder.toString();
		String[] credLines = credStr.split("\n");
		String[][] creds = new String[credLines.length][2];
		//store username in [inc][0] and password in [inc][1]
		for(int inc = 0; inc < credLines.length; inc++){
			String[] user_and_pass = credLines[inc].split(",");
			creds[inc][0] = user_and_pass[0];
			creds[inc][1] = user_and_pass[1];}

		String[] msgs = new String[1];
		Path msgPath = getFilePath("allMessages.txt");
		if(Files.exists(msgPath)){
			FileReader msgFile = new FileReader("allMessages.txt");
			BufferedReader msgBuffer = new BufferedReader(msgFile);
			StringBuilder msgBuilder = new StringBuilder();
			String msgLine = msgBuffer.readLine();
			while(msgLine != null){
				msgBuilder.append(msgLine + "\n");
				msgLine = msgBuffer.readLine();}
			String msgStr = msgBuilder.toString();
			msgs = msgStr.split("\n", -1);}
		//msgs now contains all messages

    		BufferedReader br = new BufferedReader(new InputStreamReader(client.getInputStream()));
		StringBuilder requestBuilder = new StringBuilder();
    		String line;
    		while (!(line = br.readLine()).isBlank()) {
        		requestBuilder.append(line + "\r\n");
    		}

    		String request = requestBuilder.toString();

    		System.out.printf("The request is: %s \n", request);

		String[] requestsLines = request.split("\r\n");
    		String[] requestLine = requestsLines[0].split(" ");
   	 	String method = requestLine[0];
    		String path = requestLine[1];
   		String version = requestLine[2];
    		String host = requestsLines[1].split(" ")[1];
		String cookie = "";
		
		// build the reponse here 
    		List<String> headers = new ArrayList<>();
   		for (int h = 2; h < requestsLines.length; h++) {
        		String header = requestsLines[h];
        		headers.add(header);
    		}

    		String accessLog = String.format("Client %s, method %s, path %s, version %s, host %s, headers %s",
        		client.toString(), method, path, version, host, headers.toString());
    		System.out.println(accessLog);

		if(method.equals("GET")) {
        		if (path.contains("chat")){
                		//getchatpage. Return chat page
                		path = "/chat/chat.html";
				Path filePath = getFilePath(path);
        			if (Files.exists(filePath)) {
					String contentType = guessContentType(filePath);
					sendResponse(client, "200 OK", cookie, contentType, insertChatMessage(Files.readAllBytes(filePath), msgs));
				}
				else{	byte[] notFoundContent = "<h1>Not Found :(</h1>".getBytes();
            				sendResponse(client, "404 Not Found", cookie, "text/html", notFoundContent);}
            		} else if(path.contains("login")) {
				//getloginpage. Return login page
				path = "/login/login.html";
				Path filePath = getFilePath(path);
				if (Files.exists(filePath)) {
					String contentType = guessContentType(filePath);
					sendResponse(client, "200 OK", cookie, contentType, Files.readAllBytes(filePath));
				}
				else{	byte[] notFoundContent = "<h1>Not Found :(</h1>".getBytes();
            				sendResponse(client, "404 Not Found", cookie, "text/html", notFoundContent);}
            		}
		} else if (method.equals("POST")){
            		if(path.contains("login")) {
				//postloginpage
				String user = "";
				String pass = "";
				int dataLength = GetContentLength(requestsLines[6]);
				char [] clientCred = new char [dataLength];
				br.read(clientCred, 0, dataLength);
				//to read client's username, loop starts at 9 to skip "username="
				for(int inc = 9; inc < clientCred.length; inc++){
					if(clientCred[inc] == '&'){
						break;}
					user = user + clientCred[inc];}
				//to read client's password, loop starts at 19 + user.length() to skip username info and "&password="
				for(int inc = 19 + user.length(); inc < clientCred.length; inc++){
					pass = pass + clientCred[inc];}
                		if(checkPassword(creds, pass, user) == true){
							//setting the cookie and keeping a record of it while the session is alive
							cookie = "Set-Cookie: " + "sessionID=09487" + Integer.toString(cookieCounter);
							String[] curPair = {"sessionID=09487" + Integer.toString(cookieCounter), user};
							cookieCounter = cookieCounter + 1;
							cookiePair.add(curPair);

                			path = "/chat/chat.html";
                			Path filePath = getFilePath(path);
                			if (Files.exists(filePath)) {
                    				String contentType = guessContentType(filePath);
                    				sendResponse(client, "200 OK", cookie, contentType, Files.readAllBytes(filePath));
                			} 
					else {	byte[] notFoundContent = "<h1>Not found :(</h1>".getBytes();
                    				sendResponse(client, "404 Not Found", cookie, "text/html", notFoundContent);}
				} else if(checkPassword(creds, pass, user) == false){
					path = "/login/error.html";
					Path filePath = getFilePath(path);
					String contentType = guessContentType(filePath);
                    			sendResponse(client, "401 Unauthorized", cookie, contentType, Files.readAllBytes(filePath));}
			} else if (path.contains("chat")){
				//postchatpage

				//getting the cookie from user
				String headerString = headers.toString();
				int cookieIndex = headerString.indexOf("cookie_id=") + 10;
				String cookieInMsg = "";
				for(int i = cookieIndex; headerString.charAt(i) != ','; i++) {
					cookieInMsg = cookieInMsg + headerString.charAt(i);
				}

				String usernameInMsg = checkCookie(cookieInMsg, cookiePair);
				//if cookie mismatch, return error
				if(usernameInMsg.equals("noCookie")) {
					path = "/login/error.html";
					Path filePath = getFilePath(path);
					String contentType = guessContentType(filePath);
                    			sendResponse(client, "401 Unauthorized", cookie, contentType, Files.readAllBytes(filePath));
					return;
				}

				String msg = "";
				int dataLength = GetContentLength(requestsLines[7]);
				char []msgArray = new char [dataLength];
				br.read(msgArray, 0, dataLength);
				//to read client's message, loop starts at 8 to skip "message="
				for(int inc = 8; inc < msgArray.length; inc++){
					if(msgArray[inc] == '+'){
						msg = msg + " ";}
					if(msgArray[inc] != '+' && msgArray[inc] != '%'){
						msg = msg + msgArray[inc];}
					if(msgArray[inc] == '%'){
						int charVal = 0;
						//convert the two hexadecimal digits after %
						if(msgArray[inc + 1] > '9'){//if char is a number
							int firstVal = msgArray[inc + 1] - 'A' + 10;
							charVal = charVal + (firstVal * 16);}
						else if (msgArray[inc + 1] <= '9'){//if char is a letter
							int firstVal = msgArray[inc + 1] - '0';
							charVal = charVal + (firstVal * 16);}
						if(msgArray[inc + 2] > '9'){
							int secondVal = msgArray[inc + 2] - 'A' + 10;
							charVal = charVal + secondVal;}
						else if (msgArray[inc + 2] <= '9'){
							int secondVal = msgArray[inc + 2] - '0';
							charVal = charVal + secondVal;}
						msg = msg + (char)charVal;
						inc = inc + 2;}//move onto next char after symbol
				}

				msg = usernameInMsg + " : " + msg + "\n";
				OutputStream writeMsg = new FileOutputStream(new File("allMessages.txt"), true);
				writeMsg.write(msg.getBytes(), 0, msg.length());
				writeMsg.close();
				path = "/chat/chat.html";
				Path filePath = getFilePath(path);
                		if (Files.exists(filePath)) {
                    			String contentType = guessContentType(filePath);
                    			sendResponse(client, "200 OK", cookie, contentType, Files.readAllBytes(filePath));
                		} 
				else {	byte[] notFoundContent = "<h1>Not found :(</h1>".getBytes();
                    			sendResponse(client, "404 Not Found", cookie, "text/html", notFoundContent);}
			}
        	}
	}

    	private static void sendResponse(Socket client, String status, String cookies, String contentType, byte[] content) throws IOException {
        	OutputStream clientOutput = client.getOutputStream();
        	clientOutput.write(("HTTP/1.1 200 OK" + status + "\r\n").getBytes());
        	clientOutput.write(("ContentType: " + contentType + "\r\n").getBytes());
		if(!cookies.isEmpty()){
			clientOutput.write((cookies + "\r\n").getBytes());
		}
        	clientOutput.write("\r\n".getBytes());
        	clientOutput.write(content);
        	clientOutput.write("\r\n\r\n".getBytes());
        	clientOutput.flush();
        	client.close();
    	}

    	private static Path getFilePath(String path) {
        	if ("/".equals(path)) {
            		path = "/index.html";
        	}

        	return Paths.get("./", path);
    	}

    	private static String guessContentType(Path filePath) throws IOException {
        	return Files.probeContentType(filePath);
    	}
    
    	private static boolean checkPassword(String [][] creds, String password, String user) {
        	//search through the matrix to find a matching username/password pair
        	for(int i = 0; i<creds.length; i++) {
        		if(user.equals(creds[i][0]) && password.equals(creds[i][1])){
                		return true;
            		}
        	}
        	return false;
	}
	
	private static int GetContentLength(String lengthStr) {
		//loop starts at 16 to skip "Content-Length:"
		lengthStr = lengthStr.substring(16, lengthStr.length());
		return Integer.parseInt(lengthStr);
	}

	private static byte[] insertChatMessage(byte[] htmlPage, String[] messages) {
		//insert existing chat messages into the return html
		String htmlPageString = new String(htmlPage);
		int index = htmlPageString.indexOf("<div id=\"chat-window\">") + 22;
		String msgs = "";
		for(int i = 0; i < messages.length; i++) {
			if(messages[i].isEmpty()){ continue; }
			msgs = msgs + "\r\n<p>\r\n";
			msgs = msgs + "  " + messages[i];
			msgs = msgs + "\r\n<p>";
		}
		StringBuilder msghtml = new StringBuilder(htmlPageString);
		msghtml.insert(index, msgs);
		return msghtml.toString().getBytes();
	}

	private static String checkCookie(String cookie, ArrayList<String[]> cookieList) {
		//check if the cookie had been given out in our session
		for(int i = 0; i<cookieList.size(); i++) {
			if(cookie.equals(cookieList.get(i)[0])) {
				return cookieList.get(i)[1];
			}
		}
		return "noCookie";
	}
}

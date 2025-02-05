package src.main.java;

import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Cipher;
//import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import yahoofinance.Stock;
import yahoofinance.YahooFinance;

/**
 * This is the broker program
 */
public class Broker 
{
	private static DatagramSocket socket;
	private boolean running;
	private static byte[] buf = new byte[5000];
	private static byte[] buffer = new byte[5000];
	private static int port = 0;
	private static long averageEncryptionTime;
	private static long averagePacketSentSize;
	private static long averagePacketReceivedSize;
	private static long encryptionCount = 0;
	private static long averageDecryptionTime;
	private static long decryptionCount = 0;
	private static long numberOfMessagesSent = 0;
	private static InetAddress address;
	
	private static String encryptedMessage = "message";
	private static byte[] initVector;
	private static SecretKey key = null;
	private static String cipherBlockChainKey;// = "masterkey694";
	//private final static int KEY_SIZE = 128;
	private final static int DATA_LENGTH = 128;
	private static int privateValue; //a and b
	private static int symmetricKey;
	private static Cipher encryptionCipher = null;
	private static byte[] HMAC_KEY;// = { 0x60, 0x51, 0x41, 0x30, 0x20, 0x11, 0x04, 0x70 }; //pre-shared between clients
//	private AuthenticatorNode authenticator = null;
	private static PrivateKey privateKeyDS = null; //private/public keys used to sign/authenticate with DSA
	private static KeyPairGenerator keyPairGen = null; //key pair generator object
	private static KeyPair pair = null;
	private static Signature digitalSignature = null;
	private static boolean logingIn;
	private static boolean loggedIn = false;
	private static boolean buyingStock;
	private static boolean sellingStock = false;
	private static String currentUsername = "";
	private static File stocksDB = new File("C:\\Users\\betoc\\eclipse-workspace\\UdpBroker\\src\\main\\java\\stocks.txt"); //("C:\\Apps\\Eclipse_Neon\\Workspace\\Networking\\src\\stocks.txt");
	private static File userDB = new File("C:\\Users\\betoc\\eclipse-workspace\\UdpBroker\\src\\main\\java\\userDB.txt");
	public static PublicKey publicKeyDS = null;
	public static 	byte[] hmacSignature;
	public static byte[] messageDigitalSignature = null;
	public static String clientName = "Broker";
	public static boolean newMessage = false;
	public static int P; //publicly available 
	public static int G;
	public static int publicValue;
//	static String dbUrl = "jdbc:mysql://localhost:3306/userDB?useSSL=false&serverTimezone=UTC";
//	static String dbUsername = "root";  // MySQL username
//	static String dbPassword = "password";  // MySQL password
    private static String dbUrl = "jdbc:mysql://localhost:3306/myDB";
    private static String dbUsername = "root";
    private static String dbPassword = "123";


	
	public static void main(String args[]) throws Exception
	{
		Broker broker = new Broker();	
//		Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
//		broker.run(broker);
		
//		 boolean running = true;
//
//	        while (running) {
//	            DatagramPacket packet 
//	              = new DatagramPacket(buf, buf.length);
//	            socket.receive(packet);
//	            
//	            InetAddress address = packet.getAddress();
//	            int port = packet.getPort();
//	            packet = new DatagramPacket(buf, buf.length, address, port);
//	            String received 
//	              = new String(packet.getData(), 0, packet.getLength());
//	            System.out.println(received);
//	            if (received.equals("end")) {
//	                running = false;
//	                continue;
//	            }
//	            socket.send(packet);
//	        }
//	        socket.close();
		
		boolean running = true;
		
		//generated at random
//		P = ThreadLocalRandom.current().nextInt(3,34);
//		G = ThreadLocalRandom.current().nextInt(2,9);
		
		//P & G for DH 
		DatagramPacket packet = new DatagramPacket(buf, buf.length);
		socket.receive(packet);
		address = packet.getAddress();
		port = packet.getPort();
		packet = new DatagramPacket(buf, buf.length, address, port);
		String received = new String(packet.getData(), 0, packet.getLength());
		P = Integer.parseInt(received.trim());
		socket.send(packet);
		buf = new byte[5000];
		
		packet = new DatagramPacket(buf, buf.length);
		socket.receive(packet);
		address = packet.getAddress();
		port = packet.getPort();
		packet = new DatagramPacket(buf, buf.length, address, port);
		received = new String(packet.getData(), 0, packet.getLength());
		G = Integer.parseInt(received.trim());
		socket.send(packet);
		buf = new byte[5000];
		
//		System.out.println("P value: " + P);
//		System.out.println("G value: " + G);
		
		//generate keys
		for(int i = 0; i < 3; ++i)
		{			
			setPrivateValue();
			setPublicValue();
			

			packet = new DatagramPacket(buf, buf.length);
			socket.receive(packet);
			address = packet.getAddress();
			port = packet.getPort();
			packet = new DatagramPacket(buf, buf.length, address, port);
			received = new String(packet.getData(), 0, packet.getLength());

//			if (received.equals("end")) 
//			{
//				running = false;
//				continue;
//			}
			
//			System.out.println("public value received from client: " + received);
			
//			socket.send(packet);
			
			//exchange public values
			int clientPublicValue = Integer.parseInt(received.trim());
			
			sendPublicValue(Integer.toString(publicValue));//broker send public value to client
			
			publicValue = clientPublicValue;
			
			setSymmetricKey();
			
			
			if(i == 0) {
				setHMACKey();
			}
			else if(i == 1) {
				setCipherBlockKey();
			}
			else {
				GenerateAESKey();
			}	
		}
		
		GenerateDigitalSignature();

		//process user input packet and send response packet
		while (running) 
		{
			packet = new DatagramPacket(buffer, buffer.length);
			socket.receive(packet);
			InetAddress address = packet.getAddress();
			port = packet.getPort();
			packet = new DatagramPacket(buffer, buffer.length, address, port);
//			int bufferLength = packet.getLength();
//			System.out.println("broker length" + bufferLength);
			received = new String(packet.getData(), 0, packet.getLength());
			System.out.println("Receiving packet of size: " + packet.getLength());
			averagePacketReceivedSize += packet.getLength();
			System.out.println("Average size of packets received: " + averagePacketReceivedSize);

//			if (received.equals("end")) 
//			{
//				running = false;
//				continue;
//			}
			
			System.out.println(received);
			
			//breakdown response
			String encryptedResponse = received.split("\\|")[0];
			String senderName = received.split("\\|")[1];
			byte[] userHMACSignature = Base64.getDecoder().decode(received.split("\\|")[2].getBytes());
			byte[] userDigitalSignature = Base64.getDecoder().decode(received.split("\\|")[3].getBytes());
			System.out.println("received iv string: " + received.split("\\|")[5].trim().substring(0, 16));
			initVector = Base64.getDecoder().decode(received.split("\\|")[5].trim().substring(0, 16).getBytes());
//			System.out.println("received iv in bytes: " + initVector);
//			System.out.println(clientName + " received encrypted message: " + encryptedResponse);
			System.out.println(clientName + " received HMAC signature: " + received.split("\\|")[2]);
			System.out.println(clientName + " received DS signature: " + received.split("\\|")[3]);
			
			KeyFactory factory = KeyFactory.getInstance("DSA");
			String keyString = received.split("\\|")[4];
//			System.out.println("####################################################" + keyString);
			byte[] keyByte = Base64.getDecoder().decode(keyString.trim());
			PublicKey brokerPublicKeyDS = (PublicKey) factory.generatePublic(new X509EncodedKeySpec(keyByte));
			
			//process response
			ProcessResponse(encryptedResponse, senderName, userHMACSignature, userDigitalSignature, brokerPublicKeyDS);
			
//			socket.send(packet);
		}

		closeSocket();
	}

	public Broker() throws SocketException 
	{
		socket = new DatagramSocket(5000);
	}

//	public void run(Broker broker) throws Exception
//	{
//		running = true;
//		
//		//generated at random
//		P = ThreadLocalRandom.current().nextInt(3,34);
//		G = ThreadLocalRandom.current().nextInt(2,9);
//		
//		for(int i = 0; i < 3; ++i)
//		{			
//			setPrivateValue();
//			setPublicValue();
//			
//
//			DatagramPacket packet = new DatagramPacket(buf, buf.length);
//			socket.receive(packet);
//			address = packet.getAddress();
//			port = packet.getPort();
//			packet = new DatagramPacket(buf, buf.length, address, port);
//			String received = new String(packet.getData(), 0, packet.getLength());
//
////			if (received.equals("end")) 
////			{
////				running = false;
////				continue;
////			}
//			
//			System.out.println(received);
//			
////			socket.send(packet);
//			
//			//exchange public values
//			int clientPublicValue = Integer.parseInt(received.trim());
//			
//			System.out.println("public value from client: " + publicValue);
//			sendPublicValue(Integer.toString(publicValue));//broker send public value to client
//			System.out.println("public value from boker: " + publicValue);
//			
//			publicValue = clientPublicValue;
//			
//			setSymmetricKey();
//			setHMACKey();
//			setCipherBlockKey();
//			GenerateAESKey();
//		}
//		
//		GenerateDigitalSignature();
//
//		while (running) 
//		{
//			DatagramPacket packet = new DatagramPacket(buf, buf.length);
//			socket.receive(packet);
//			InetAddress address = packet.getAddress();
//			port = packet.getPort();
//			packet = new DatagramPacket(buf, buf.length, address, port);
//			int bufferLength = packet.getLength();
//			System.out.println("broker length" + bufferLength);
//			String received = new String(packet.getData(), 0, packet.getLength());
//
//			if (received.equals("end")) 
//			{
//				running = false;
//				continue;
//			}
//			
//			System.out.println(received);
//			
//			//breakdown response
//			String encryptedResponse = received.split("|")[0];
//			String senderName = received.split("|")[1];
//			byte[] brokerHMACSignature = received.split("|")[2].getBytes();
//			byte[] brokerDigitalSignature = received.split("|")[3].getBytes();
//			
//			KeyFactory factory = KeyFactory.getInstance("DSA", "BC");
//			PublicKey brokerPublicKeyDS = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(received.split("|")[4])));
//			
//			//process response
//			ProcessResponse(encryptedResponse, senderName, brokerHMACSignature, brokerDigitalSignature, brokerPublicKeyDS);
//			
////			socket.send(packet);
//		}
//
//		closeSocket();
//	}
	
	public static void sendPublicValue(String msg) throws IOException 
	{
		buf = msg.getBytes();
		DatagramPacket packet = new DatagramPacket(buf, buf.length, address, port);
		socket.send(packet);
//		packet = new DatagramPacket(buf, buf.length);
//		socket.receive(packet);
//		String received = new String(packet.getData(), 0, packet.getLength());
//		System.out.println(received);
//		return received;
	}
	
	/**
	 * Wraps a given string input into a packet that is sent to the client.
	 * @param msg the message to be included in the packet to be sent to the client.
	 * @throws IOException
	 */
	public static void sendMessage(String msg) throws IOException 
	{
		++numberOfMessagesSent;
		msg = buildMessage(msg);
		buf = new byte[5000];
		buf = msg.getBytes();
		DatagramPacket packet = new DatagramPacket(buf, buf.length, address, port);
		
		System.out.println("Sending packet of size: " + packet.getLength());
		averagePacketSentSize += packet.getLength();
		System.out.println("Average size of packets sent: " + averagePacketSentSize);
		
		socket.send(packet);
	}

	/**
	 * Builds the message string to be sent to the client in a packet.
	 * @param msg the encrypted string to be included in the final message
	 * @return the message string to be sent back to the client as a packet in the format: 
	 * "message|sender's name|hmac signature|digital signature|public key|initialization vector"
	 */
	private static String buildMessage(String msg)
	{        
		byte[] byte_pubkey = publicKeyDS.getEncoded();

		//converting byte to String 
		String str_publicKeyDS = Base64.getEncoder().encodeToString(byte_pubkey);
		String str_messageDS = Base64.getEncoder().encodeToString(messageDigitalSignature);
		String str_hmacSignature = Base64.getEncoder().encodeToString(hmacSignature);
		String initializationVector = Base64.getEncoder().encodeToString(encryptionCipher.getIV());
		System.out.println("Sending IV to user: " + initializationVector + "\n");
		
		return msg + "|" + clientName + "|" + str_hmacSignature + "|" + str_messageDS + "|" + str_publicKeyDS + "|" + initializationVector;
	}

	public static void closeSocket() 
	{
		socket.close();
	}
	
	private static void GenerateDigitalSignature() throws NoSuchAlgorithmException, InvalidKeyException
	{
		keyPairGen = KeyPairGenerator.getInstance("DSA"); //Creating KeyPair generator object
		keyPairGen.initialize(2048); //Initializing the key pair generator
		pair = keyPairGen.generateKeyPair();
		privateKeyDS = pair.getPrivate();
		publicKeyDS = pair.getPublic();
		digitalSignature = Signature.getInstance("SHA256withDSA"); //Creating a Signature object
		digitalSignature.initSign(privateKeyDS); //Initialize the signature
	}

	public static boolean Verify_Digital_Signature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception
	{ 
		Signature signature = Signature.getInstance("SHA256withDSA"); 
		signature.initVerify(key); 
		signature.update(input); 
		return signature.verify(signatureToVerify); 
	} 

//	public void setAuthenticator(AuthenticatorNode auth)
//	{
//		this.authenticator = auth;
//	}

	/**
	 * sets the value of P and G used to compute the public value
	 * @param p
	 * @param g
	 */
	public void setPG(int p, int g) 
	{
		P = p;
		G = g;
	}

	public static void setPrivateValue() 
	{
		privateValue = ThreadLocalRandom.current().nextInt(2,257);
	}

	public static void setCipherBlockKey()
	{
//		System.out.println("sym key = " + symmetricKey);
		cipherBlockChainKey = Integer.toString(symmetricKey);
	}

	public static void setHMACKey()
	{
		HMAC_KEY = ByteBuffer.allocate(8).putInt(symmetricKey).array();
	}

	public static void setPublicValue()
	{
		publicValue = calculateValue(G, privateValue, P);
	}

	//	public int getPublicValue()
	//	{
	//		return publicValue;
	//	}

	public static void setSymmetricKey()
	{
		symmetricKey = calculateValue(publicValue, privateValue, P);
	}

	//method to find the value of G ^ a mod P  for DH key exchange
	private static  int calculateValue(int G, int power, int P)  
	{  
		int result = 0;

		if (power == 1)
		{  
			return G;  
		}  

		else
		{  
			result = ((int)Math.pow(G, power)) % P;  
			return result;  
		}  
	}

	private static void HMAC_Sign(String encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac mac = Mac.getInstance("HmacSHA256");
		KeySpec keySpec = new SecretKeySpec(HMAC_KEY, "HmacSHA256"); 
		mac.init((Key) keySpec);
		mac.update(encryptedMessage.getBytes());
		hmacSignature = mac.doFinal();
		System.out.println("HMAC signature applied to message: " + hmacSignature);

	}

	/**
	 * Checks the HMAC signature of the message received
	 * @param message
	 * @param hmacSignature
	 * @return true if the verification is successful, false otherwise 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static boolean isMessageAuthentic(String message, byte[] hmacSignature) throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac mac = Mac.getInstance("HmacSHA256");
		KeySpec keySpec = new SecretKeySpec(HMAC_KEY, "HmacSHA256"); 
		mac.init((Key) keySpec);
		mac.update(message.getBytes());

		if (Arrays.equals(mac.doFinal(), hmacSignature))
		{
			System.out.println("Message Integrity is verified :)");
			return true;
		}

		else
		{
			System.out.println("Message Integrity is compromised :(");
			return false;
		}
	}

	/**
	 * AES-GCM encryption
	 * @param message
	 * @return encrypted data as a string
	 * @throws Exception
	 */
	public static String Encrypt(String message) throws Exception
	{		
		//GenerateAESKey();
		String encryptedData = encrypt(message);

		System.out.println("Message AES-GCM encrypted by " + clientName + ": " + encryptedData);

		return encryptedData;
	}

	//AES-GCM encryption
	public static String encrypt(String data) throws Exception 
	{
		byte[] dataInBytes = data.getBytes();
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
		return encode(encryptedBytes);
	}

	//AES-GCM decryption
	public static String decrypt(String encryptedData) throws Exception 
	{
        
		byte[] dataInBytes = decode(encryptedData);
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, initVector);
		System.out.println("iv: " + initVector);
		System.out.println("key: " + key);
		decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
		byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
		return new String(decryptedBytes);
	}

	public static String CCMP_Encrypt(String plaintext, String key) throws Exception 
	{
		// Generate a 256-bit key from the given encryption key
		byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		keyBytes = sha.digest(keyBytes);
		keyBytes = Arrays.copyOf(keyBytes, 16);

		// Create a secret key specification from the key bytes
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// Create a cipher instance and initialize it with the secret key
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

		// Encrypt the plaintext
		byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

		// Encode the encrypted bytes to Base64 string
		//encode(encryptedBytes);
		System.out.println("Cipher Block Chain Encryption: " + Base64.getEncoder().encodeToString(encryptedBytes));
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	public static String CCMP_Decrypt(String ciphertext, String key) throws Exception {
		// Generate a 256-bit key from the given decryption key
		byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		keyBytes = sha.digest(keyBytes);
		keyBytes = Arrays.copyOf(keyBytes, 16);

		// Create a secret key specification from the key bytes
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// Create a cipher instance and initialize it with the secret key
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

		// Decode the Base64 string to encrypted bytes
		byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);

		// Decrypt the ciphertext
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

		// Convert the decrypted bytes to plain text
		//encode(decryptedBytes);
		return new String(decryptedBytes, StandardCharsets.UTF_8);
	}

//	public String getMessage()
//	{
//		this.newMessage = false;
//		return encryptedMessage;
//	}
	
	/******************** below are different versions of the same method used to perform the decryptions in different orders ***************************/

	//GHC
//	public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//	{
//		String decryptedData = "";
//		++decryptionCount;
//
//		System.out.println("Message received by " + clientName + ": " + message);
//
//		//verify digital signature
//		if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//		{
//			System.out.println("Digital signature verified :)");
//			
//			long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//			long startTime = System.nanoTime();//start timer
//			
//			decryptedData = decrypt(message);
//
//
//
//			if(isMessageAuthentic(decryptedData, hmacSignature))
//			{				
//				message = CCMP_Decrypt(decryptedData, cipherBlockChainKey);
//				System.out.println("Decrypted Cipher Block Chain: " + message);
//				long stopTime = System.nanoTime();// stop timer
//				long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//				System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//				System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//				averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//				System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//
//				System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////				PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////				chatScreen.println(senderName + ": " + decryptedData);
//			}
//
//			else
//			{
//				System.out.println("Message discarded!");
//				decryptedData = "0";
//			}
//
//			if(clientName.equals("Broker"))
//			{
//				ProcessCommand(message, senderName);
//			}
//		}
//		
//		else
//		{
//			System.out.println("Digital signature could not be verified");
//		}
//	}
	
	//GCH
//	public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//	{
//		String decryptedData = "";
//		++decryptionCount;
//
//		System.out.println("Message received by " + clientName + ": " + message);
//
//		//verify digital signature
//		if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//		{
//			System.out.println("Digital signature verified :)");
//			
//			long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//			long startTime = System.nanoTime();//start timer
//			decryptedData = decrypt(message);
//			message = CCMP_Decrypt(decryptedData, cipherBlockChainKey);
//			System.out.println("Decrypted Cipher Block Chain: " + message);
//
//			if(isMessageAuthentic(message, hmacSignature))
//			{				
//				long stopTime = System.nanoTime();// stop timer
//				long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//				System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//				System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//				averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//				System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//				
//				System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////				PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////				chatScreen.println(senderName + ": " + decryptedData);
//			}
//
//			else
//			{
//				System.out.println("Message discarded!");
//				decryptedData = "0";
//			}
//
//			if(clientName.equals("Broker"))
//			{
//				ProcessCommand(message, senderName);
//			}
//		}
//		
//		else
//		{
//			System.out.println("Digital signature could not be verified");
//		}
//	}

	//CGH
//		public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//		{
//			String decryptedData = "";
//			++decryptionCount;
//
//			System.out.println("Message received by " + clientName + ": " + message);
//
//			//verify digital signature
//			if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//			{
//				System.out.println("Digital signature verified :)");
//				
//				long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long startTime = System.nanoTime();//start timer
//
//				message = CCMP_Decrypt(message, cipherBlockChainKey);
//				System.out.println("Decrypted Cipher Block Chain: " + message);
//				decryptedData = decrypt(message);
//
//
//				if(isMessageAuthentic(decryptedData, hmacSignature))
//				{				
//					
//					long stopTime = System.nanoTime();// stop timer
//					long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//					long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//					System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//					System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//					averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//					System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//					
//					System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////					PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////					chatScreen.println(senderName + ": " + decryptedData);
//				}
//
//				else
//				{
//					System.out.println("Message discarded!");
//					decryptedData = "0";
//				}
//
//				if(clientName.equals("Broker"))
//				{
//					ProcessCommand(decryptedData, senderName);
//				}
//			}
//			
//			else
//			{
//				System.out.println("Digital signature could not be verified");
//			}
//		}
		
		//CHG
		public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
		{
			String decryptedData = "";
			++decryptionCount;

			System.out.println("Message received by " + clientName + ": " + message);

			//verify digital signature
			if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
			{
				System.out.println("Digital signature verified :)");
				
				long startTime = System.nanoTime();//start timer

				message = CCMP_Decrypt(message, cipherBlockChainKey);
				System.out.println("Decrypted Cipher Block Chain: " + message);



				if(isMessageAuthentic(message, hmacSignature))
				{	
					decryptedData = decrypt(message);					
					long stopTime = System.nanoTime();// stop timer
					System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
					averageDecryptionTime += (stopTime - startTime) / decryptionCount;
					System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
					
					System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);

//					PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
//					chatScreen.println(senderName + ": " + decryptedData);
				}

				else
				{
					System.out.println("Message discarded!");
					decryptedData = "0";
				}

				if(clientName.equals("Broker"))
				{
					ProcessCommand(decryptedData, senderName);
				}
			}
			
			else
			{
				System.out.println("Digital signature could not be verified");
			}
		}
		
		//HCG
//		public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//		{
//			String decryptedData = "";
//			++decryptionCount;
//
//			System.out.println("Message received by " + clientName + ": " + message);
//
//			//verify digital signature
//			if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//			{
//				System.out.println("Digital signature verified :)");
//				
//				long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long startTime = System.nanoTime();//start timer
//
//				if(isMessageAuthentic(message, hmacSignature))
//				{
//					message = CCMP_Decrypt(message, cipherBlockChainKey);
//					System.out.println("Decrypted Cipher Block Chain: " + message);
//					decryptedData = decrypt(message);	
//					
//					long stopTime = System.nanoTime();// stop timer
//					long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//					long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//					System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//					System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//					averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//					System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//					
//					System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////					PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////					chatScreen.println(senderName + ": " + decryptedData);
//				}
//
//				else
//				{
//					System.out.println("Message discarded!");
//					decryptedData = "0";
//				}
//
//				if(clientName.equals("Broker"))
//				{
//					ProcessCommand(decryptedData, senderName);
//				}
//			}
//			
//			else
//			{
//				System.out.println("Digital signature could not be verified");
//			}
//		}
	
	//HGC
//	public static void ProcessResponse(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
//	{
//		String decryptedData = "";
//		++decryptionCount;
//
//		System.out.println("Message received by " + clientName + ": " + message);
//
//		//verify digital signature
//		if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
//		{
//			System.out.println("Digital signature verified :)");
//			
//			long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//			long startTime = System.nanoTime();//start timer
//
//			if(isMessageAuthentic(message, hmacSignature))
//			{
//				decryptedData = decrypt(message);
//				message = CCMP_Decrypt(decryptedData, cipherBlockChainKey);
//				System.out.println("Decrypted Cipher Block Chain: " + message);	
//				
//				long stopTime = System.nanoTime();// stop timer
//				long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//				long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//				System.out.println("Memory used during decryption: " + actualUsedMemory + " bytes");
//				System.out.println("Message decryption time: " + (stopTime - startTime) + "ns");
//				averageDecryptionTime += (stopTime - startTime) / decryptionCount;
//				System.out.println("Average message decryption time over " + decryptionCount + " decryptions: " + averageDecryptionTime + "ns");
//				
//				System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);
//
////				PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
////				chatScreen.println(senderName + ": " + decryptedData);
//			}
//
//			else
//			{
//				System.out.println("Message discarded!");
//				decryptedData = "0";
//			}
//
//			if(clientName.equals("Broker"))
//			{
//				ProcessCommand(message, senderName);
//			}
//		}
//		
//		else
//		{
//			System.out.println("Digital signature could not be verified");
//		}
//	}

	/**
	 * processes the user's command. This command is obtained from decrypting the message included in
	 * the packet received from the client.
	 * @param decryptedCommand
	 * @throws Exception 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private static void ProcessCommand(String decryptedCommand, String senderName) throws InvalidKeyException, NoSuchAlgorithmException, Exception
	{
		String feedback = "";

		switch(decryptedCommand)
		{
//		case "0":
//			break;

		case "1":
			logingIn = true;
			feedback = "Enter \"[username] [password]\" for user: ";
			break;

		case "2":
			if(loggedIn) {
//				Scanner stocksDBScanner = new Scanner(stocksDB);
//				feedback = "\n\n";
//
//				//			File file = new File(".");
//				//			for(String fileNames : file.list()) System.out.println(fileNames);
//
//				while (stocksDBScanner.hasNextLine())
//				{
//					feedback += stocksDBScanner.nextLine() + "\n";
//				}
//
//				//			feedback = "Available stock = EMU - $1.09";
				feedback = getStockInfo();
			}
			
			else {
				feedback = "Please press [1] to login first";
			}
			
			break;

		case "3":
			if(loggedIn) {
				buyingStock = true;
				feedback = "Enter purchase [stock] [quantity] [trading pin]: ";
			}
			
			else {
				feedback = "Please press [1] to login first";
			}
			
			break;

		case "4":
			if(loggedIn) {
				sellingStock = true;
				feedback = "Enter sale [stock] [quantity] [trading pin]: ";
			}
			
			else {
				feedback = "Please press [1] to login first";
			}
			
			break;

		default:
			if(logingIn) 
			{
				logingIn = false;
				
				if(VerifyPassword(senderName, decryptedCommand))
				{
					System.out.println(clientName + " message: password authenticated. Login successful");
					feedback = "Login Successful!";
					loggedIn = true;
				}
//				
				else
				{
					System.out.println(clientName + " message: Password authentication failed. Login unsuccessful");
					feedback = "Password authentication failed. Login unsuccessful";
				}
			}
			
			else if(buyingStock)
			{
				buyingStock = false;
				
				if(VerifyPin(senderName, decryptedCommand))
				{
					System.out.println(clientName + " message: Pin verified");
					
					if(PerformBuy(decryptedCommand)) {
						System.out.println(clientName + " message: Purchase successful!");
						feedback = "Pin verified. Purchase successful!";
					}
					else {
						System.out.println(clientName + " message: Purchase unsuccessful!");
						feedback = "Pin verified. Purchase unsuccessful! Please check that you have enough purchasing power for this transaction.";
					}
				}
				
				else
				{
					System.out.println(clientName + " message: Invalid pin. Please try again.");
					feedback = "Invalid pin. Please try again.";
				}	
			}
			
			else if(sellingStock)
			{
				sellingStock = false;
				
				if(VerifyPin(senderName, decryptedCommand))
				{
					System.out.println(clientName + " message: Pin verified.");
					
					if(PerformSell(decryptedCommand)) {
						System.out.println(clientName + " message: Sale successful!");
						feedback = "Pin verified. Sale successful!";
					}
					else {
						System.out.println(clientName + " message: Purchase unsuccessful!");
						feedback = "Pin verified. Sale unsuccessful! Please check that you have enough of this stock to sell.";
					}
				}
				
				else
				{
					System.out.println(clientName + " message: Invalid pin. Please retry.");
					feedback = "Invalid pin. Please retry.";
				}	
			}
			
			else
			{
				System.out.println(clientName + " message: Command failed!");
				feedback = "An error has occured. Please try again";
			}
						
			break;
		}
		
		encryptedMessage = ThreeLayerEncryption(feedback);
		SignMessage();
		newMessage = true;
		sendMessage(encryptedMessage);
	}
	
//	private static String getStockInfo() throws IOException {
//	    String feedback = "\n\n";
//	    
//	    // MySQL connection setup
//	    try (Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword)) {
//	        
//	        // SQL query to fetch the balance from the users table and stock info from the stocks table
//	        String query = "SELECT u.username, u.balance, s.ticker, s.price, s.quantity " +
//	                       "FROM users u " +
//	                       "LEFT JOIN stocks s ON u.username = s.username " +
//	                       "WHERE u.username = ?";
//	        
//	        try (PreparedStatement stmt = conn.prepareStatement(query)) {
//	            stmt.setString(1, currentUsername);  // Set the current logged-in user's username
//	            
//	            // Execute the query
//	            try (ResultSet rs = stmt.executeQuery()) {
//	                // Check if there are results
//	                if (!rs.next()) {
//	                    feedback = "No data found for user: " + currentUsername;
//	                } else {
//	                    // Add username and balance info
//	                    String username = rs.getString("username");
//	                    String balance = rs.getString("balance");
//	                    feedback += "Username: " + username + " | Balance: " + balance + "\n";
//	                    
//	                    // Add the table headers
//	                    feedback += "Ticker\tPrice\tQuantity\n";
//	                    
//	                    // Loop through the result set and format the stock data
//	                    do {
//	                        String ticker = rs.getString("ticker");
//	                        String quantity = rs.getString("quantity");
//	                        
//	                        if (ticker != null) {
//	                            // Fetch the current price from Yahoo Finance
//	                            Stock stock = YahooFinance.get(ticker);
//	                            double currentPrice = stock.getQuote().getPrice().doubleValue();
//	                            
//	                            // Update the stock price in the database
//	                            String updateQuery = "UPDATE stocks SET price = ? WHERE username = ? AND ticker = ?";
//	                            try (PreparedStatement updateStmt = conn.prepareStatement(updateQuery)) {
//	                                updateStmt.setDouble(1, currentPrice);
//	                                updateStmt.setString(2, currentUsername);
//	                                updateStmt.setString(3, ticker);
//	                                updateStmt.executeUpdate();
//	                            }
//	                            
//	                            // Add the updated stock data to the feedback
//	                            feedback += ticker + "\t$" + currentPrice + "\t" + (quantity == null ? "0" : quantity) + "\n";
//	                        }
//	                    } while (rs.next());
//	                }
//	            }
//	        }
//	    } catch (SQLException e) {
//	        e.printStackTrace();
//	        feedback = "Error fetching data from the database.";
//	    }
//	    
//	    return feedback;
//	}
	
    private static String getStockInfo() throws IOException {
        String feedback = "\n\n";

        // MySQL connection setup
        try (Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword)) {
            
            // SQL query to fetch the balance from the users table and stock info from the stocks table
            String query = "SELECT u.username, u.balance, s.ticker, s.price, s.quantity " +
                           "FROM users u " +
                           "LEFT JOIN stocks s ON u.username = s.username " +
                           "WHERE u.username = ?";
            
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, currentUsername);  // Set the current logged-in user's username
                
                // Execute the query
                try (ResultSet rs = stmt.executeQuery()) {
                    // Check if there are results
                    if (!rs.next()) {
                        feedback = "No data found for user: " + currentUsername;
                    } else {
                        // Add username and balance info
                        String username = rs.getString("username");
                        String balance = rs.getString("balance");
                        feedback += "Username: " + username + " | Balance: " + balance + "\n";
                        
                        // Add the table headers
                        feedback += "Ticker\tPrice\tQuantity\n";
                        
                        // Loop through the result set and format the stock data
                        do {
                            String ticker = rs.getString("ticker");
                            String quantity = rs.getString("quantity");
                            
                            if (ticker != null) {
                                // Fetch the current price from Yahoo Finance using jsoup
                                double currentPrice = getStockPriceFromYahoo(ticker);
                                System.out.println("shit " + ticker + " = " + currentPrice);
                                
                                // Update the stock price in the database
                                String updateQuery = "UPDATE stocks SET price = ? WHERE username = ? AND ticker = ?";
                                try (PreparedStatement updateStmt = conn.prepareStatement(updateQuery)) {
                                    updateStmt.setDouble(1, currentPrice);
                                    updateStmt.setString(2, currentUsername);
                                    updateStmt.setString(3, ticker);
                                    updateStmt.executeUpdate();
                                }
                                
                                // Add the updated stock data to the feedback
                                feedback += ticker + "\t$" + currentPrice + "\t" + (quantity == null ? "0" : quantity) + "\n";
                            }
                        } while (rs.next());
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            feedback = "Error fetching data from the database.";
        }
        
        return feedback;
    }

    // Method to fetch stock price from Yahoo Finance using jsoup
    private static double getStockPriceFromYahoo(String ticker) {
        double price = 0.0;

        try {
            // Fetch the HTML page for the given stock ticker
            String url = "https://finance.yahoo.com/quote/" + ticker;
            Document doc = Jsoup.connect(url).get();
            
            // Find the stock price by selecting the appropriate HTML element
            Element priceElement = doc.select("span[data-testid='qsp-price']").first();; //doc.select("fin-streamer[data-symbol='regularMarketPrice']").first();
            
            // Extract the text (price) from the element
            if (priceElement != null) {
                String priceText = priceElement.text();
                price = Double.parseDouble(priceText.replaceAll(",", ""));
            } else {
                System.out.println("Could not find the price for " + ticker);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error fetching stock price for " + ticker);
        }
        
        return price;
    }

//	private static String getStockInfo() throws IOException {
//	    String feedback = "\n\n";
//	    
////	    YahooFinance.get("GOOG");
//
//	    // MySQL connection setup
//	    try (Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword)) {
//	        
//	        // SQL query to fetch the balance from the users table and stock info from the stocks table
//	        String query = "SELECT u.username, u.balance, s.ticker, s.price, s.quantity " +
//	                       "FROM users u " +
//	                       "LEFT JOIN stocks s ON u.username = s.username " +
//	                       "WHERE u.username = ?";
//	        
//	        try (PreparedStatement stmt = conn.prepareStatement(query)) {
//	            stmt.setString(1, currentUsername);  // Set the current logged-in user's username
//	            
//	            // Execute the query
//	            try (ResultSet rs = stmt.executeQuery()) {
//	                // Check if there are results
//	                if (!rs.next()) {
//	                    feedback = "No data found for user: " + currentUsername;
//	                } else {
//	                    // Add username and balance info
//	                    String username = rs.getString("username");
//	                    String balance = rs.getString("balance");
//	                    feedback += "Username: " + username + " | Balance: " + balance + "\n";
//	                    
//	                    // Add the table headers
//	                    feedback += "Ticker\tPrice\tQuantity\n";
//	                    
//	                    // Loop through the result set and format the stock data
//	                    do {
//	                        String ticker = rs.getString("ticker");
//	                        String price = rs.getString("price");
//	                        String quantity = rs.getString("quantity");
//	                        
//	                        // Add each row in tabular form
//	                        feedback += (ticker == null ? "No stock" : ticker) + "\t" + 
//	                                    (price == null ? "$0" : price) + "\t" + 
//	                                    (quantity == null ? "0" : quantity) + "\n";
//	                    } while (rs.next());
//	                }
//	            }
//	        }
//	    } catch (SQLException e) {
//	        e.printStackTrace();
//	        feedback = "Error fetching data from the database.";
//	    }
//	    
//	    return feedback;
//	}

	
//	private static boolean PerformBuy(String buyInfo) throws IOException {		
//		Scanner stocksDBScanner = new Scanner(stocksDB);
//		String user = "";
//		String userData = "";
//		String oldContent = "";
//		String newFileContent = "";
//		String ticker = "";
//		int lineNumber = 0;
//		int currentStockQuantity = 0;
//		int newStockQuantity = 0;
//		double totalBuyPrice = 0;
//		double unitPrice = 0;
//		double purchasePower = 0;
//		double newPurchasePower = 0;
//		boolean purchaseSuccessful = false;
//		
//		//get qty
//		int buyQuantity = Integer.parseInt(buyInfo.split(" ")[1]); //could throw numberFormatException
//		
//		//get stock unit price and balance and current quantity owned by user
//		while (stocksDBScanner.hasNextLine())
//		{
//			++lineNumber;
//			userData = stocksDBScanner.nextLine();
//			
//			if(lineNumber == 1) {
//				user = userData.split(" ")[0].split(":")[1];
//				
//				if(user.equals(currentUsername)) {
//					purchasePower = Double.parseDouble(userData.split(" ")[1].split(":")[1]);
//				}
//			}
//			
//			//get price and current quantity owned from db
//			else if(user.equals(currentUsername) && lineNumber > 2 && buyInfo.split(" ")[0].equals(userData.split("\t")[0].trim())) {
//				ticker = userData.split("\t")[0].trim();
//				unitPrice = Double.parseDouble(userData.split("\t")[1].trim().replace("$", ""));
//				currentStockQuantity = Integer.parseInt(userData.split("\t")[2].trim());
//			}
//			
//			oldContent = oldContent + userData + System.lineSeparator();
//		}
//		
//		stocksDBScanner.close();
//		
//		//get total buy price
//		totalBuyPrice = buyQuantity * unitPrice;
//		
//		//check if there is enough to purchase
//		if(totalBuyPrice <= purchasePower) {
//			newPurchasePower = purchasePower - totalBuyPrice; //charge user
//			newStockQuantity = currentStockQuantity + buyQuantity; //get the stocks
//
//			//update stock qty and purchase power for user
////			System.out.println("balance:" + purchasePower);
////			System.out.println(ticker + " \t$" +  unitPrice + " \t" + currentStockQuantity);
////			System.out.println(newStockQuantity);
//			newFileContent = oldContent.replaceAll("balance:" + purchasePower, "balance:" + (newPurchasePower)).replace(ticker + " \t$" +  unitPrice + " \t" + currentStockQuantity, ticker + " \t$" +  unitPrice + " \t" + newStockQuantity);
//			FileWriter writer = new FileWriter(stocksDB);
//			writer.write(newFileContent.trim());
//			writer.close();
//			
//			purchaseSuccessful = true;
//		}
//
//		return purchaseSuccessful;
//	}


	private static boolean PerformBuy(String buyInfo) throws SQLException {
	    boolean purchaseSuccessful = false;

	    // Parse the buyInfo to get the stock ticker and the quantity to buy
	    String tickerToBuy = buyInfo.split(" ")[0];
	    int buyQuantity = Integer.parseInt(buyInfo.split(" ")[1]);

	    // MySQL connection setup
	    Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);

	    // Query to get the user's current balance (purchase power)
	    String balanceQuery = "SELECT balance FROM users WHERE username = ?";
	    PreparedStatement balanceStmt = conn.prepareStatement(balanceQuery);
	    balanceStmt.setString(1, currentUsername); // Set the current logged-in user's username
	    ResultSet balanceResult = balanceStmt.executeQuery();

	    if (balanceResult.next()) {
	        double purchasePower = Double.parseDouble(balanceResult.getString("balance"));
	        
	        // Query to get the stock unit price and the current stock quantity for the specified ticker
	        String stockQuery = "SELECT price, quantity FROM stocks WHERE username = ? AND ticker = ?";
	        PreparedStatement stockStmt = conn.prepareStatement(stockQuery);
	        stockStmt.setString(1, currentUsername); // Set the current logged-in user's username
	        stockStmt.setString(2, tickerToBuy); // Set the ticker from the buyInfo
	        ResultSet stockResult = stockStmt.executeQuery();

	        double unitPrice = 0;
	        int currentStockQuantity = 0;

	        if (stockResult.next()) {
	            unitPrice = Double.parseDouble(stockResult.getString("price").replace("$", ""));
	            currentStockQuantity = Integer.parseInt(stockResult.getString("quantity"));
	        }

	        // Calculate the total purchase price
	        double totalBuyPrice = buyQuantity * unitPrice;

	        // Check if the user has enough purchase power to make the purchase
	        if (totalBuyPrice <= purchasePower) {
	            double newPurchasePower = purchasePower - totalBuyPrice; // Deduct the purchase price from the user's balance
	            int newStockQuantity = currentStockQuantity + buyQuantity; // Increase the stock quantity for the user

	            // Update the user's balance
	            String updateBalanceQuery = "UPDATE users SET balance = ? WHERE username = ?";
	            PreparedStatement updateBalanceStmt = conn.prepareStatement(updateBalanceQuery);
	            updateBalanceStmt.setDouble(1, newPurchasePower);
	            updateBalanceStmt.setString(2, currentUsername);
	            updateBalanceStmt.executeUpdate();

	            // Update the stock quantity for the user
	            String updateStockQuery = "UPDATE stocks SET quantity = ? WHERE username = ? AND ticker = ?";
	            PreparedStatement updateStockStmt = conn.prepareStatement(updateStockQuery);
	            updateStockStmt.setInt(1, newStockQuantity);
	            updateStockStmt.setString(2, currentUsername);
	            updateStockStmt.setString(3, tickerToBuy);
	            updateStockStmt.executeUpdate();

	            purchaseSuccessful = true; // The purchase was successful
	        }
	        
		    stockResult.close();
	    }

	    // Close the database connections
	    balanceResult.close();
	    conn.close();

	    return purchaseSuccessful;
	}

	
//	private static boolean PerformSell(String sellInfo) throws IOException {		
//		Scanner stocksDBScanner = new Scanner(stocksDB);
//		String user = "";
//		String userData = "";
//		String oldContent = "";
//		String newFileContent = "";
//		String ticker = "";
//		int lineNumber = 0;
//		int currentStockQuantity = 0;
//		int newStockQuantity = 0;
//		double totalSellPrice = 0;
//		double unitPrice = 0;
//		double currentPurchasePower = 0;
//		double newPurchasePower = 0;
//		boolean saleSuccessful = false;
//		
//		//get qty
//		int saleQuantity = Integer.parseInt(sellInfo.split(" ")[1]); //could throw numberFormatException
//		
//		//get stock unit price and balance and current quantity owned by user
//		while (stocksDBScanner.hasNextLine())
//		{
//			++lineNumber;
//			userData = stocksDBScanner.nextLine();
//			
//			if(lineNumber == 1) {
//				user = userData.split(" ")[0].split(":")[1];
//				
//				if(user.equals(currentUsername)) {
//					currentPurchasePower = Double.parseDouble(userData.split(" ")[1].split(":")[1]);
//				}
//			}
//			
//			//get price and current quantity owned from db
//			else if(user.equals(currentUsername) && lineNumber > 2 && sellInfo.split(" ")[0].equals(userData.split("\t")[0].trim())) {
//				ticker = userData.split("\t")[0].trim();
//				unitPrice = Double.parseDouble(userData.split("\t")[1].trim().replace("$", ""));
//				currentStockQuantity = Integer.parseInt(userData.split("\t")[2].trim());
//			}
//			
//			oldContent = oldContent + userData + System.lineSeparator();
//		}
//		
//		stocksDBScanner.close();
//		
//		//get total sell price
//		totalSellPrice = saleQuantity * unitPrice;
//		
//		//check if there is enough to sell
//		if(currentStockQuantity >= saleQuantity) {
//			newPurchasePower = currentPurchasePower + totalSellPrice; //credit user
//			newStockQuantity = currentStockQuantity - saleQuantity; //sell the stocks
//
//			//update stock qty and purchase power for user
//			newFileContent = oldContent.replaceAll("balance:" + (currentPurchasePower), "balance:" + (newPurchasePower)).replace(ticker + " \t$" +  unitPrice + " \t" + currentStockQuantity, ticker + " \t$" +  unitPrice + " \t" + newStockQuantity);
//			FileWriter writer = new FileWriter(stocksDB);
//			writer.write(newFileContent.trim());
//			writer.close();
//	
//			saleSuccessful = true;
//		}
//
//		return saleSuccessful;
//	}

	private static boolean PerformSell(String sellInfo) throws SQLException {
	    boolean saleSuccessful = false;

	    // Parse the sellInfo to get the stock ticker and the quantity to sell
	    String tickerToSell = sellInfo.split(" ")[0];
	    int saleQuantity = Integer.parseInt(sellInfo.split(" ")[1]);

	    // MySQL connection setup
	    Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);

	    // Query to get the user's current stock quantity and unit price for the specified ticker
	    String stockQuery = "SELECT price, quantity FROM stocks WHERE username = ? AND ticker = ?";
	    PreparedStatement stockStmt = conn.prepareStatement(stockQuery);
	    stockStmt.setString(1, currentUsername); // Set the current logged-in user's username
	    stockStmt.setString(2, tickerToSell); // Set the ticker from the sellInfo
	    ResultSet stockResult = stockStmt.executeQuery();

	    if (stockResult.next()) {
	        double unitPrice = Double.parseDouble(stockResult.getString("price").replace("$", ""));
	        int currentStockQuantity = Integer.parseInt(stockResult.getString("quantity"));
	        
	        // Check if the user has enough stock to sell
	        if (currentStockQuantity >= saleQuantity) {
	            // Calculate the total sell price
	            double totalSellPrice = saleQuantity * unitPrice;

	            // Query to get the user's current balance
	            String balanceQuery = "SELECT balance FROM users WHERE username = ?";
	            PreparedStatement balanceStmt = conn.prepareStatement(balanceQuery);
	            balanceStmt.setString(1, currentUsername); // Set the current logged-in user's username
	            ResultSet balanceResult = balanceStmt.executeQuery();

	            if (balanceResult.next()) {
	                double currentPurchasePower = Double.parseDouble(balanceResult.getString("balance"));
	                double newPurchasePower = currentPurchasePower + totalSellPrice; // Add the sell price to the balance

	                // Update the user's balance in the users table
	                String updateBalanceQuery = "UPDATE users SET balance = ? WHERE username = ?";
	                PreparedStatement updateBalanceStmt = conn.prepareStatement(updateBalanceQuery);
	                updateBalanceStmt.setDouble(1, newPurchasePower);
	                updateBalanceStmt.setString(2, currentUsername);
	                updateBalanceStmt.executeUpdate();

	                // Update the stock quantity in the stocks table
	                int newStockQuantity = currentStockQuantity - saleQuantity;
	                String updateStockQuery = "UPDATE stocks SET quantity = ? WHERE username = ? AND ticker = ?";
	                PreparedStatement updateStockStmt = conn.prepareStatement(updateStockQuery);
	                updateStockStmt.setInt(1, newStockQuantity);
	                updateStockStmt.setString(2, currentUsername);
	                updateStockStmt.setString(3, tickerToSell);
	                updateStockStmt.executeUpdate();

	                saleSuccessful = true; // The sale was successful
	            }
	            
	    	    balanceResult.close();
	        }
	    }

	    // Close the database connections
	    stockResult.close();
	    conn.close();

	    return saleSuccessful;
	}

	
	//verifies the pin for Buy/Sell commands
//	private static boolean VerifyPin(String senderName, String decryptedCommand) throws FileNotFoundException
//	{
//		boolean isPinValid = false;
//		Scanner userDBScanner = new Scanner(userDB);
//		String userData = "";
//		String dbUser = "";
//		String dbPin = "";
//		String enteredPin = decryptedCommand.split(" ")[2];
//		
//		while (userDBScanner.hasNextLine())
//		{
//			userData = userDBScanner.nextLine();
//			dbUser = userData.split(" ")[1];
//			dbPin = new String(Base64.getDecoder().decode(userData.split(" ")[2])); //pwd is base 64 encoded
//			
//			if(dbUser.equals(currentUsername) && dbPin.equals(enteredPin)) 
//			{
//				isPinValid = true;
//				break;
//			}
//		}
//		
//		userDBScanner.close();
//		return isPinValid;
//	}

	private static boolean VerifyPin(String senderName, String decryptedCommand) {
	    boolean isPinValid = false;
	    String enteredPin = decryptedCommand.split(" ")[2];
	    
	    // SQL query to check the user and pin in the database
	    String query = "SELECT username, pin FROM users WHERE username = ?";
	    
	    try (Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
	         PreparedStatement stmt = conn.prepareStatement(query)) {
	        
	        // Set the currentUsername as a parameter in the query
	        stmt.setString(1, currentUsername);
	        
	        // Execute the query
	        ResultSet rs = stmt.executeQuery();
	        
	        // Check if a user was found
	        if (rs.next()) {
	            // Get the stored username and pin
	            String dbUser = rs.getString("username");
	            String dbPin = rs.getString("pin");
	            
	            dbPin = new String(Base64.getDecoder().decode(dbPin));
	            
	            // Compare the username and pin
	            if (dbUser.equals(currentUsername) && dbPin.equals(enteredPin)) {
	                isPinValid = true;
	            }
	        }
	        
	    } catch (SQLException e) {
	        e.printStackTrace(); // Handle any database errors
	    }

	    return isPinValid;
	}

	
	//verifies the login password
//	private static boolean VerifyPassword(String senderName, String decryptedCommand) throws FileNotFoundException
//	{
//		Scanner userDBScanner = new Scanner(userDB);
//		boolean foundUser = false;
//		String userData = "";
//		String dbUser = "";
//		String dbPwd = "";
//		String enteredUsername = decryptedCommand.split(" ")[0];
//		String enteredPwd = decryptedCommand.split(" ")[1];
//		
//		while (userDBScanner.hasNextLine())
//		{
//			userData = userDBScanner.nextLine();
//			dbUser = userData.split(" ")[1];
//			dbPwd = new String(Base64.getDecoder().decode(userData.split(" ")[2])); //pwd is base 64 encoded
//			
//			if(dbUser.equals(enteredUsername) && dbPwd.equals(enteredPwd)) 
//			{
//				foundUser = true;
//				currentUsername = enteredUsername;
//				break;
//			}
//		}
//		
//		userDBScanner.close();
//		return foundUser;
//	}
	
	
	//Login authentication with DB
	private static boolean VerifyPassword(String senderName, String decryptedCommand) {
	    boolean foundUser = false;
	    String enteredUsername = decryptedCommand.split(" ")[0];
	    String enteredPwd = decryptedCommand.split(" ")[1];
	    
	    
	    // SQL query to check the user in the database
	    String query = "SELECT username, password FROM users WHERE username = ?";
	    
	    try (Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
	         PreparedStatement stmt = conn.prepareStatement(query)) {
	        
	        // Set the entered username as a parameter in the query
	        stmt.setString(1, enteredUsername);
	        
	        // Execute the query
	        ResultSet rs = stmt.executeQuery();
	        
	        // Check if a user was found
	        if (rs.next()) {
	            // Get the stored username, password (base64 encoded)
	            String dbUser = rs.getString("username");
	            String dbPwdBase64 = rs.getString("password");
	            
	            // Decode the stored password from base64
	            String dbPwd = new String(Base64.getDecoder().decode(dbPwdBase64));
	            
	            // Compare the username and password
	            if (dbUser.equals(enteredUsername) && dbPwd.equals(enteredPwd)) {
	                foundUser = true;
	                currentUsername = enteredUsername; // Store the current logged-in username
	            }
	        }
	        
	    } catch (SQLException e) {
	        e.printStackTrace(); // Handle any database errors
	    }

	    return foundUser;
	}

	
	 // Verifies the login password using a database instead of a file
//    private static boolean VerifyPassword(String decryptedCommand) 
//    {
//        boolean foundUser = false;
//        String enteredUsername = decryptedCommand.split(" ")[0];
//        String enteredPwd = decryptedCommand.split(" ")[1];
//        
//        // Database connection details
////        String dbUrl = "jdbc:mysql://localhost:3306/yourDatabaseName"; // Replace with your DB details
////        String dbUsername = "yourDBUsername"; // Replace with your DB username
////        String dbPassword = "yourDBPassword"; // Replace with your DB password
//        
//        Connection conn = null;
//        PreparedStatement stmt = null;
//        ResultSet rs = null;
//
//        try {
//            // Establish connection to the database
//            conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
//            
//            // Prepare a SQL query to check if the user exists
//            String sql = "SELECT username, password FROM users WHERE username = ?";
//            stmt = conn.prepareStatement(sql);
//            stmt.setString(1, enteredUsername);
//            
//            // Execute the query
//            rs = stmt.executeQuery();
//            
//            // Check if the user is found
//            if (rs.next()) {
//                // Retrieve the username and password (base64 encoded)
//                String dbUser = rs.getString("username");
//                String dbPwd = rs.getString("password");
//                
//                // Decode the password from base64
//                String decodedDbPwd = new String(Base64.getDecoder().decode(dbPwd));
//                
//                // Compare the entered password with the decoded one
//                if (dbUser.equals(enteredUsername) && decodedDbPwd.equals(enteredPwd)) {
//                    foundUser = true;
//                    currentUsername = enteredUsername;
//                }
//            }
//        } catch (SQLException e) {
//            e.printStackTrace(); // Handle SQL exceptions
//        } finally {
//            // Close resources
//            try {
//                if (rs != null) rs.close();
//                if (stmt != null) stmt.close();
//                if (conn != null) conn.close();
//            } catch (SQLException e) {
//                e.printStackTrace();
//            }
//        }
//        
//        return foundUser;
//    }
	
	/*
	 * digital signature
	 */
	private static void SignMessage() throws SignatureException
	{
		digitalSignature.update(encryptedMessage.getBytes());
		messageDigitalSignature = digitalSignature.sign();
		System.out.println("Digital signature applied to encrypted message: " + messageDigitalSignature);
	}
	
	/******************** below are different versions of the same method used to perform the encryptions in different orders ***************************/

	//GHC
	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
	{
		String CCMP_encryptedMessage = "";
		++encryptionCount;
		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
		long startTime = System.nanoTime();
		
		encryptedMessage = Encrypt(message);//AES-GCM
		HMAC_Sign(encryptedMessage);//HMAC
		CCMP_encryptedMessage = CCMP_Encrypt(encryptedMessage, cipherBlockChainKey);//CCMP
		
		long stopTime = System.nanoTime();
		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
		
		return CCMP_encryptedMessage;
	}
	
	//GCH
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//		encryptedMessage = Encrypt(message);//AES-GCM
//		CCMP_encryptedMessage = CCMP_Encrypt(encryptedMessage, cipherBlockChainKey);
//		HMAC_Sign(CCMP_encryptedMessage);
//
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		
//		return CCMP_encryptedMessage;
//	}
	
	//CGH
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//		CCMP_encryptedMessage = CCMP_Encrypt(message, cipherBlockChainKey);
//		encryptedMessage = Encrypt(CCMP_encryptedMessage);//AES-GCM
//		HMAC_Sign(encryptedMessage);
//		
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		
//		return encryptedMessage;
//	}
	
	//CHG
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//		CCMP_encryptedMessage = CCMP_Encrypt(message, cipherBlockChainKey);//CCMP
//		HMAC_Sign(CCMP_encryptedMessage);//HMAC
//		encryptedMessage = Encrypt(CCMP_encryptedMessage);//AES-GCM
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		
//		return encryptedMessage;
//	}
	
	//HCG
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//		HMAC_Sign(message);//HMAC
//		CCMP_encryptedMessage = CCMP_Encrypt(message, cipherBlockChainKey);//CCMP
//		encryptedMessage = Encrypt(CCMP_encryptedMessage);//AES-GCM
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		
//		return encryptedMessage;
//	}
	
	//HGC
//	private static String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
//	{
//		String CCMP_encryptedMessage = "";
//		++encryptionCount;
//		
//		long beforeUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long startTime = System.nanoTime();
//		
//		HMAC_Sign(message);//HMAC
//		encryptedMessage = Encrypt(message);//AES-GCM
//		CCMP_encryptedMessage = CCMP_Encrypt(encryptedMessage, cipherBlockChainKey);//CCMP
//		
//		long stopTime = System.nanoTime();
//		long afterUsedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
//		long actualUsedMemory = afterUsedMemory - beforeUsedMemory;
//		System.out.println("Memory used during encryption: " + actualUsedMemory + " bytes");
//		System.out.println("Message encryption time: " + (stopTime - startTime) + "ns");
//		averageEncryptionTime += (stopTime - startTime) / encryptionCount;
//		System.out.println("Average message encryption time over " + encryptionCount + " encryptions: " + averageEncryptionTime + "ns");
//		
//		return CCMP_encryptedMessage;
//	}

	public static void GenerateAESKey() throws Exception 
	{
		int keySize = 0;

		System.out.println("symmetric key: " + symmetricKey);
		
		//determine AES key size based on random privateValue
		switch(symmetricKey % 3)
		{
		case 0:
			keySize = 128;
			break;

		case 1:
			keySize = 192;
			break;

		case 2:
			keySize = 255; //256;
			break;

		}
		
//		keySize = 128;

//		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//		keyGenerator.init(keySize);
//		key = keyGenerator.generateKey();
		System.out.println("key size: " + keySize);
		
		String str = Long.toBinaryString(keySize); //"1234567812345678";
		str += str;
		System.out.println("AES key string: " + str);
		key = new SecretKeySpec(str.getBytes(), "AES");
	}

	//	public SecretKey getKey()
	//	{
	//		return key;
	//	}
	//	
	//	public void setKey(SecretKey aesKey)
	//	{
	//		this.key = aesKey;
	//	}
	//	
//	public Cipher getEncryptionCipher()
//	{
//		return encryptionCipher;
//	}
//
//	public void setEncryptionCipher(Cipher encryptionCipher)
//	{
//		this.encryptionCipher = encryptionCipher;
//	}

	//turns byte into string and returns the string
	private static String encode(byte[] data) 
	{
		return Base64.getEncoder().encodeToString(data);
	}

	//turns string into byte and returns the byte
	private static byte[] decode(String data) 
	{
		return Base64.getDecoder().decode(data);
	}

//	public void Wait() throws InterruptedException
//	{
//		Thread.sleep(1);
//	}
}

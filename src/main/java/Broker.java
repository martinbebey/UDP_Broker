package src.main.java;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
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
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

/**
 * This is the broker program
 */
public class Broker 
{
	private static DatagramSocket socket;
	private static byte[] buf = new byte[5000];
	private static byte[] buffer = new byte[5000];
	private static int port = 0;
	private static int datagramSocketPortNumber = 5000;
	private static long averageEncryptionTime;
	private static long averagePacketSentSize;
	private static long averagePacketReceivedSize;
	private static long encryptionCount = 0;
	private static long averageDecryptionTime;
	private static long decryptionCount = 0;
	private static InetAddress address;
	private static String encryptedMessage = "message";
	private static byte[] initVector;
	private static SecretKey key = null;
	private static String cipherBlockChainKey;
	private final static int DATA_LENGTH = 128;
	private static int privateValue; //used for DH key exchange
	private static int symmetricKey;
	private static Cipher encryptionCipher = null;
	private static byte[] HMAC_KEY;
	private static PrivateKey privateKeyDS = null; //private/public keys used to sign/authenticate with DSA
	private static KeyPairGenerator keyPairGen = null; //key pair generator object
	private static KeyPair pair = null;
	private static Signature digitalSignature = null;
	private static boolean logingIn;
	private static boolean loggedIn = false;
	private static boolean buyingStock;
	private static boolean sellingStock = false;
	private static String currentUsername = "";
	public static PublicKey publicKeyDS = null;
	public static 	byte[] hmacSignature;
	public static byte[] messageDigitalSignature = null;
	public static String clientName = "Broker";
	public static boolean newMessage = false;
	public static int P; //used for DH key exchange
	public static int G; //used for DH key exchange
	public static int publicValue;
    private static String dbUrl = "jdbc:mysql://localhost:3306/myDB";
    private static String dbUsername = "root";
    private static String dbPassword = "123";


	/**
	 * Broker program's entry point. Infinitely loops listening to client commands, decrypts and processes them
	 * then sends an encrypted response
	 * @throws Exception
	 */
	public static void main(String args[]) throws Exception
	{
		socket = new DatagramSocket(datagramSocketPortNumber);		
		boolean running = true;
		
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
		
		//get G
		packet = new DatagramPacket(buf, buf.length);
		socket.receive(packet);
		address = packet.getAddress();
		port = packet.getPort();
		packet = new DatagramPacket(buf, buf.length, address, port);
		received = new String(packet.getData(), 0, packet.getLength());
		G = Integer.parseInt(received.trim());
		socket.send(packet);
		buf = new byte[5000];
		
		//generate of keys for HMAC, CCMP, AES-GCM and broker's Digital Signature
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
			received = new String(packet.getData(), 0, packet.getLength());
			System.out.println("Receiving packet of size: " + packet.getLength());
			averagePacketReceivedSize += packet.getLength();
			System.out.println("Average size of packets received: " + averagePacketReceivedSize);	
			System.out.println(received);
			
			//breakdown response
			String encryptedResponse = received.split("\\|")[0];
			String senderName = received.split("\\|")[1];
			byte[] userHMACSignature = Base64.getDecoder().decode(received.split("\\|")[2].getBytes());
			byte[] userDigitalSignature = Base64.getDecoder().decode(received.split("\\|")[3].getBytes());
			System.out.println("received iv string: " + received.split("\\|")[5].trim().substring(0, 16));
			initVector = Base64.getDecoder().decode(received.split("\\|")[5].trim().substring(0, 16).getBytes());
			System.out.println(clientName + " received HMAC signature: " + received.split("\\|")[2]);
			System.out.println(clientName + " received DS signature: " + received.split("\\|")[3]);	
			KeyFactory factory = KeyFactory.getInstance("DSA");
			String keyString = received.split("\\|")[4];
			byte[] keyByte = Base64.getDecoder().decode(keyString.trim());
			PublicKey brokerPublicKeyDS = (PublicKey) factory.generatePublic(new X509EncodedKeySpec(keyByte));
			
			//process response
			ProcessResponse(encryptedResponse, senderName, userHMACSignature, userDigitalSignature, brokerPublicKeyDS);
		}

		socket.close();
	}
	
	/**
	 * Shares the public value with the connected client.
	 * @param msg the message to be included in the packet to be sent to the client. 
	 * In this case, it is the public value used for DH key exchange
	 * @throws IOException
	 */
	public static void sendPublicValue(String msg) throws IOException 
	{
		buf = msg.getBytes();
		DatagramPacket packet = new DatagramPacket(buf, buf.length, address, port);
		socket.send(packet);
	}
	
	/**
	 * Wraps a given string input into a packet that is sent to the client.
	 * @param msg the message to be included in the packet to be sent to the client.
	 * @throws IOException
	 */
	public static void sendMessage(String msg) throws IOException 
	{
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
	
	/**
	 * Generates the broker's digital signature to be attached to every message
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
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

	/**
	 * Verifies the digital signature of the received message.
	 * @param input - the input message in bytes
	 * @param signatureToVerify - the client's signature to verify
	 * @param pubKey - the public key used
	 * @throws IOException
	 */
	public static boolean Verify_Digital_Signature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception
	{ 
		Signature signature = Signature.getInstance("SHA256withDSA"); 
		signature.initVerify(key); 
		signature.update(input); 
		return signature.verify(signatureToVerify); 
	}

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

	/**
	 * Randomly generates the private value between 2 and 257.
	 */
	public static void setPrivateValue() 
	{
		privateValue = ThreadLocalRandom.current().nextInt(2,257);
	}

	/**
	 * Sets the cypher block key used for CCMP encryption.
	 */
	public static void setCipherBlockKey()
	{
		cipherBlockChainKey = Integer.toString(symmetricKey);
	}

	/**
	 * Sets the hmac key used to produce the hmac signature.
	 */
	public static void setHMACKey()
	{
		HMAC_KEY = ByteBuffer.allocate(8).putInt(symmetricKey).array();
	}

	/**
	 *Sets the public value shared with the client based on the values of P and G.
	 */
	public static void setPublicValue()
	{
		publicValue = calculateValue(G, privateValue, P);
	}

	/**
	 * Sets the symmetric keys obtained via DH exchange that will be secret between the
	 * client and the broker.
	 */
	public static void setSymmetricKey()
	{
		symmetricKey = calculateValue(publicValue, privateValue, P);
	}

	/**
	 * Method to find the value of G ^ [power] mod P  for DH key exchange.
	 * @param P
	 * @param G
	 * @param power - the power to which G will be raised in the formula
	 */
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

	/**
	 * Adds the borker's HMAC signature to the message.
	 * @param encryptedMessage - the message to be signed
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
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
	 * AES-GCM encryption.
	 * @param message
	 * @return encrypted data as a string
	 * @throws Exception
	 */
	public static String Encrypt(String message) throws Exception
	{		
		String encryptedData = encrypt(message);
		System.out.println("Message AES-GCM encrypted by " + clientName + ": " + encryptedData);
		return encryptedData;
	}

	/**
	 * Performs the AES-GCM encryption.
	 * @param data - the data to be encrypted
	 * @throws Exception
	 */
	public static String encrypt(String data) throws Exception 
	{
		byte[] dataInBytes = data.getBytes();
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
		return encode(encryptedBytes);
	}

	/**
	 * Performs the AES-GCM decryption.
	 * @param encryptedData - the data to be decrypted
	 * @throws Exception
	 */
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

	/**
	 * Performs the CCMP encryption.
	 * @param plaintext - the message to be encrypted
	 * @param key - the key used for the cipher encryption
	 * @throws Exception
	 */
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
		System.out.println("Cipher Block Chain Encryption: " + Base64.getEncoder().encodeToString(encryptedBytes));
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	/**
	 * Performs the CCMP decryption.
	 * @param ciphertext - the message to be decrypted
	 * @param key - the key used for the cipher decryption
	 * @throws Exception
	 */
	public static String CCMP_Decrypt(String ciphertext, String key) throws Exception 
	{
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
	
	/******************** Below are different versions of the same method used to perform the decryptions in different orders. The order of decryption is commented on top of each method, 
	 * where GHC stands for (GCM decryption, followed by HMAC verification, followed by CCMP decryption). Note that the message would have to have been encrypted in the opposite order by the client who sent it. ***************************/

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
	 * Processes the user's command. This command is obtained from decrypting the message included in
	 * the packet received from the client.
	 * @param decryptedCommand - the decrypted command to be processed
	 * @throws Exception 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private static void ProcessCommand(String decryptedCommand, String senderName) throws InvalidKeyException, NoSuchAlgorithmException, Exception
	{
		String feedback = "";

		switch(decryptedCommand)
		{

		case "1":
			logingIn = true;
			feedback = "Enter \"[username] [password]\" for user: ";
			break;

		case "2":
			if(loggedIn) {
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
						feedback = "Pin verified. Purchase unsuccessful! Please check your balance and the trading information provided.";
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
	
	/**
	 * Gets the LIVE stock information from Yahoo Finance.
	 * @throws IOException
	 */
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

	/**
	 * Helper function to fetch the ticker's LIVE price.
	 * @param ticker - the ticker who's LIVE price will be fetched
	 */
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

	/**
	 * Performs the stock buying operation if applicable, and updates the user's database records.
	 * @param buyInfo - information about the purchase such as the stock ticker and quantity
	 * @throws SQLException
	 */    
    private static boolean PerformBuy(String buyInfo) throws SQLException {
        boolean purchaseSuccessful = false;

        // Parse the buyInfo to get the stock ticker and the quantity to buy
        String tickerToBuy = buyInfo.split(" ")[0];
        int buyQuantity = Integer.parseInt(buyInfo.split(" ")[1]);

        // Fetch the stock price using the existing getStockPriceFromYahoo function
        double unitPrice = getStockPriceFromYahoo(tickerToBuy);

        // If the price is not valid, exit the function
        if (unitPrice <= 0) {
            System.out.println("Invalid stock info " + tickerToBuy);
            return false;
        }

        // MySQL connection setup
        Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);

        // Query to get the user's current balance (purchase power)
        String balanceQuery = "SELECT balance FROM users WHERE username = ?";
        PreparedStatement balanceStmt = conn.prepareStatement(balanceQuery);
        balanceStmt.setString(1, currentUsername); // Set the current logged-in user's username
        ResultSet balanceResult = balanceStmt.executeQuery();

        if (balanceResult.next()) {
            double purchasePower = balanceResult.getDouble("balance");

            // Calculate the total purchase price
            double totalBuyPrice = buyQuantity * unitPrice;

            // Check if the user has enough purchase power to make the purchase
            if (totalBuyPrice <= purchasePower) {
                // Query to get the stock quantity for the specified ticker
                String stockQuery = "SELECT quantity FROM stocks WHERE username = ? AND ticker = ?";
                PreparedStatement stockStmt = conn.prepareStatement(stockQuery);
                stockStmt.setString(1, currentUsername); // Set the current logged-in user's username
                stockStmt.setString(2, tickerToBuy); // Set the ticker from the buyInfo
                ResultSet stockResult = stockStmt.executeQuery();

                int currentStockQuantity = 0;

                if (stockResult.next()) {
                    currentStockQuantity = stockResult.getInt("quantity");
                }

                // Update the user's balance
                double newPurchasePower = purchasePower - totalBuyPrice; // Deduct the purchase price from the user's balance
                String updateBalanceQuery = "UPDATE users SET balance = ? WHERE username = ?";
                PreparedStatement updateBalanceStmt = conn.prepareStatement(updateBalanceQuery);
                updateBalanceStmt.setDouble(1, newPurchasePower);
                updateBalanceStmt.setString(2, currentUsername);
                updateBalanceStmt.executeUpdate();

                // Check if the stock already exists for the user, then update or insert
                String updateStockQuery;
                if (currentStockQuantity > 0) {
                    // Update the stock quantity and price if the user already has this stock
                    updateStockQuery = "UPDATE stocks SET quantity = ?, price = ? WHERE username = ? AND ticker = ?";
                    PreparedStatement updateStockStmt = conn.prepareStatement(updateStockQuery);
                    updateStockStmt.setInt(1, currentStockQuantity + buyQuantity); // Increase the stock quantity for the user
                    updateStockStmt.setDouble(2, unitPrice); // Update the stock price with the latest price
                    updateStockStmt.setString(3, currentUsername);
                    updateStockStmt.setString(4, tickerToBuy);
                    updateStockStmt.executeUpdate();
                } 
                else {
                    // Create a new stock entry for the user if not already present
                    updateStockQuery = "INSERT INTO stocks (username, ticker, price, quantity) VALUES (?, ?, ?, ?)";
                    PreparedStatement insertStockStmt = conn.prepareStatement(updateStockQuery);
                    insertStockStmt.setString(1, currentUsername);
                    insertStockStmt.setString(2, tickerToBuy);
                    insertStockStmt.setDouble(3, unitPrice);
                    insertStockStmt.setInt(4, buyQuantity);
                    insertStockStmt.executeUpdate();
                }

                purchaseSuccessful = true; // The purchase was successful
                
                stockResult.close();
            } 
            else {
                System.out.println("Insufficient funds to make the purchase.");
            }
        }

        // Close the database connections
        balanceResult.close();
        conn.close();

        return purchaseSuccessful;
    }

	/**
	 * Performs the stock selling operation if applicable, and updates the user's database records.
	 * @param sellInfo - information about the sale such as the stock ticker and quantity
	 * @throws SQLException
	 */
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

	/**
	 * Verifies the user's trading pin before performing a transaction. The encoded pin is checked
	 * against the user's database records.
	 * @param senderName - the client's name
	 * @param decryptedCommand - the user's decrypted pin, which is encoded
	 */
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
	
	/**
	 * Verifies the user's login password. The encoded password is checked
	 * against the user's database records.
	 * @param senderName - the client's name
	 * @param decryptedCommand - the user's decrypted password, which is encoded
	 */
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
	
	/**
	 * Signs the encrypted message to be sent to the client.
	 * @throws SignatureException
	 */
	private static void SignMessage() throws SignatureException
	{
		digitalSignature.update(encryptedMessage.getBytes());
		messageDigitalSignature = digitalSignature.sign();
		System.out.println("Digital signature applied to encrypted message: " + messageDigitalSignature);
	}
	
	/******************** Below are different versions of the same method used to perform the encryptions in different orders. The order of encryption is commented on top of each method, 
	 * where GHC stands for (GCM encryption, followed by HMAC verification, followed by CCMP encryption). ***************************/

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

	/**
	 * Generates the key used for AES-GCM encryption.
	 * @throws Exception
	 */
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

	/**
	 * Base 64 encodes a byte of data into a string.
	 * @param data - the byte to be encoded
	 */
	private static String encode(byte[] data) 
	{
		return Base64.getEncoder().encodeToString(data);
	}

	/**
	 * Base 64 decodes a string of data into a byte.
	 * @param data - the string to be decoded
	 */
	private static byte[] decode(String data) 
	{
		return Base64.getDecoder().decode(data);
	}
}

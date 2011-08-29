/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package dateends;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author messuti.edd
 */
public class SecureAppProperty {
	
	private String fileName;
	private String dir;
	private String encryptKey;
	private int monthsTest;
	
	private String fileMac = null;
	private long fileTime;
	
	public SecureAppProperty(String encryptKey, String dir, String fileName, int monthsTest) {
		this.dir = dir;
		this.fileName = fileName;
		this.monthsTest = monthsTest;
		this.encryptKey = encryptKey;
	}
	
	/** Checks if the trial period hasnt pass or the program is running in other pc
	 * 
	 * @return 
	 *		-1 if trial period has pass
	 *		-2 if the program is running in other pc
	 *		1 if OK
	 *		0 if the file hasnt been loaded yet
	 */
	public int check() {
		if (fileMac == null) {
			System.err.println("File not loaded!");
			return 0;
		}
		
		Calendar cal = Calendar.getInstance();
		
		if (cal.getTimeInMillis() > fileTime) {
			return -1;
		}
		else if (!fileMac.equals(getMacAdress())) {
			return -2;
		}
		return 1;
	}
	
	public void loadFile() {
		try {
			BufferedReader reader = new BufferedReader(new FileReader(dir + "\\" + fileName));
			fileMac = SecureAppProperty.decrypt(encryptKey, reader.readLine());
			fileTime = Long.parseLong(SecureAppProperty.decrypt(encryptKey, reader.readLine()));
			
		} catch (InvalidKeyException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (UnsupportedEncodingException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (InvalidKeySpecException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchPaddingException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IllegalBlockSizeException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (BadPaddingException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IOException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		}
	}
	
	public void saveFile() {
		try {
			Calendar cal = Calendar.getInstance();
			cal.add(Calendar.MONTH, monthsTest);
			
			String curDir = System.getProperty("user.home");			
			BufferedWriter writer = new BufferedWriter(new FileWriter(dir + "\\" + fileName));
			writer.write(SecureAppProperty.encrypt(encryptKey, SecureAppProperty.getMacAdress()) + "\n");
			writer.write(SecureAppProperty.encrypt(encryptKey, String.valueOf(cal.getTimeInMillis())));
			writer.close();
			
		} catch (IOException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (InvalidKeyException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (InvalidKeySpecException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchPaddingException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IllegalBlockSizeException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		} catch (BadPaddingException ex) {
			Logger.getLogger(SecureAppProperty.class.getName()).log(Level.SEVERE, null, ex);
		}
	}
	
	public static String encrypt(String encryptKey, String str) throws 
			InvalidKeyException, UnsupportedEncodingException, 
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, 
			IllegalBlockSizeException, BadPaddingException {
		DESKeySpec keySpec = new DESKeySpec(encryptKey.getBytes("UTF8"));
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey key = keyFactory.generateSecret(keySpec);
		sun.misc.BASE64Encoder base64encoder = new BASE64Encoder();
		sun.misc.BASE64Decoder base64decoder = new BASE64Decoder();
		
		byte[] cleartext = str.getBytes("UTF8"); 
		Cipher cipher = Cipher.getInstance("DES"); // cipher is not thread safe
		cipher.init(Cipher.ENCRYPT_MODE, key);
		String encryptedStr = base64encoder.encode(cipher.doFinal(cleartext));
		
		return encryptedStr;
	}
	
	public static String decrypt(String encryptKey, String encryptedStr)  throws 
			InvalidKeyException, UnsupportedEncodingException, 
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, 
			IllegalBlockSizeException, BadPaddingException, IOException {
		DESKeySpec keySpec = new DESKeySpec(encryptKey.getBytes("UTF8"));
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		SecretKey key = keyFactory.generateSecret(keySpec);
		sun.misc.BASE64Encoder base64encoder = new BASE64Encoder();
		sun.misc.BASE64Decoder base64decoder = new BASE64Decoder();
		
		byte[] encrypedPwdBytes = base64decoder.decodeBuffer(encryptedStr);	

		Cipher cipher = Cipher.getInstance("DES");// cipher is not thread safe
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plainTextPwdBytes = (cipher.doFinal(encrypedPwdBytes));
		return new String(plainTextPwdBytes);
	}

	public static String getMacAdress() {
		try {
			InetAddress[] addresses = InetAddress.getAllByName(InetAddress.getLocalHost().getHostName());
			String macString = "";

			for (int k = 0; k < addresses.length; k++) {
				NetworkInterface ni = NetworkInterface.getByInetAddress(addresses[k]);
				byte[] mac = ni.getHardwareAddress();
				for (int i = 0; i < mac.length; i++) {
					macString = macString + String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : "");
				}
				if (!macString.equals("")) {
					break;
				}
			}
			return macString;
		} catch (Exception ex) {
			Logger.getLogger(DateEnds.class.getName()).log(Level.SEVERE, null, ex);
			return "";
		}
	}
}

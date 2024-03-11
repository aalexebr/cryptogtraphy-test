package org.java.pojo;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class SecretKeyCD {
	
	public Key secretKey;
	public String password;
	public  Cipher cipher; 
	public IvParameterSpec iv;
	private final int pswdLength = 32;
	
	public SecretKeyCD() {
		try {
			this.cipher = Cipher.getInstance("DESede/CBC/NoPadding", new BouncyCastleProvider());
		} catch (Exception ignored) {}
	}
	
	public void createKeyFromPassword(String string) {
		
//		get string/pswd and convert to byte array
		String pswd = string;
//		control obver the lenght of 32 bits
		if(pswd.length()< 32) {
			int n = 32 - pswd.length();
			for(int i =0; i<=n; i++) {
				pswd += "0";
			}
		}
		else if(pswd.length()> 32) {
			pswd = pswd.substring(0, Math.min(pswd.length(), 32));
		}
		String keyString = Hex.toHexString(pswd.getBytes(StandardCharsets.UTF_8));
		byte[] keyBytes = Hex.decode(keyString);
//		get byte array and 
		final byte[] ivBytes = new byte[8];
		final byte[] keyCipherBytes = new byte[24];
		System.arraycopy(keyBytes, 0, ivBytes, 0, 8);
		System.arraycopy(keyBytes, 8, keyCipherBytes, 0, 24);
		
		this.secretKey = new SecretKeySpec(keyCipherBytes, "DESede");
		this.iv = new IvParameterSpec(ivBytes);
		
	}
	public String turnPrivateKeytoString() {

		return new String (Base64.getEncoder().encodeToString(secretKey.getEncoded()));
		
	}
		
	
	public String crypt(String text) throws Exception{
		
		byte[] inputBytes = text.getBytes(StandardCharsets.UTF_8);
		byte[] padded;
 
		if (inputBytes.length % 8 != 0) {
			padded = new byte[inputBytes.length + 8 - (inputBytes.length % 8)];
			System.arraycopy(inputBytes, 0, padded, 0, inputBytes.length);
			inputBytes = padded;
		}
		
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
		byte[] encrypted = new byte[cipher.getOutputSize(inputBytes.length)];
		int enLength = cipher.update(inputBytes, 0, inputBytes.length, encrypted);
		cipher.doFinal(encrypted, enLength);
		return Hex.toHexString(encrypted);
		
	}
//	
	public String decrypt(String encypted)throws Exception{
		byte[] encrypted = Hex.decode(encypted);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
		byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
		int deLength = cipher.update(encrypted, 0, encrypted.length, decrypted);
		cipher.doFinal(decrypted, deLength);
//		System.out.println(new String(decrypted).trim());
		return new String(decrypted).trim();
		
	}
	
	
	public static void cryptDecrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		String input = "prova a cifrarmi una stringa piu lunga xxxxxxxxxxx";
		String keyString = Hex.toHexString("tantddddddddddddd222222222222222".getBytes(StandardCharsets.UTF_8));
		byte[] keyBytes = Hex.decode(keyString);
		final byte[] ivBytes = new byte[8];
		final byte[] keyCipherBytes = new byte[24];
		System.arraycopy(keyBytes, 0, ivBytes, 0, 8);
		System.arraycopy(keyBytes, 8, keyCipherBytes, 0, 24);
		//System.arraycopy(keyBytes, 0, keyCipherBytes, 0, 24);
		byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
		byte[] padded;
 
		if (inputBytes.length % 8 != 0) {
			padded = new byte[inputBytes.length + 8 - (inputBytes.length % 8)];
			System.arraycopy(inputBytes, 0, padded, 0, inputBytes.length);
			inputBytes = padded;
		}
		SecretKeySpec key = new SecretKeySpec(keyCipherBytes, "DESede");
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", new BouncyCastleProvider());
 
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] encrypted = new byte[cipher.getOutputSize(inputBytes.length)];
		int enLength = cipher.update(inputBytes, 0, inputBytes.length, encrypted);
		cipher.doFinal(encrypted, enLength);
		System.out.println(Hex.toHexString(encrypted).toUpperCase());
		//D9DC84513C20EDCFD99D472C5D627E29

		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
		int deLength = cipher.update(encrypted, 0, encrypted.length, decrypted);
		cipher.doFinal(decrypted, deLength);
		System.out.println(new String(decrypted).trim());
		
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("CBC");
		generator.initialize(128);
}


}

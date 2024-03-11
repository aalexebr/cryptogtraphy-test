package org.java.pojo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class Decrypter {
	
	private Key privateKey;
	
	public Decrypter() {}
	
	public Decrypter(Key privateKey) {
		setPrivateKey(privateKey);
	}

	public Key getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(Key privateKey) {
		this.privateKey = privateKey;
	}
	
	public String decrypt(String text) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		byte[] encryptedBytes = Base64.getDecoder().decode(text);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, this.getPrivateKey());
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
	}
	
	public void getPrivKeyFromP12 (String filepath, String keyStorePassword, String Keypassword ,String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
		
		char[] keystorePassword = keyStorePassword.toCharArray();
		char[] keyPassword = Keypassword.toCharArray();
		 
		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream(filepath), keystorePassword);
		privateKey = (PrivateKey) keystore.getKey(alias, keyPassword);
		
	}
	
	
}

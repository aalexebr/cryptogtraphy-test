package org.java.pojo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class Crypter {
	
	private Key publicKey;
	
	public Crypter() {}
	
	public Crypter(Key publicKey) {
		setPublicKey(publicKey);
	}

	public Key getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(Key publicKey) {
		this.publicKey = publicKey;
	}
	
	public String cryptMessage(String text) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		 
        byte[] messageToBytes = text.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return Base64.getEncoder().encodeToString(encryptedBytes);

	}
	
	public void getPublicKeyOfCertificate(String filepath) throws Exception {
		FileInputStream fin = new FileInputStream(filepath);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate certificate = f.generateCertificate(fin);
		setPublicKey(certificate.getPublicKey());
	}
	

}

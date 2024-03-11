package org.java.pojo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class KeyDecoderEncoder {
	
	
	public  Key  getPrivateKeyFromString(String data) throws NoSuchAlgorithmException, InvalidKeySpecException {
			
			byte[] dataPrivKey = Base64.getDecoder().decode(data);
		        
	        PKCS8EncodedKeySpec keyPrivate = new PKCS8EncodedKeySpec(dataPrivKey);
	        
	        KeyFactory keyfactory = KeyFactory.getInstance("RSA");	        
	
	        return keyfactory.generatePrivate(keyPrivate);
	    }
	
	public  Key getPublicKeyFromString(String data) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] dataPubKey = Base64.getDecoder().decode(data);
	        
        X509EncodedKeySpec keyPublic = new X509EncodedKeySpec(dataPubKey);

        KeyFactory keyfactory = KeyFactory.getInstance("RSA");	        
        
         return keyfactory.generatePublic(keyPublic);
    }
	
	public String turnPrivateKeytoString(Key key) {
		
		return new String (Base64.getEncoder().encodeToString(key.getEncoded()));
		
	}
	
	public String turnPublicKeytoString(Key key) {
			
			return new String (Base64.getEncoder().encodeToString(key.getEncoded()));
			
	}
	
	public Key keyFileReader(String filepath) throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException {
		Scanner myReader = new Scanner(new File(filepath));
        String publicKeyDataStr = new String();
        while (myReader.hasNextLine()) {
          String dataStr = myReader.nextLine();
          if(!dataStr.startsWith("---")) {
        	  publicKeyDataStr += dataStr;
          }
        }
        return getPrivateKeyFromString(publicKeyDataStr);
	}
	
	public Key getPrivKeyFromP12 (String filepath, String keyStorePassword, String Keypassword ,String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
		
		char[] keystorePassword = keyStorePassword.toCharArray();
		char[] keyPassword = Keypassword.toCharArray();
		 
		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream(filepath), keystorePassword);
		return  (PrivateKey) keystore.getKey(alias, keyPassword);
		
	}

}

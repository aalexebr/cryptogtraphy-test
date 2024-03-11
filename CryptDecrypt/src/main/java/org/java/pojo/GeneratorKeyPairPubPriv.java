package org.java.pojo;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GeneratorKeyPairPubPriv {
	
	private Key privateKey;
	
	private Key publicKey;
	
	public GeneratorKeyPairPubPriv() throws NoSuchAlgorithmException, NoSuchProviderException {
		createKeys();
	}
	
	public Key getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(Key privateKey) {
		this.privateKey = privateKey;
	}

	public Key getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(Key publicKey) {
		this.publicKey = publicKey;
	}
	
	private void createKeys() throws NoSuchAlgorithmException, NoSuchProviderException {
//		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        generator.initialize(1024, new SecureRandom());
        
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();
        this.setPrivateKey(privKey);
        this.setPublicKey(pubKey);
	}
	
	public String decodePrivateKey() {
		return Base64.getEncoder().encodeToString(privateKey.getEncoded());
	}
	
	public String decodePublicKey() {
		return Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}
 
}

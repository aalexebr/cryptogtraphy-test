package org.java;

import java.io.File;
import java.io.FileWriter;
import java.security.Key;
import java.util.Scanner;

import org.java.pojo.Crypter;
import org.java.pojo.Decrypter;
import org.java.pojo.GeneratorKeyPairPubPriv;
import org.java.pojo.KeyDecoderEncoder;
import org.java.pojo.SecretKeyCD;

public class Main {
	
	public static void main(String[] args) throws Exception {
		
		KeyDecoderEncoder keyDecoderEncoder = new KeyDecoderEncoder();
//		
//        
////    	USING CRYPTER FROM CERTIFICATE PUBLIC KEY 
//		
//		System.out.println("TEST BEALDUNG CERT + P12 :");
//        
//        Crypter crypter2 = new Crypter();
//        
//        crypter2.getPublicKeyOfCertificate("C:\\Users\\alessandro.ebreo\\eclipse-workspace\\Test\\Baeldung.cer");
//        
//        String texttocryptwithcert = "new string to crypt with cert pub key ";
//        
//        String cryptedText = crypter2.cryptMessage(texttocryptwithcert);
//        
//        System.out.println("CRYPTED: "+cryptedText);
//        
////        DECRYPTING WITH P12 FILE 
//        
//        Decrypter decrypter2 = new Decrypter();
//        
//        decrypter2.getPrivKeyFromP12("C:\\Users\\alessandro.ebreo\\eclipse-workspace\\Test\\Baeldung.p12", "password","password","baeldung");
//        String decrypted = decrypter2.decrypt(cryptedText);
//        
//        System.out.println("DECRY: "+decrypted);
//        
//        
////        TEST WITH NEW OPENSSL CREATED CERT AND PRIV KEY
//        
//        System.out.println("TEST OPENSSL CEERT : ");
//        
//        Crypter crypter3 = new Crypter();
//        
//        crypter3.getPublicKeyOfCertificate("NEWTESTCERT.crt");
//        
//        String s = "test to crypt";
//        
//        String c = crypter3.cryptMessage(s);
//        
//        System.out.println("NEW CRY : "+c);
//        
//        keyDecoderEncoder.keyFileReader("newTESTPRIVKEY.key");
//        
//        Decrypter decrypter3 = new Decrypter(keyDecoderEncoder.keyFileReader("newTESTPRIVKEY.key"));
//                
//
//        System.out.println("NEW DECRY : "+decrypter3.decrypt(c));
//        
        GeneratorKeyPairPubPriv generator = new GeneratorKeyPairPubPriv();
        
        System.out.println("generator private key-----> "+generator.decodePrivateKey());
        
        String privateKeyAsStr = generator.decodePrivateKey();
		
		SecretKeyCD x = new SecretKeyCD();
		x.createKeyFromPassword("1!fdas");
		
//		cryptDecrypt();
//		PROCESS: input gives password 
//		->  generates symm key PrK1
//		->  generate key pair PrK2 + PbK
//		->	save Prk2 in file crypted with PrK1
//		-> recieve and crypt with Pbk 
//		-> decrypt writing in user PrK1 that reads file to decrypt Prk2 to be used to decrypt files
		
		String cryptPrivKey = x.crypt(privateKeyAsStr);
		System.out.println(cryptPrivKey);
		
		try {
		      File myObj = new File("cryptedPrivateKey.txt");
		      if (myObj.createNewFile()) {
		        System.out.println("File created: " + myObj.getName());
		      } else {
		        System.out.println("File already exists.");
		      }
		    } catch (Exception ignored) {}
		
		try {
		      FileWriter myWriter = new FileWriter("cryptedPrivateKey.txt");
		      myWriter.write(cryptPrivKey);
		      myWriter.close();
		      System.out.println("Successfully wrote to the file.");
			} catch (Exception ignored) {}
		String cryptedPrKFromFile = new String();
		 try {
		      File myObj = new File("cryptedPrivateKey.txt");
		      Scanner myReader = new Scanner(myObj);
		      while (myReader.hasNextLine()) {
		    	  cryptedPrKFromFile = myReader.nextLine();
//		        System.out.println(cryptedPrKFromFile);
		      }
		      myReader.close();
		 	} catch (Exception ignored) {}
		 
		 
		 Key privK  = keyDecoderEncoder.getPrivateKeyFromString(x.decrypt(cryptedPrKFromFile));
		 
		 String text = "hey this needs to be crypted";
		 
		 Crypter crypter = new Crypter(generator.getPublicKey());
		 
		 String cryptedText = crypter.cryptMessage(text);
		 System.out.println(cryptedText);
		 
		 Decrypter decrypter = new Decrypter(privK);
		 String decr = decrypter.decrypt(cryptedText);
		 System.out.println(decr);
	}
	


}

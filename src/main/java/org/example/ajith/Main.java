package org.example.ajith;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.*;

public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {

        KeyPair keyPair = createKeyPair(2048);
        PrivateKey pvtkey = keyPair.getPrivate();
        PublicKey pubkey = keyPair.getPublic();

        saveToPEM(pvtkey, pubkey);


    }

    public static KeyPair createKeyPair(int size) {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("No RSA KeyPair generator available");
            nsae.printStackTrace();
            return null;
        }

        try {
            keyPairGenerator.initialize(size, new SecureRandom());
        } catch (InvalidParameterException ipe)  {
            System.out.println("RSA KeyPair generation failed for invalid key size: " + size);
            ipe.printStackTrace();
            return null;
        }

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;

    }

    public static void saveToPEM(PrivateKey privateKey, PublicKey publicKey) {

        PemWriter pemWriter = null;
        PemObject pemObject = null;

        pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
        try {
            pemWriter = new PemWriter(new FileWriter("keypair.pem"));
            pemWriter.writeObject(pemObject);

        } catch (IOException e) {
            System.out.println("Error saving private key: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        } finally {
            if (pemWriter != null) {
                try {
                    pemWriter.close();
                } catch (IOException e) {
                    System.out.println("Error saving private key file: " + e.getMessage());
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }
        }


    }
}
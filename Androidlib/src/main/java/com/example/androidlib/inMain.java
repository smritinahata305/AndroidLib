package com.example.androidlib;

import java.io.BufferedInputStream;
import java.io.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;

public class inMain {
    final static String filePath1 = "src/pin.txt";
    final static String filePath2 = "src/prikey.txt";
    final static String filePath3 = "src/pubkey.txt";
    final static String filePath4 = "src/csrinbytes.txt";
    //	final static String filePath5 = "src/usercert.txt";
//	final static String filePath6 = "src/cakacert.txt";
//	final static String filePath7 = "src/Signthisdoc.txt";
    final static String filePath8 = "src/csrinpem.csr";
    final static String filePath9 = "src";

    public static String pin = null;
    public static byte[] CsrtoCA;
    static byte[] privateKeyBytes;
    static byte[] publicKeyBytes;
    public static KeyPair k;
    public static List<X509Certificate> certList = new ArrayList<X509Certificate>();

    public static void main(String args[]) {

    }

    //API 1 : TO CHECK IF SIM IS PRESENT
    public boolean isPKISimPresent() {
        return true;
    }

    ////API 2 : TO UPDATE PIN OR SET PIN(IF INITIAL PIN IS NULL)
    public String updatePin(String oldPin, String newPin) throws Exception {
        pin = readFileAsString(filePath1);

        if (!oldPin.equals(pin)) {
            return "OLD PIN INCORRECT";
        } else {
            pin = newPin;


            FileWriter fw = new FileWriter(filePath1, false);
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(newPin);
            bw.close();


            return "PIN CHANGED SUCCESSFULLY";
        }
    }


    //API 3 : TO GENERATE CSR BY READING PUBLIC AND PRIVATE KEY FROM FILES AND STORE IT IN THE LIBRARY FOR FUTURE USE
    public static String getCSR(String userpin, String userdetails) throws Exception {

        pin = readFileAsString(filePath1);
        if (!userpin.equals(pin)) {
            return "FAIL";
        } else {
            //If the files having private and public keys are empty then Generate keypair first and store them in the files
            if (readFileAsByteArray(filePath2).length == 0) {
                KeyPair k = GenerateCSR.createKeyPair();
                byte[] privateKeyBytes = k.getPrivate().getEncoded();
                byte[] publicKeyBytes = k.getPublic().getEncoded();
                Path path = Paths.get(filePath2);
                Files.write(path, privateKeyBytes);
                path = Paths.get(filePath3);
                Files.write(path, publicKeyBytes);
            }

            //Here read the private and public keys and generate CSR to store

            privateKeyBytes = readFileAsByteArray(filePath2);
            publicKeyBytes = readFileAsByteArray(filePath3);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            KeyPair k = new KeyPair(publicKey, privateKey);


            //Generate the CSR USING BOUNCY CASTLE FUNCTIONS
            CsrtoCA = GenerateCSR.createCSR(k, userdetails);

            //Store the CSR byte array in the file
            Path path = Paths.get(filePath4);
            Files.write(path, CsrtoCA);

            PrintWriter out = new PrintWriter(filePath8);
            out.println("\n-----BEGIN CERTIFICATE REQUEST-----\r\n" + java.util.Base64.getEncoder().encodeToString(CsrtoCA) + "\n-----END CERTIFICATE REQUEST-----");
            out.close();
            return "X509 GENERATED SUCCESSFULLY";
        }

    }

    //API 4 : TO save user and CA CERTIFICATES in the corresponding files, verify user certificate and prompt the user.
    public boolean downloadCert(String userpin, X509Certificate USERCERT, ArrayList<X509Certificate> CACERT) throws Exception {
        pin = readFileAsString(filePath1);
        if (!userpin.equals(pin)) {
            return false;
        }


        int n = CACERT.size();
        for (int i = 0; i < n - 1; i++) {
            X509Certificate tempuser = CACERT.get(i);
            X509Certificate tempCA = CACERT.get(i + 1);
            if (tempuser.getIssuerX500Principal().equals(tempCA.getSubjectX500Principal()) == false) {
                return false;
            }
            try {
                tempuser.verify(tempCA.getPublicKey());
                return true;
            } catch (Exception e) {
                return false;
            }
        }
        //The CA chain has been verified above


        // if self-signed, verify the LAST INDEX cert
        X509Certificate last = CACERT.get(n - 1);
        // if self-signed, verify the final cert
        if (last.getIssuerX500Principal().equals(last.getSubjectX500Principal())) {
            try {
                last.verify(last.getPublicKey());
            } catch (Exception e) {
                return false;
            }
        } else
            return false;


        X509Certificate immediate = CACERT.get(0);

        if (immediate.getSubjectX500Principal().equals(USERCERT.getIssuerX500Principal())) {
            try {
                USERCERT.verify(immediate.getPublicKey());
                {
                    //Here add all x509 certs to the array of x509 certs
                    certList.add(0, USERCERT);
                    for (int i = 0; i < CACERT.size(); i++)
                        certList.add(i + 1, CACERT.get(i));


                    File path = new File(filePath9);
                    OutputStream os = null;
                    for (X509Certificate cert : certList) {
                        File certFile = new File(path, cert.getSubjectX500Principal().getName() + ".crt");
                        os = new FileOutputStream(certFile);
                        os.write(cert.getEncoded());
                        os.flush();
                    }
                    os.close();


                }
                return true;
            } catch (Exception e) {
                return false;
            }
        }
        return false;


    }


    //API 5 : Sign the data provided with the stored private key of the user and return it in base64 format
    public String docSign(String userpin, byte[] docinbytes) throws Exception {
        pin = readFileAsString(filePath1);
        if (!userpin.equals(pin)) {
            return "WRONG PIN";
        }
        privateKeyBytes = readFileAsByteArray(filePath2);
        if (privateKeyBytes.length == 0) {
            return "No Private key generated till now";
        }

        Signature sig = Signature.getInstance("SHA256WithRSA");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey p = keyFactory.generatePrivate(privateKeySpec);

        sig.initSign(p);
        sig.update(docinbytes);
        byte[] signatureBytes = sig.sign();
        return "Signature:" + java.util.Base64.getEncoder().encodeToString(signatureBytes);

    }


    //API 6 :Generate a new pair of public and private key and store them in files for future use
    public static void blockorReset() throws Exception {

        Path path1 = Paths.get(filePath1);
        Files.newBufferedWriter(path1, StandardOpenOption.TRUNCATE_EXISTING);
        //Files.newInputStream(filePath1 , StandardOpenOption.TRUNCATE_EXISTING);
        //here you have to generate a new keypair and store in file for future use
        certList.clear();

        KeyPair k = GenerateCSR.createKeyPair();
        byte[] privateKeyBytes = k.getPrivate().getEncoded();
        byte[] publicKeyBytes = k.getPublic().getEncoded();

        Path path = Paths.get(filePath2);
        Files.write(path, privateKeyBytes);
        path = Paths.get(filePath3);
        Files.write(path, publicKeyBytes);

    }


    //API 7 : if USER WANT TO DOWNLOAD the certificate from the library then use this to give array of x509 certificate
    public List<X509Certificate> exportCertificate(String userpin) throws Exception {

        pin = readFileAsString(filePath1);
        if (!userpin.equals(pin)) {
            return null;
        }


        if (certList.size() > 0)
            return certList;
        else {
            File directoryPath = new File(filePath9);
            int i = 0;
            File filesList[] = directoryPath.listFiles();
            for (File file : filesList) {

                byte[] temp = readFileAsByteArray(file.getAbsolutePath());
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(temp));
                certList.add(i, (X509Certificate) certificate);
            }
            return certList;
        }


    }

    public static String readFileAsString(String filepath) throws Exception {
        String data = "";
        data = new String(Files.readAllBytes(Paths.get(filepath)));
        return data;
    }

    public static byte[] readFileAsByteArray(String filepath) throws Exception {
        byte[] b;
        b = Files.readAllBytes(Paths.get(filepath));
        return b;
    }
}
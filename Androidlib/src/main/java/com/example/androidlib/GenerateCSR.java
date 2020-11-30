package com.example.androidlib;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import javax.security.auth.x500.X500Principal;

public class GenerateCSR {
    private static String commonName = "Smriti.com";
    private static String locality = "Juhu";
    private static String state = "Maharashtra";
    private static String country = "Nagpur";
    private static String organizationUnit = "Jio Strategic Initiative";
    private static String organization  = "Jio";
    private static  String email = "smriti@ril.com";

    public static String fun(){
        StringBuilder sb = new StringBuilder();
        if (commonName == null || commonName.isEmpty()) {
            throw new IllegalArgumentException("Common Name cannot be empty");
        } else {
            sb.append("CN=").append(commonName);
        }
        if (locality != null && !locality.isEmpty()) {
            sb.append(", L=").append(locality);
        }
        if (state != null && !state.isEmpty()) {
            sb.append(", ST=").append(state);
        }
        if (country != null && !country.isEmpty()) {
            sb.append(", C=").append(country);
        }
        if (organizationUnit != null && !organizationUnit.isEmpty()) {
            sb.append(", OU=").append(organizationUnit);
        }
        if (organization != null && !organization.isEmpty()) {
            sb.append(", O=").append(organization);
        }
//        if (email != null && !email.isEmpty()) {
//            sb.append(", EMAIL=").append(email);
//        }

        return sb.toString();
    }
    public static byte[] createCSR(KeyPair kp,String s) throws IOException, OperatorCreationException, NoSuchAlgorithmException {

        X500Principal principal = new X500Principal(s);

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(principal, kp.getPublic());

        //hashing and signing in line 85 and 86 together

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(kp.getPrivate() );

        PKCS10CertificationRequest csr = p10Builder.build(signer);


        return csr.getEncoded();
//        System.out.println(csrFormat);
//        return csrFormat;

    }

    public static KeyPair createKeyPair() throws Exception {
//        KeyPair keyPair;
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",  );
//        generator.initialize(2048, new SecureRandom());
//        keyPair = generator.generateKeyPair();

        KeyPairGenerator kpg = KeyPairGenerator
                .getInstance("RSA");

        // initializing with 1024
        kpg.initialize(2048);

        // getting key pairs
        // using generateKeyPair() method
        KeyPair kp = kpg.generateKeyPair();



        return kp;
    }
    public X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
//    	if (certificateString != null && !certificateString.trim().isEmpty()) {
//            certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----\n", "")
//                    .replace("-----END CERTIFICATE-----", "");
//    	}
        InputStream targetStream = new ByteArrayInputStream(certificateString.getBytes());
        return (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(targetStream);


//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        FileInputStream finStream = new FileInputStream("CACertificate.pem");
//        X509Certificate caCertificate = (X509Certificate)cf.generateCertificate(finStream);

    }
}
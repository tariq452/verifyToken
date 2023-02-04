package org.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        // add JWT
        String token="";
        // Add path for public certificate
        PublicKey publicCert= getPublicKeyFromPem(new File(""));

        boolean isValid= verifyToken(token, (RSAPublicKey) publicCert);
        System.out.println("Result :"+isValid);
    }

    public static boolean verifyToken(String token, RSAPublicKey publicKey){
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    //more validations if needed
                    .build();
            verifier.verify(token);
            return true;
        } catch (Exception e){
            System.out.println("Exception in verifying "+e.toString());
            return false;
        }
    }
    public static PublicKey getPublicKeyFromPem(File f)
            throws Exception
    {
        byte[] keyBytes = Files.readAllBytes(f.toPath());

        String temp = new String(keyBytes);
        String publicKeyPEM = temp;

        if(temp.contains("-----BEGIN PUBLIC KEY-----"))
        {
            publicKeyPEM = temp
                    .replace("-----BEGIN PUBLIC KEY-----\n", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .trim();
        }
        else if(temp.contains("-----BEGIN RSA PUBLIC KEY-----"))
        {
            publicKeyPEM = temp
                    .replace("-----BEGIN RSA PUBLIC KEY-----\n", "")
                    .replace("-----END RSA PUBLIC KEY-----", "")
                    .trim();
        }
        else if(temp.contains("-----BEGIN CERTIFICATE-----"))
        {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            try (FileInputStream is = new FileInputStream(f))
            {
                X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
                return cer.getPublicKey();
            }
        }

        Base64.Decoder b64 = Base64.getDecoder();
        byte[] decoded = b64.decode(publicKeyPEM);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
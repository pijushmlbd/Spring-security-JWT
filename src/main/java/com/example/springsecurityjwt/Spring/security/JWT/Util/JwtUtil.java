package com.example.springsecurityjwt.Spring.security.JWT.Util;

import com.example.springsecurityjwt.Spring.security.JWT.model.AuthenticationResponse;
import com.example.springsecurityjwt.Spring.security.JWT.property.TokenProperty;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    private static PrivateKey privateKey;
    private static PublicKey publicKey;


    TokenProperty tokenProperty;

    public JwtUtil(TokenProperty tokenProperty) {
        this.tokenProperty = tokenProperty;
    }


    public void generateKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        try (FileOutputStream fileOutputStream = new FileOutputStream("public.key")) {
            fileOutputStream.write(publicKey.getEncoded());
        }

        try (FileOutputStream fileOutputStream = new FileOutputStream("private.key")) {
            fileOutputStream.write(privateKey.getEncoded());
        }

    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
            publicKey = getPublicKey();
            return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public AuthenticationResponse generateToken(UserDetails userDetails) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        privateKey = getPrivateKey();
        if (privateKey == null)
            generateKeyPair();
        Map<String, Object> claims = new HashMap<>();
        return createAccessToken(claims, userDetails.getUsername(), privateKey);
    }

    private AuthenticationResponse createAccessToken(Map<String, Object> claims, String subject, PrivateKey privateKey) {

        String access_token = Jwts.builder().setClaims(claims).setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(new Date().getTime() + tokenProperty.getAccessTokenExpirationTime()))
                .signWith(SignatureAlgorithm.RS256, privateKey).compact();

        String refresh_token = Jwts.builder().setClaims(claims).setSubject(subject)
                .setIssuedAt(new Date())
                .setId("refresh_token")
                .setExpiration(new Date(new Date().getTime() + tokenProperty.getRefreshTokenExpirationTime()))
                .signWith(SignatureAlgorithm.RS256, privateKey).compact();

        return new AuthenticationResponse(access_token, refresh_token);

    }


    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public PublicKey getPublicKey()  {
        File publicKeyFile = new File("public.key");
        byte[] publicKeyBytes;
        try {
            publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    public PrivateKey getPrivateKey() {
        File privateKeyFile = new File("private.key");
        try {
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return keyFactory.generatePrivate(privateKeySpec);

        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }
}

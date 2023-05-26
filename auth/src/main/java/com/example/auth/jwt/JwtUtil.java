package com.example.auth.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Date;

public class JwtUtil {

//    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//    private static final long EXPIRATION_TIME_MS = 15 * 60 * 1000; // 15 minutos
//    private static final long EXPIRATION_TIME_MS = Long.MAX_VALUE; // no expira
    private static final long EXPIRATION_TIME_MS = 1000L * 60 * 60 * 24 * 365; // 1 año
    public static String generateToken(String username, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + EXPIRATION_TIME_MS);

        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiration);
        Key key = generateSecretKeyFromPassword(password);
                jwtBuilder.signWith(key)
                .compact();
        return jwtBuilder.compact();
    }

    public static boolean validateToken(String token, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            Jwts.parserBuilder().setSigningKey(generateSecretKeyFromPassword(password)).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static String getUsernameFromToken(String token, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(generateSecretKeyFromPassword(password))
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    private static final byte[] SECRET_KEY_SALT = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }; // Sal para mejorar la seguridad

    private static Key generateSecretKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), SECRET_KEY_SALT, 10000, 256);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
    }
}

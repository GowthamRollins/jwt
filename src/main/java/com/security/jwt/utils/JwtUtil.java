package com.security.jwt.utils;

import com.security.jwt.models.AuthRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.function.Function;

public class JwtUtil {

    private static final String SECRET = "!@#$%^&*()_+";

    public static String generateToken(AuthRequest authRequest) {
        return Jwts.builder()
                .setSubject(authRequest.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
                .signWith(SignatureAlgorithm.HS512, SECRET.getBytes()).compact();
    }

    public static String getSubject(String token) {
        return getClaimsFromToken(token, Claims::getSubject);
    }

    public static boolean checkIfTokenIsValid(String token) {
        return getClaimsFromToken(token, Claims::getIssuedAt).before(getClaimsFromToken(token, Claims::getExpiration));
    }

    private static <T> T getClaimsFromToken(String token, Function<Claims, T> claimResolver) {
        return claimResolver.apply(getAllClaims(token));
    }

    private static Claims getAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET.getBytes()).parseClaimsJws(token).getBody();
    }
}

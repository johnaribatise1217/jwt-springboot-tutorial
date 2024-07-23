package com.example.jwtAuth.Config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
  @Value("${security.jwt.secret-key}")
  private String secretKey;

  public String extractUsername(String token){
    return extractClaim(token, Claims::getSubject);
  }

  public <T> T extractClaim(String token , Function<Claims, T> claimsResolver){
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public String generateToken(UserDetails userDetails){
    return generateToken(new HashMap<>(), userDetails);
  }

  public String generateToken(
    Map<String, Object> extraClaims,
    UserDetails userDetails
  ){
    return Jwts
      .builder()
      .setClaims(extraClaims)
      .setSubject(userDetails.getUsername())
      .setIssuedAt(new Date(System.currentTimeMillis()))
      .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //set the expiration time to 24 hrs from the date issuedAt
      .signWith(getSigninKey(), SignatureAlgorithm.HS256)
      .compact();
  }

  public boolean isTokenValid(UserDetails userDetails, String token){
    final String username = extractUsername(token);
    return (
      username.equals(userDetails.getUsername()) && !isTokenExpired(token)
    );
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  private Date extractExpiration(String token) {
   return extractClaim(token, Claims::getExpiration);
  }

  private Claims extractAllClaims(String token){
    return Jwts
      .parserBuilder()
      .setSigningKey(getSigninKey())
      .build()
      .parseClaimsJws(token)
      .getBody();
  }

  private Key getSigninKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
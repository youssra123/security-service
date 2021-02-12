package com.exam.security.Security.Filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JwtAuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //On recupère nos credentials et on le retourne
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        //apres qu'attempt est reussie :
        System.out.println("Successful Authentication");
        //Recupere notre user
        User user = (User) authResult.getPrincipal();
        //Generer le token :
        //On ajoute la dep
        Algorithm algorithm1 = Algorithm.HMAC256("mySecret1234"); //signature
        //On construit le payload de notre access token
        String jwtAccessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 5*60*1000)) //give it a small timeout for eg 5min : pb de revocation de tokens
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(ga-> ga.getAuthority()).collect(Collectors.toList()))
                .sign(algorithm1);

    // To blacklist token no longer wanted
        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 15*60*1000)) // for a long time 1year or so
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm1);


        Map<String, String> idToken = new HashMap<>();
        idToken.put("access-Token",jwtAccessToken);
        idToken.put("refresh-Token",jwtRefreshToken);
        //On l'envoie au user dans le header  response.setHeader("Authorisation", jwtAccessToken);
        //Ou dans le body de type json
        //Quand on l'envoie en envoie dans le header un objet "Autorisation" de valeur Bearer accesstoken
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), idToken);

        // Reste à définir les autorisations
    }
}

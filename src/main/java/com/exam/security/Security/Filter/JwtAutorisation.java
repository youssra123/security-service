package com.exam.security.Security.Filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class JwtAutorisation extends OncePerRequestFilter {
    //intercepte la requete avant d'arriver à la servlet
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
       //Verifier si on a recu l'access token !! NON PAS LE REFRESH TOKEN
        if(request.getServletPath().equals("/refreshToken")) filterChain.doFilter(request,response);
        //lire le header autorization + Prefix Basic : auth basic http, or Bearer : porteur de JWT
        else{

            String authorizationToken = request.getHeader("Authorization");
            if(authorizationToken !=null && authorizationToken.startsWith("Bearer ")){
                try {
                    String jwt= authorizationToken.substring(7);
                    Algorithm algorithm = Algorithm.HMAC256("mySecret1234"); //Meme signature utilisée pour coder le token
                    // Pour HMAC : ma meme cle pour crypter et decripter Unlike RSA : cle privee et cle publique
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    //verifier si le jwt est valide :
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                    Arrays.stream(roles).forEach(r->{
                        grantedAuthorities.add(new SimpleGrantedAuthority(r));
                    });
                    //Objet User construit depuis le JTW !!
                    UsernamePasswordAuthenticationToken passwordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);
                    //Authentifier l'utilisateur
                    SecurityContextHolder.getContext().setAuthentication(passwordAuthenticationToken);
                    //Filter chain pour passer au filtre suivant (ici JWT Auth filter)
                    filterChain.doFilter(request,response);
                }catch (Exception e){
                    //Sinon interdir et renvoyer un code 403
                    response.setHeader("error-message", e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }

            }
            //Passer au filtre suivant pour vérifier si la requete requiert une authentification
            else{
                filterChain.doFilter(request,response);
            }


        }













    }

}

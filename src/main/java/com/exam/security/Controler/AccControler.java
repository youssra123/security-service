package com.exam.security.Controler;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.exam.security.Entities.AppRole;
import com.exam.security.Entities.AppUser;
import com.exam.security.Service.IService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccControler {
    private IService accService;

    public AccControler(IService accService) {
        this.accService = accService;
    }

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> listUser(){
        return accService.listUser();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addUSer(@RequestBody AppUser appUser){
        this.accService.addUser(appUser);
    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRole(@RequestBody AppRole appRole){
        this.accService.addRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleAndUserForm roleAndUserForm){
        this.accService.addRoleToUser(roleAndUserForm.getUsername(), roleAndUserForm.getRoleName());
    }

    //pour renouveler l'access token
    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request,HttpServletResponse response) throws IOException {
        String authToken = request.getHeader("Authorization");
        if(authToken != null && authToken.startsWith("Bearer ")){
            try{
                String refreshToken =authToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("mySecret1234");
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT= jwtVerifier.verify(refreshToken);
                String username = decodedJWT.getSubject();
                //Verifier la blacklist :
                AppUser appUser = accService.findUserByUsername(username);
                //On cree le nouveau access token
                String jwtNewAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 1*60*1000)) // 1 min
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                //On l'envoi !
                Map<String, String> idToken = new HashMap<>();
                idToken.put("access-Token",jwtNewAccessToken);
                idToken.put("refresh-Token",refreshToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);

            }catch (Exception e){
                response.setHeader("error-message in generating new token", e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                //or throw e
            }
        }
        else {
            throw new RuntimeException("Refresh token required");
        }
    }

}

@Data
class RoleAndUserForm{
    private String username;
    private String roleName;
}

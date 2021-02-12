package com.exam.security.Security;


import com.exam.security.Entities.AppUser;
import com.exam.security.Security.Filter.JwtAuthFilter;
import com.exam.security.Security.Filter.JwtAutorisation;
import com.exam.security.Service.IService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class ConfigSec extends WebSecurityConfigurerAdapter {
    private IService iService;

    public ConfigSec(IService iService) {
        this.iService = iService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*
        // accepter toutes les requetes
        http.authorizeRequests().anyRequest().permitAll(); // authenticated() : pour n'autoriser que les pers authentifieees
        // ne pas generer le sync token et le placer dans la session (pas de verif contre csrf attack) :
        //Pour stateFull seulement (stateLess ne travail pas avec les cookies et sessions)
        http.csrf().disable();
        // Autoriser les frames si on veut acceder a une app qui contient des frames
        http.headers().frameOptions().disable();
        //Pour afficher e formulaire d'authentification par def
        http.formLogin();
        */

        //Generer les JWT !!
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //AJOUTER FORMULAIRE
        http.formLogin();
        // P our authoriser h2 console sans auth
        http.authorizeRequests().antMatchers("/h2-console/**", "/refreshToken/**").permitAll();
        http.headers().frameOptions().disable();

        //ajouter les roles par has authority ou par annotation dans le controleur ou dans les services
/*        http.authorizeRequests().antMatchers(HttpMethod.POST,"/users/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers(HttpMethod.GET,"/users/**").hasAuthority("USER");*/
        http.authorizeRequests().anyRequest().authenticated();
        //config stateLESS->FILTRES
        //Creer des filtres :
            // JWT AUTH FILTER : pour generer un token (verifies and builds the TOKEN with a library JWTS)
            //JTW AUTORISATION : pour vérifier les autorisations par role !
        http.addFilter(new JwtAuthFilter(authenticationManager()));
        http.addFilterBefore(new JwtAutorisation(), UsernamePasswordAuthenticationFilter.class);

    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Auth StateFULL
        // to look for the user in the service
        auth.userDetailsService(username -> {
            AppUser appUser = iService.findUserByUsername(username);
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            //Soit on parcours et on ajoute chaque role dans la collection soit on le fait dans une class
            appUser.getAppRoles().stream().forEach(r ->{
                grantedAuthorities.add(new SimpleGrantedAuthority(r.getRoleName()));
            });
            // On retourne un objet de type User de spring
            return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
        });

    }
}

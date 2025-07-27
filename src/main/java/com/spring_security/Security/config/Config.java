package com.spring_security.Security.config;

import com.spring_security.Security.filter.JwtValidatorFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class Config {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtValidatorFilter(), BasicAuthenticationFilter.class)
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests((requests) -> requests
                .requestMatchers("roles/save").hasAnyRole("ADMIN", "USER")
                .requestMatchers("/getUsers","/users/saveWithRole").hasRole("ADMIN")
                .requestMatchers("/user/save", "/error", "/loginUser", "/getTokens", "/getTokensUsingBody").permitAll()
        );

//        http.csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests((requests) -> requests
//                        .requestMatchers("roles/save").authenticated()
//                        .requestMatchers("/getUsers","/users/saveWithRole").authenticated()
//                        .requestMatchers("/user/save", "/error").permitAll()
//                );
        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails users = User.withUsername("Siva").password("{noop}ohm").authorities("read").build();
//        UserDetails admin = User.withUsername("dhinesh")
//                .password("{bcrypt}$2a$12$.Hv4lJcz3kK1qyFXXSQV5OFD2aXcbT4ErbhP60zUzoEawuqKXf/Z.")
//                .authorities("admin").build();
//        return new InMemoryUserDetailsManager(users, admin);
//    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        MyAppUserAuthenticationProvider myAppUserAuthenticationProvider = new MyAppUserAuthenticationProvider(userDetailsService, passwordEncoder);
        ProviderManager providerManager = new ProviderManager(myAppUserAuthenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);
        return providerManager;
    }
}

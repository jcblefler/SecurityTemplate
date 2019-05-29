package com.example.security_template;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetailsService userDetailsServiceBean() throws Exception {
        return new SSUserDetailsService(userRepository);
    }

    // configure()
    // This overrides the default configure method, configures users who can
    // access the application. By default, Spring Boot will provide a new
    // random password assigned to the user "user" when it starts up, if you
    // do not include this method.
    //
    //
    // This is also the method in which you can configure how users are
    // granted access to the application if their details are stored in a
    // database.
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .authorizeRequests()
                .antMatchers("/css/**","/", "/h2/**", "/register").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login").permitAll() // Must be on it's own line
                .and()
                // logout() removes the user from the current session
                // default timeout is 20 minutes
                .logout()
                .logoutRequestMatcher(
                        new AntPathRequestMatcher("/logout"))
                // The user is redirected to the login page after logout
                .logoutSuccessUrl("/login").permitAll().permitAll()
                .and()
                .httpBasic();
        http
                .csrf().disable(); // Only for the H2 console, NOT IN PRODUCTION
        http
                .headers().frameOptions().disable(); // Only for the H2 console, NOT IN PRODUCTION
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {

        // Manually creates Spring Security user
        /*
        auth.inMemoryAuthentication().withUser("dave")
                .password(encoder().encode("password")).authorities("ADMIN");
        */

        // Allows database authentication
        auth.userDetailsService(userDetailsServiceBean())
                .passwordEncoder(encoder());
    }

}
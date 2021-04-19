package com.example.authenticatingldap;

import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.ppolicy.PasswordPolicyAwareContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Properties;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //@Autowired
    //private CustomAuthenticationProvider customAuthProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .formLogin();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.authenticationProvider(ldapAuthenticationProvider());

    }

    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() throws Exception {
        LdapAuthenticationProvider lAP = new LdapAuthenticationProvider(ldapAuthenticator(), ldapAuthoritiesPopulator());
        return lAP;
    }

    private LdapAuthoritiesPopulator ldapAuthoritiesPopulator() throws Exception {
        return new DefaultLdapAuthoritiesPopulator(ldapContextSource(), "OU=Global");
    }

    @Bean
    public LdapContextSource ldapContextSource() throws Exception {
        PasswordPolicyAwareContextSource contextSource = new PasswordPolicyAwareContextSource("ldaps://mfcgd.com:636");
        contextSource.setUserDn("svcapex_apex_ldap");
        contextSource.setPassword("&EzwsQSP2%mW");
        return contextSource;
    }

    @Bean
    public LdapAuthenticator ldapAuthenticator() throws Exception {
        BindAuthenticator authenticator = new BindAuthenticator(ldapContextSource());
        authenticator.setUserDnPatterns(new String[] {"CN={0},OU=Global"});
        return authenticator;
    }


}
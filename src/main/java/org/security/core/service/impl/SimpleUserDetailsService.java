package org.security.core.service.impl;

import java.util.HashSet;
import java.util.Set;

import org.security.core.model.SimpleUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author David Ruiz Coronel
 * @since 11/12/2015
 */
public class SimpleUserDetailsService implements UserDetailsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleUserDetailsService.class);

    /* (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        final SimpleUserDetails simpleUserDetails = new SimpleUserDetails();

        simpleUserDetails.setAccountNonExpired(true);
        simpleUserDetails.setAccountNonLocked(true);
        final Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        simpleUserDetails.setAuthorities(authorities);
        simpleUserDetails.setCredentialsNonExpired(true);
        simpleUserDetails.setEnabled(true);
        simpleUserDetails.setPassword("system");
        simpleUserDetails.setUsername(username);

        LOGGER.debug("user : {}", simpleUserDetails);

        return simpleUserDetails;
    }

}

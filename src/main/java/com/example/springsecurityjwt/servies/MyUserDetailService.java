package com.example.springsecurityjwt.servies;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class MyUserDetailService implements UserDetailsService
{
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException
    {

        System.out.println("++++loadUserByUsername: " + userName);
        // here hardcoded the user, ideally, it should return user from user service or other persistent service
        return
            new User("foo", "foo", new ArrayList<>());
    }
}

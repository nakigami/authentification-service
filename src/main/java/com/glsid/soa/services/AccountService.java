package com.glsid.soa.services;

import com.glsid.soa.entities.AppRole;
import com.glsid.soa.entities.AppUser;

import java.util.*;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}

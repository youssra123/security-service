package com.exam.security.Service;

import com.exam.security.Entities.AppRole;
import com.exam.security.Entities.AppUser;
import java.util.List;

public interface IService {
    AppUser addUser(AppUser appUser);
    AppRole addRole(AppRole appRole);
    void addRoleToUser(String nameRole, String nameUser);
    AppUser findUserByUsername(String username);
    List<AppUser> listUser();

}

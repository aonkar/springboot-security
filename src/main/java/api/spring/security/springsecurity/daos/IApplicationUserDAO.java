package api.spring.security.springsecurity.daos;

import api.spring.security.springsecurity.dtos.ApplicationUser;

import java.util.Optional;

public interface IApplicationUserDAO {

    public Optional<ApplicationUser> selectApplicationUserByUsername(final String username);

}

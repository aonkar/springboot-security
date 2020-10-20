package api.spring.security.springsecurity.daos.impls;

import api.spring.security.springsecurity.daos.IApplicationUserDAO;
import api.spring.security.springsecurity.dtos.ApplicationUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static api.spring.security.springsecurity.enums.ApplicationUserRoles.ADMIN;
import static api.spring.security.springsecurity.enums.ApplicationUserRoles.ADMIN_TRAINEE;
import static api.spring.security.springsecurity.enums.ApplicationUserRoles.STUDENT;

@Repository
public class FakeApplicationUserDAOService implements IApplicationUserDAO {

    @Autowired
    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDAOService(final PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(final String username) {
        return getApplicationUsers().stream().filter(
                applicationUser -> username.equals(applicationUser.getUsername())).findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        final List<ApplicationUser> applicationUsers = new ArrayList<>();
        applicationUsers.add(new ApplicationUser(
                STUDENT.getGrantedAuthorities(),
                "aonkar",
                passwordEncoder.encode("aonkar"),
                true,
                true,
                true,
                true
        ));
        applicationUsers.add(new ApplicationUser(
                ADMIN.getGrantedAuthorities(),
                "aonkar_admin",
                passwordEncoder.encode("aonkar_admin"),
                true,
                true,
                true,
                true
        ));
        applicationUsers.add(new ApplicationUser(
                ADMIN_TRAINEE.getGrantedAuthorities(),
                "aonkar_admin_trainee",
                passwordEncoder.encode("aonkar_admin_trainee"),
                true,
                true,
                true,
                true
        ));
        return applicationUsers;
    }
}

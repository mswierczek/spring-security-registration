package org.baeldung.service;

import org.baeldung.persistence.dao.DeviceMetadataRepository;
import org.baeldung.persistence.dao.PrivilegeRepository;
import org.baeldung.persistence.dao.RoleRepository;
import org.baeldung.persistence.dao.UserRepository;
import org.baeldung.persistence.model.Privilege;
import org.baeldung.persistence.model.Role;
import org.baeldung.persistence.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;

@Service
@Transactional
public class InitialDataService {

    private final DeviceMetadataRepository deviceMetadataRepository;

    private final PasswordEncoder passwordEncoder;

    private final PrivilegeRepository privilegeRepository;

    private final RoleRepository roleRepository;

    private final UserRepository userRepository;

    public InitialDataService(DeviceMetadataRepository deviceMetadataRepository, PasswordEncoder passwordEncoder,
                              PrivilegeRepository privilegeRepository, RoleRepository roleRepository,
                              UserRepository userRepository) {
        this.deviceMetadataRepository = deviceMetadataRepository;
        this.passwordEncoder = passwordEncoder;
        this.privilegeRepository = privilegeRepository;
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
    }

    public Privilege createPrivilegeIfNotFound(final String name) {
        Privilege privilege = privilegeRepository.findByName(name);
        if (privilege == null) {
            privilege = new Privilege(name);
            privilege = privilegeRepository.save(privilege);
        }
        return privilege;
    }

    public Role createRoleIfNotFound(final String name, final Collection<Privilege> privileges) {
        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
        }
        role.setPrivileges(privileges);
        role = roleRepository.save(role);
        return role;
    }

    public User createUserIfNotFound(final String email, final String firstName, final String lastName, final String password, final Collection<Role> roles) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            user = new User();
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setPassword(passwordEncoder.encode(password));
            user.setEmail(email);
            user.setEnabled(true);
        }
        user.setRoles(roles);
        user = userRepository.save(user);
        return user;
    }

}

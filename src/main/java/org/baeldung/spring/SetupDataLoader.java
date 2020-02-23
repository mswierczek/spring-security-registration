package org.baeldung.spring;

import org.baeldung.persistence.model.Privilege;
import org.baeldung.persistence.model.Role;
import org.baeldung.security.Privileges;
import org.baeldung.security.Roles;
import org.baeldung.service.InitialDataService;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private static final AtomicBoolean IS_INITIAL_DATA_ALREADY_SETUP = new AtomicBoolean(false);

    private static final Object LOCK = new Object();

    private final InitialDataService initialDataService;

    public SetupDataLoader(InitialDataService initialDataService) {
        this.initialDataService = initialDataService;
    }

    // API
    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {
        synchronized (LOCK) {
            if (IS_INITIAL_DATA_ALREADY_SETUP.get()) {
                return;
            }

            // == create initial privileges
            final Privilege readPrivilege = initialDataService.createPrivilegeIfNotFound(Privileges.READ_PRIVILEGE);
            final Privilege writePrivilege = initialDataService.createPrivilegeIfNotFound(Privileges.WRITE_PRIVILEGE);
            final Privilege passwordPrivilege = initialDataService.createPrivilegeIfNotFound(Privileges.CHANGE_PASSWORD_PRIVILEGE);
            final Privilege managerPrivilege = initialDataService.createPrivilegeIfNotFound(Privileges.MANAGER_PRIVILEGE);

            // == create initial roles
            final List<Privilege> adminPrivileges = asMutableList(readPrivilege, writePrivilege, passwordPrivilege, managerPrivilege);
            final List<Privilege> userPrivileges = asMutableList(readPrivilege, passwordPrivilege);
            final List<Privilege> managerPrivileges = asMutableList(readPrivilege, passwordPrivilege, managerPrivilege);


            final Role adminRole = initialDataService.createRoleIfNotFound(Roles.ROLE_ADMIN, adminPrivileges);
            initialDataService.createRoleIfNotFound(Roles.ROLE_USER, userPrivileges);

            final Role managerRole = initialDataService.createRoleIfNotFound(Roles.ROLE_MANAGER, managerPrivileges);

            // == create initial users
            initialDataService.createUserIfNotFound("test@test.com", "Test", "Test", "test",
                asMutableList(adminRole));

            initialDataService.createUserIfNotFound("manager@test.com", "John", "Doe", "manager",
                asMutableList(managerRole));

            IS_INITIAL_DATA_ALREADY_SETUP.set(true);
        }
    }

    @SafeVarargs
    private final <E> List<E> asMutableList(E... items) {
        return new ArrayList<>(Arrays.asList(items));
    }

}
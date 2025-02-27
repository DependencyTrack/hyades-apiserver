package org.dependencytrack.persistence;

import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.List;

import javax.jdo.PersistenceManager;

import org.dependencytrack.model.Role;

import alpine.common.logging.Logger;
import alpine.resources.AlpineRequest;

final class RoleQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(ProjectQueryManager.class);

    RoleQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    RoleQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public Role createRole(Role role) {
        // TODO:Implement role creation logic
        return role;
    }

    public List<Role> getRoles() {
        // TODO:Implement role retrieval logic
        return Collections.emptyList();
    }

    public Role getRole(String uuid) {
        // TODO:Implement role retrieval logic
        return null;
    }

    public Role updateRole(Role role) {
        // TODO:Implement role update logic
        return role;
    }

    public boolean deleteRole(String uuid, boolean value) {
        // TODO:Implement role deletion logic
        return false;
    }

    boolean addRoleToUser(UserPrincipal principal, Role role, String roleName, String projectName){
        //WARNING: This method is a stub.
        //TODO: Implement addRoleToUser
        return true;
    }

    boolean removeRoleFromUser(UserPrincipal principal, Role role, String roleName, String projectName){
        //WARNING: This method is a stub.
        //TODO: Implement removeRoleFromUser
        return true;
    }
}

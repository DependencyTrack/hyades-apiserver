package org.dependencytrack.persistence;

import java.nio.file.attribute.UserPrincipal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.dependencytrack.model.Role;

import alpine.common.logging.Logger;
import alpine.model.Permission;
import alpine.resources.AlpineRequest;

final class RoleQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(ProjectQueryManager.class);

    RoleQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    RoleQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
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

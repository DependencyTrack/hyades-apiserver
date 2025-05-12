package org.dependencytrack.persistence;

import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.List;

import javax.jdo.PersistenceManager;

import org.dependencytrack.model.Role;

import org.apache.commons.lang3.StringUtils;

import alpine.common.logging.Logger;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.User;
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

    @Override
    public Role getRoleByName(final String name) {
        final String role = StringUtils.lowerCase(StringUtils.trimToNull(name));
        final Query<Role> query = pm.newQuery(Role.class)
                .filter("name.toLowerCase().trim() == :name")
                .setNamedParameters(Map.of("name", role))
                .range(0, 1);

        return executeAndCloseUnique(query);
    }

    @Override
    public Role getRole(final String uuid) {
        return getObjectByUuid(Role.class, uuid, Role.FetchGroup.ALL.name());
    }

    @Override
    public List<ProjectRole> getUserRoles(final User user) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class)
                .getUserRoles(user.getUsername()));
    }

    public List<Project> getUnassignedProjects(final String username) {
        return getUnassignedProjects(getUser(username));
    }

    public List<Project> getUnassignedProjects(final User user) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class)
                .getUserUnassignedProjects(user.getUsername()));
    }

    public List<Permission> getUnassignedRolePermissions(final Role role) {
        final List<Permission> permissions = new ArrayList<>();

        final var permissionNames = role.getPermissions().stream()
                .map(Permission::getName)
                .toList();

        final Query<Permission> query = pm.newQuery(Permission.class)
                .filter("!:permissionNames.contains(name)")
                .setNamedParameters(Map.of("permissionNames", permissionNames));

        permissions.addAll(executeAndCloseList(query));

        return permissions;
    }

    @Override
    public Role updateRole(final Role transientRole) {
        final Role role = getObjectByUuid(Role.class, transientRole.getUuid());
        if (role == null)
            return null;

        role.setName(transientRole.getName());

        return persist(role);
    }

    @Override
    public List<Permission> getUserProjectPermissions(final String username, final String projectName) {
        final User user = getUser(username);
        final String columnName;

        switch (user) {
            case LdapUser ldapUser -> columnName = "LDAPUSER_ID";
            case ManagedUser managedUser -> columnName = "MANAGEDUSER_ID";
            case OidcUser oidcUser -> columnName = "OIDCUSER_ID";
            default -> {
                return null;
            }
        }

        final Query<Project> projectsQuery = pm.newQuery(Project.class)
                .filter("name == :projectName")
                .setNamedParameters(Map.of("projectName", projectName));

        final String projectIds = executeAndCloseList(projectsQuery).stream()
                .map(Project::getId)
                .map(String::valueOf)
                .collect(Collectors.joining(", ", "(", ")"));

        // language=SQL
        final var queryString = """
                SELECT
                    upep."LDAPUSER_ID",
                    upep."MANAGEDUSER_ID",
                    upep."OIDCUSER_ID",
                    upep."PROJECT_ID",
                    upep."PERMISSION_ID",
                    upep."PERMISSION_NAME"
                  FROM "USER_PROJECT_EFFECTIVE_PERMISSIONS" upep
                 WHERE upep."%s" = :userId
                   AND upep."PROJECT_ID" IN %s
                """.formatted(columnName, projectIds);

        final Query<?> query = pm.newQuery(Query.SQL, queryString);
        query.setNamedParameters(Map.of(
                "userId", user.getId(),
                "projectIds", projectIds));

        return executeAndCloseResultList(query, UserProjectEffectivePermissionsRow.class)
                .stream()
                .map(UserProjectEffectivePermissionsRow::permissionName)
                .map(this::getPermission)
                .distinct()
                .toList();
    }

    @Override
    public boolean addRoleToUser(final User user, final Role role, final Project project) {
        return JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addRoleToUser(
                        user.getId(),
                        project.getId(),
                        role.getId())) == 1;
    }

    @Override
    public boolean removeRoleFromUser(final User user, final Role role, final Project project) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class).removeRoleFromUser(
                user.getId(),
                project.getName(),
                role.getId())) > 0;
    }

}

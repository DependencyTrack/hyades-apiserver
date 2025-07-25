/*
 * This file is generated by jOOQ.
 */
package org.dependencytrack.persistence.jooq.generated.tables;


import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.dependencytrack.persistence.jooq.generated.DefaultSchema;
import org.dependencytrack.persistence.jooq.generated.Keys;
import org.dependencytrack.persistence.jooq.generated.tables.Project.ProjectPath;
import org.dependencytrack.persistence.jooq.generated.tables.Team.TeamPath;
import org.dependencytrack.persistence.jooq.generated.tables.records.ProjectAccessTeamsRecord;
import org.jooq.Condition;
import org.jooq.Field;
import org.jooq.ForeignKey;
import org.jooq.InverseForeignKey;
import org.jooq.Name;
import org.jooq.Path;
import org.jooq.PlainSQL;
import org.jooq.QueryPart;
import org.jooq.Record;
import org.jooq.SQL;
import org.jooq.Schema;
import org.jooq.Select;
import org.jooq.Stringly;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.UniqueKey;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class ProjectAccessTeams extends TableImpl<ProjectAccessTeamsRecord> {

    private static final long serialVersionUID = -1362786051;

    /**
     * The reference instance of <code>PROJECT_ACCESS_TEAMS</code>
     */
    public static final ProjectAccessTeams PROJECT_ACCESS_TEAMS = new ProjectAccessTeams();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<ProjectAccessTeamsRecord> getRecordType() {
        return ProjectAccessTeamsRecord.class;
    }

    /**
     * The column <code>PROJECT_ACCESS_TEAMS.PROJECT_ID</code>.
     */
    public final TableField<ProjectAccessTeamsRecord, Long> projectId = createField(DSL.name("PROJECT_ID"), SQLDataType.BIGINT.nullable(false), this, "");

    /**
     * The column <code>PROJECT_ACCESS_TEAMS.TEAM_ID</code>.
     */
    public final TableField<ProjectAccessTeamsRecord, Long> teamId = createField(DSL.name("TEAM_ID"), SQLDataType.BIGINT.nullable(false), this, "");

    private ProjectAccessTeams(Name alias, Table<ProjectAccessTeamsRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private ProjectAccessTeams(Name alias, Table<ProjectAccessTeamsRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>PROJECT_ACCESS_TEAMS</code> table reference
     */
    public ProjectAccessTeams(String alias) {
        this(DSL.name(alias), PROJECT_ACCESS_TEAMS);
    }

    /**
     * Create an aliased <code>PROJECT_ACCESS_TEAMS</code> table reference
     */
    public ProjectAccessTeams(Name alias) {
        this(alias, PROJECT_ACCESS_TEAMS);
    }

    /**
     * Create a <code>PROJECT_ACCESS_TEAMS</code> table reference
     */
    public ProjectAccessTeams() {
        this(DSL.name("PROJECT_ACCESS_TEAMS"), null);
    }

    public <O extends Record> ProjectAccessTeams(Table<O> path, ForeignKey<O, ProjectAccessTeamsRecord> childPath, InverseForeignKey<O, ProjectAccessTeamsRecord> parentPath) {
        super(path, childPath, parentPath, PROJECT_ACCESS_TEAMS);
    }

    /**
     * A subtype implementing {@link Path} for simplified path-based joins.
     */
    public static class ProjectAccessTeamsPath extends ProjectAccessTeams implements Path<ProjectAccessTeamsRecord> {

        private static final long serialVersionUID = -1362786051;
        public <O extends Record> ProjectAccessTeamsPath(Table<O> path, ForeignKey<O, ProjectAccessTeamsRecord> childPath, InverseForeignKey<O, ProjectAccessTeamsRecord> parentPath) {
            super(path, childPath, parentPath);
        }
        private ProjectAccessTeamsPath(Name alias, Table<ProjectAccessTeamsRecord> aliased) {
            super(alias, aliased);
        }

        @Override
        public ProjectAccessTeamsPath as(String alias) {
            return new ProjectAccessTeamsPath(DSL.name(alias), this);
        }

        @Override
        public ProjectAccessTeamsPath as(Name alias) {
            return new ProjectAccessTeamsPath(alias, this);
        }

        @Override
        public ProjectAccessTeamsPath as(Table<?> alias) {
            return new ProjectAccessTeamsPath(alias.getQualifiedName(), this);
        }
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : DefaultSchema.DEFAULT_SCHEMA;
    }

    @Override
    public UniqueKey<ProjectAccessTeamsRecord> getPrimaryKey() {
        return Keys.PROJECT_ACCESS_TEAMS_PK;
    }

    @Override
    public List<ForeignKey<ProjectAccessTeamsRecord, ?>> getReferences() {
        return Arrays.asList(Keys.PROJECT_ACCESS_TEAMS_PROJECT_FK, Keys.PROJECT_ACCESS_TEAMS_TEAM_FK);
    }

    private transient ProjectPath _project;

    /**
     * Get the implicit join path to the <code>PROJECT</code> table.
     */
    public ProjectPath project() {
        if (_project == null)
            _project = new ProjectPath(this, Keys.PROJECT_ACCESS_TEAMS_PROJECT_FK, null);

        return _project;
    }

    private transient TeamPath _team;

    /**
     * Get the implicit join path to the <code>TEAM</code> table.
     */
    public TeamPath team() {
        if (_team == null)
            _team = new TeamPath(this, Keys.PROJECT_ACCESS_TEAMS_TEAM_FK, null);

        return _team;
    }

    @Override
    public ProjectAccessTeams as(String alias) {
        return new ProjectAccessTeams(DSL.name(alias), this);
    }

    @Override
    public ProjectAccessTeams as(Name alias) {
        return new ProjectAccessTeams(alias, this);
    }

    @Override
    public ProjectAccessTeams as(Table<?> alias) {
        return new ProjectAccessTeams(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public ProjectAccessTeams rename(String name) {
        return new ProjectAccessTeams(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public ProjectAccessTeams rename(Name name) {
        return new ProjectAccessTeams(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public ProjectAccessTeams rename(Table<?> name) {
        return new ProjectAccessTeams(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ProjectAccessTeams where(Condition condition) {
        return new ProjectAccessTeams(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ProjectAccessTeams where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ProjectAccessTeams where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ProjectAccessTeams where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public ProjectAccessTeams where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public ProjectAccessTeams where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public ProjectAccessTeams where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public ProjectAccessTeams where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ProjectAccessTeams whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ProjectAccessTeams whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}

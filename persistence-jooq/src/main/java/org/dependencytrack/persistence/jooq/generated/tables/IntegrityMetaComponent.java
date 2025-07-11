/*
 * This file is generated by jOOQ.
 */
package org.dependencytrack.persistence.jooq.generated.tables;


import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.dependencytrack.persistence.jooq.generated.DefaultSchema;
import org.dependencytrack.persistence.jooq.generated.Indexes;
import org.dependencytrack.persistence.jooq.generated.Keys;
import org.dependencytrack.persistence.jooq.generated.tables.records.IntegrityMetaComponentRecord;
import org.jooq.Check;
import org.jooq.Condition;
import org.jooq.Field;
import org.jooq.Identity;
import org.jooq.Index;
import org.jooq.Name;
import org.jooq.PlainSQL;
import org.jooq.QueryPart;
import org.jooq.SQL;
import org.jooq.Schema;
import org.jooq.Select;
import org.jooq.Stringly;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.UniqueKey;
import org.jooq.impl.DSL;
import org.jooq.impl.Internal;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class IntegrityMetaComponent extends TableImpl<IntegrityMetaComponentRecord> {

    private static final long serialVersionUID = -1245477881;

    /**
     * The reference instance of <code>INTEGRITY_META_COMPONENT</code>
     */
    public static final IntegrityMetaComponent INTEGRITY_META_COMPONENT = new IntegrityMetaComponent();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<IntegrityMetaComponentRecord> getRecordType() {
        return IntegrityMetaComponentRecord.class;
    }

    /**
     * The column <code>INTEGRITY_META_COMPONENT.ID</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, Long> id = createField(DSL.name("ID"), SQLDataType.BIGINT.nullable(false).identity(true), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.LAST_FETCH</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, OffsetDateTime> lastFetch = createField(DSL.name("LAST_FETCH"), SQLDataType.TIMESTAMPWITHTIMEZONE(6), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.MD5</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, String> md5 = createField(DSL.name("MD5"), SQLDataType.VARCHAR(32), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.PUBLISHED_AT</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, OffsetDateTime> publishedAt = createField(DSL.name("PUBLISHED_AT"), SQLDataType.TIMESTAMPWITHTIMEZONE(6), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.PURL</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, String> purl = createField(DSL.name("PURL"), SQLDataType.VARCHAR(1024).nullable(false), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.REPOSITORY_URL</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, String> repositoryUrl = createField(DSL.name("REPOSITORY_URL"), SQLDataType.VARCHAR(1024), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.SHA1</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, String> sha1 = createField(DSL.name("SHA1"), SQLDataType.VARCHAR(40), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.SHA256</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, String> sha256 = createField(DSL.name("SHA256"), SQLDataType.VARCHAR(64), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.SHA512</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, String> sha512 = createField(DSL.name("SHA512"), SQLDataType.VARCHAR(128), this, "");

    /**
     * The column <code>INTEGRITY_META_COMPONENT.STATUS</code>.
     */
    public final TableField<IntegrityMetaComponentRecord, String> status = createField(DSL.name("STATUS"), SQLDataType.VARCHAR(64), this, "");

    private IntegrityMetaComponent(Name alias, Table<IntegrityMetaComponentRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private IntegrityMetaComponent(Name alias, Table<IntegrityMetaComponentRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>INTEGRITY_META_COMPONENT</code> table reference
     */
    public IntegrityMetaComponent(String alias) {
        this(DSL.name(alias), INTEGRITY_META_COMPONENT);
    }

    /**
     * Create an aliased <code>INTEGRITY_META_COMPONENT</code> table reference
     */
    public IntegrityMetaComponent(Name alias) {
        this(alias, INTEGRITY_META_COMPONENT);
    }

    /**
     * Create a <code>INTEGRITY_META_COMPONENT</code> table reference
     */
    public IntegrityMetaComponent() {
        this(DSL.name("INTEGRITY_META_COMPONENT"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : DefaultSchema.DEFAULT_SCHEMA;
    }

    @Override
    public List<Index> getIndexes() {
        return Arrays.asList(Indexes.INTEGRITY_META_COMPONENT_PURL_IDX, Indexes.LAST_FETCH_IDX);
    }

    @Override
    public Identity<IntegrityMetaComponentRecord, Long> getIdentity() {
        return (Identity<IntegrityMetaComponentRecord, Long>) super.getIdentity();
    }

    @Override
    public UniqueKey<IntegrityMetaComponentRecord> getPrimaryKey() {
        return Keys.INTEGRITY_META_COMPONENT_PK;
    }

    @Override
    public List<Check<IntegrityMetaComponentRecord>> getChecks() {
        return Arrays.asList(
            Internal.createCheck(this, DSL.name("INTEGRITY_META_COMPONENT_STATUS_check"), "(((\"STATUS\" IS NULL) OR ((\"STATUS\")::text = ANY (ARRAY['IN_PROGRESS'::text, 'NOT_AVAILABLE'::text, 'PROCESSED'::text]))))", true)
        );
    }

    @Override
    public IntegrityMetaComponent as(String alias) {
        return new IntegrityMetaComponent(DSL.name(alias), this);
    }

    @Override
    public IntegrityMetaComponent as(Name alias) {
        return new IntegrityMetaComponent(alias, this);
    }

    @Override
    public IntegrityMetaComponent as(Table<?> alias) {
        return new IntegrityMetaComponent(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public IntegrityMetaComponent rename(String name) {
        return new IntegrityMetaComponent(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public IntegrityMetaComponent rename(Name name) {
        return new IntegrityMetaComponent(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public IntegrityMetaComponent rename(Table<?> name) {
        return new IntegrityMetaComponent(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public IntegrityMetaComponent where(Condition condition) {
        return new IntegrityMetaComponent(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public IntegrityMetaComponent where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public IntegrityMetaComponent where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public IntegrityMetaComponent where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public IntegrityMetaComponent where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public IntegrityMetaComponent where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public IntegrityMetaComponent where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public IntegrityMetaComponent where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public IntegrityMetaComponent whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public IntegrityMetaComponent whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}

/*
 * This file is generated by jOOQ.
 */
package org.dependencytrack.persistence.jooq.generated.tables;


import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.dependencytrack.persistence.jooq.generated.DefaultSchema;
import org.dependencytrack.persistence.jooq.generated.Keys;
import org.dependencytrack.persistence.jooq.generated.tables.NotificationRule.NotificationRulePath;
import org.dependencytrack.persistence.jooq.generated.tables.records.NotificationPublisherRecord;
import org.jooq.Condition;
import org.jooq.Field;
import org.jooq.ForeignKey;
import org.jooq.Identity;
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
public class NotificationPublisher extends TableImpl<NotificationPublisherRecord> {

    private static final long serialVersionUID = 885777098;

    /**
     * The reference instance of <code>NOTIFICATIONPUBLISHER</code>
     */
    public static final NotificationPublisher NOTIFICATIONPUBLISHER = new NotificationPublisher();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<NotificationPublisherRecord> getRecordType() {
        return NotificationPublisherRecord.class;
    }

    /**
     * The column <code>NOTIFICATIONPUBLISHER.ID</code>.
     */
    public final TableField<NotificationPublisherRecord, Long> id = createField(DSL.name("ID"), SQLDataType.BIGINT.nullable(false).identity(true), this, "");

    /**
     * The column <code>NOTIFICATIONPUBLISHER.DEFAULT_PUBLISHER</code>.
     */
    public final TableField<NotificationPublisherRecord, Boolean> defaultPublisher = createField(DSL.name("DEFAULT_PUBLISHER"), SQLDataType.BOOLEAN.nullable(false), this, "");

    /**
     * The column <code>NOTIFICATIONPUBLISHER.DESCRIPTION</code>.
     */
    public final TableField<NotificationPublisherRecord, String> description = createField(DSL.name("DESCRIPTION"), SQLDataType.VARCHAR(255), this, "");

    /**
     * The column <code>NOTIFICATIONPUBLISHER.NAME</code>.
     */
    public final TableField<NotificationPublisherRecord, String> name = createField(DSL.name("NAME"), SQLDataType.VARCHAR(255).nullable(false), this, "");

    /**
     * The column <code>NOTIFICATIONPUBLISHER.PUBLISHER_CLASS</code>.
     */
    public final TableField<NotificationPublisherRecord, String> publisherClass = createField(DSL.name("PUBLISHER_CLASS"), SQLDataType.VARCHAR(1024).nullable(false), this, "");

    /**
     * The column <code>NOTIFICATIONPUBLISHER.TEMPLATE</code>.
     */
    public final TableField<NotificationPublisherRecord, String> template = createField(DSL.name("TEMPLATE"), SQLDataType.CLOB, this, "");

    /**
     * The column <code>NOTIFICATIONPUBLISHER.TEMPLATE_MIME_TYPE</code>.
     */
    public final TableField<NotificationPublisherRecord, String> templateMimeType = createField(DSL.name("TEMPLATE_MIME_TYPE"), SQLDataType.VARCHAR(255).nullable(false), this, "");

    /**
     * The column <code>NOTIFICATIONPUBLISHER.UUID</code>.
     */
    public final TableField<NotificationPublisherRecord, UUID> uuid = createField(DSL.name("UUID"), SQLDataType.UUID.nullable(false), this, "");

    private NotificationPublisher(Name alias, Table<NotificationPublisherRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private NotificationPublisher(Name alias, Table<NotificationPublisherRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>NOTIFICATIONPUBLISHER</code> table reference
     */
    public NotificationPublisher(String alias) {
        this(DSL.name(alias), NOTIFICATIONPUBLISHER);
    }

    /**
     * Create an aliased <code>NOTIFICATIONPUBLISHER</code> table reference
     */
    public NotificationPublisher(Name alias) {
        this(alias, NOTIFICATIONPUBLISHER);
    }

    /**
     * Create a <code>NOTIFICATIONPUBLISHER</code> table reference
     */
    public NotificationPublisher() {
        this(DSL.name("NOTIFICATIONPUBLISHER"), null);
    }

    public <O extends Record> NotificationPublisher(Table<O> path, ForeignKey<O, NotificationPublisherRecord> childPath, InverseForeignKey<O, NotificationPublisherRecord> parentPath) {
        super(path, childPath, parentPath, NOTIFICATIONPUBLISHER);
    }

    /**
     * A subtype implementing {@link Path} for simplified path-based joins.
     */
    public static class NotificationPublisherPath extends NotificationPublisher implements Path<NotificationPublisherRecord> {

        private static final long serialVersionUID = 885777098;
        public <O extends Record> NotificationPublisherPath(Table<O> path, ForeignKey<O, NotificationPublisherRecord> childPath, InverseForeignKey<O, NotificationPublisherRecord> parentPath) {
            super(path, childPath, parentPath);
        }
        private NotificationPublisherPath(Name alias, Table<NotificationPublisherRecord> aliased) {
            super(alias, aliased);
        }

        @Override
        public NotificationPublisherPath as(String alias) {
            return new NotificationPublisherPath(DSL.name(alias), this);
        }

        @Override
        public NotificationPublisherPath as(Name alias) {
            return new NotificationPublisherPath(alias, this);
        }

        @Override
        public NotificationPublisherPath as(Table<?> alias) {
            return new NotificationPublisherPath(alias.getQualifiedName(), this);
        }
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : DefaultSchema.DEFAULT_SCHEMA;
    }

    @Override
    public Identity<NotificationPublisherRecord, Long> getIdentity() {
        return (Identity<NotificationPublisherRecord, Long>) super.getIdentity();
    }

    @Override
    public UniqueKey<NotificationPublisherRecord> getPrimaryKey() {
        return Keys.NOTIFICATIONPUBLISHER_PK;
    }

    @Override
    public List<UniqueKey<NotificationPublisherRecord>> getUniqueKeys() {
        return Arrays.asList(Keys.NOTIFICATIONPUBLISHER_UUID_IDX);
    }

    private transient NotificationRulePath _notificationRule;

    /**
     * Get the implicit to-many join path to the <code>NOTIFICATIONRULE</code>
     * table
     */
    public NotificationRulePath notificationRule() {
        if (_notificationRule == null)
            _notificationRule = new NotificationRulePath(this, null, Keys.NOTIFICATIONRULE_NOTIFICATIONPUBLISHER_FK.getInverseKey());

        return _notificationRule;
    }

    @Override
    public NotificationPublisher as(String alias) {
        return new NotificationPublisher(DSL.name(alias), this);
    }

    @Override
    public NotificationPublisher as(Name alias) {
        return new NotificationPublisher(alias, this);
    }

    @Override
    public NotificationPublisher as(Table<?> alias) {
        return new NotificationPublisher(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public NotificationPublisher rename(String name) {
        return new NotificationPublisher(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public NotificationPublisher rename(Name name) {
        return new NotificationPublisher(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public NotificationPublisher rename(Table<?> name) {
        return new NotificationPublisher(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public NotificationPublisher where(Condition condition) {
        return new NotificationPublisher(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public NotificationPublisher where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public NotificationPublisher where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public NotificationPublisher where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public NotificationPublisher where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public NotificationPublisher where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public NotificationPublisher where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public NotificationPublisher where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public NotificationPublisher whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public NotificationPublisher whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}

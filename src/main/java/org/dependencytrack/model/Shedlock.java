package org.dependencytrack.model;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Date;

@PersistenceCapable(table="shedlock")
public class Shedlock implements Serializable {

    @PrimaryKey
    @Persistent
    @Column(name = "name", length = 64, allowsNull = "false")
    private String name;

    @Persistent
    @Column(name = "lock_until", allowsNull = "false")
    private LocalDateTime lockUntil;

    @Persistent
    @Column(name = "locked_at", allowsNull = "false")
    private LocalDateTime lockedAt;

    @Persistent
    @Column(name = "locked_by", length = 255, allowsNull = "false")
    private String lockedBy;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public LocalDateTime getLockUntil() {
        return lockUntil;
    }

    public void setLockUntil(LocalDateTime lockUntil) {
        this.lockUntil = lockUntil;
    }

    public LocalDateTime getLockedAt() {
        return lockedAt;
    }

    public void setLockedAt(LocalDateTime lockedAt) {
        this.lockedAt = lockedAt;
    }

    public String getLockedBy() {
        return lockedBy;
    }

    public void setLockedBy(String lockedBy) {
        this.lockedBy = lockedBy;
    }
}

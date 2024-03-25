package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Project;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus;

import java.util.List;
import java.util.UUID;

public class ProjectVulnAnalysisComplete {

    private UUID token;
    private final Project project;
    private final List<ComponentVulnAnalysisComplete> findingsList;
    private final ProjectVulnAnalysisStatus status;

    public ProjectVulnAnalysisComplete(final UUID token, Project project, List<ComponentVulnAnalysisComplete> findingsList, ProjectVulnAnalysisStatus status) {
        this.token = token;
        this.project = project;
        this.findingsList = findingsList;
        this.status = status;
    }

    public UUID getToken() {
        return token;
    }

    public List<ComponentVulnAnalysisComplete> getComponentAnalysisCompleteList() {
        return findingsList;
    }

    public Project getProject() {
        return this.project;
    }

    public ProjectVulnAnalysisStatus getStatus() {
        return status;
    }
}

package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Project;
import org.hyades.proto.notification.v1.ProjectVulnAnalysisStatus;

import java.util.List;

public class ProjectVulnAnalysisComplete {
    private final Project project;
    private final List<ComponentVulnAnalysisComplete> findingsList;
    private final ProjectVulnAnalysisStatus status;

    public ProjectVulnAnalysisComplete(Project project, List<ComponentVulnAnalysisComplete> findingsList, ProjectVulnAnalysisStatus status) {
        this.project = project;
        this.findingsList = findingsList;
        this.status = status;
    }

    public List<ComponentVulnAnalysisComplete> getComponentAnalysisCompleteList() {
        return findingsList;
    }

    public Project getProject(){
        return this.project;
    }

    public ProjectVulnAnalysisStatus getStatus() {
        return status;
    }
}

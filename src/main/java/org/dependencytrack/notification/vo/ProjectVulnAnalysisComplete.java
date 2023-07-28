package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Project;

import java.util.List;

public class ProjectVulnAnalysisComplete {
    private final Project project;
    private final List<ComponentVulnAnalysisComplete> findingsList;
    private final String status;

    public ProjectVulnAnalysisComplete(Project project, List<ComponentVulnAnalysisComplete> findingsList, String status) {
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
}

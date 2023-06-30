package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Project;

import java.util.List;

public class ProjectVulnAnalysisComplete {
    private final Project project;
    private final List<ComponentVulnAnalysisComplete> findingsList;

    public ProjectVulnAnalysisComplete(Project project, List<ComponentVulnAnalysisComplete> findingsList) {
        this.project = project;
        this.findingsList = findingsList;
    }

    public List<ComponentVulnAnalysisComplete> getComponentAnalysisCompleteList() {
        return findingsList;
    }

    public Project getProject(){
        return this.project;
    }
}

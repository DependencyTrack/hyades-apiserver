package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Project;

import java.util.List;

public class ProjectVulnAnalysisComplete {
    private final Project project;
    private final List<ComponentVulnAnalysisComplete> componentAnalysisCompleteList;

    public ProjectVulnAnalysisComplete(Project project, List<ComponentVulnAnalysisComplete> componentAnalysisCompleteList) {
        this.project = project;
        this.componentAnalysisCompleteList = componentAnalysisCompleteList;
    }

    public List<ComponentVulnAnalysisComplete> getComponentAnalysisCompleteList() {
        return componentAnalysisCompleteList;
    }

    public Project getProject(){
        return this.project;
    }
}

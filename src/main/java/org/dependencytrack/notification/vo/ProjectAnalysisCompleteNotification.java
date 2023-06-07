package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Project;

import java.util.List;

public class ProjectAnalysisCompleteNotification {
    private final Project project;
    private final List<ComponentAnalysisComplete> componentAnalysisCompleteList;

    public ProjectAnalysisCompleteNotification(Project project, List<ComponentAnalysisComplete> componentAnalysisCompleteList) {
        this.project = project;
        this.componentAnalysisCompleteList = componentAnalysisCompleteList;
    }

    public List<ComponentAnalysisComplete> getComponentAnalysisCompleteList() {
        return componentAnalysisCompleteList;
    }

    public Project getProject(){
        return this.project;
    }
}

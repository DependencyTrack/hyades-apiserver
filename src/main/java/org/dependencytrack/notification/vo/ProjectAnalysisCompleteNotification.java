package org.dependencytrack.notification.vo;

import java.util.List;

public class ProjectAnalysisCompleteNotification {
    private final List<ComponentAnalysisComplete> componentAnalysisCompleteList;

    public ProjectAnalysisCompleteNotification(List<ComponentAnalysisComplete> componentAnalysisCompleteList) {
        this.componentAnalysisCompleteList = componentAnalysisCompleteList;
    }

    public List<ComponentAnalysisComplete> getComponentAnalysisCompleteList() {
        return componentAnalysisCompleteList;
    }
}

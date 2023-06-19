package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Project;

import java.util.List;

public class ProjectVulnAnalysisComplete {
    private final Project project;
    private final List<Findings> findingsList;

    public ProjectVulnAnalysisComplete(Project project, List<Findings> findingsList) {
        this.project = project;
        this.findingsList = findingsList;
    }

    public List<Findings> getComponentAnalysisCompleteList() {
        return findingsList;
    }

    public Project getProject(){
        return this.project;
    }
}

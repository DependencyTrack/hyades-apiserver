package org.dependencytrack.notification.persistence;

import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.jdbi.v3.core.result.RowReducer;
import org.jdbi.v3.core.result.RowView;

import java.util.stream.Stream;

public class NewVulnerableDependencySubjectRowReducer implements RowReducer<NewVulnerableDependencySubject.Builder, NewVulnerableDependencySubject> {

    @Override
    public NewVulnerableDependencySubject.Builder container() {
        return NewVulnerableDependencySubject.newBuilder();
    }

    @Override
    public void accumulate(final NewVulnerableDependencySubject.Builder container, final RowView rowView) {
        if (!container.hasComponent()) {
            container.setComponent(rowView.getRow(Component.class));
        }
        if (!container.hasProject()) {
            container.setProject(rowView.getRow(Project.class));
        }
        container.addVulnerabilities(rowView.getRow(Vulnerability.class));
    }

    @Override
    public Stream<NewVulnerableDependencySubject> stream(final NewVulnerableDependencySubject.Builder container) {
        return Stream.of(container.build());
    }

}

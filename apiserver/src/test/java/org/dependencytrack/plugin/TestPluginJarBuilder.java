/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.plugin;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

public class TestPluginJarBuilder {

    static Path buildTestPluginJar(final Path outputDir, final String className, final String sourceCode) throws IOException {
        Files.createDirectories(outputDir);
        Path srcFile = outputDir.resolve(className + ".java");
        Files.writeString(srcFile, sourceCode);

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("No system Java compiler found.");
        }

        String classpath = System.getProperty("java.class.path");

        int result = compiler.run(
                null, null, null,
                "-classpath", classpath,
                srcFile.toString()
        );

        if (result != 0) {
            throw new IllegalStateException("Compilation failed for " + className);
        }

        Path classFile = outputDir.resolve(className + ".class");
        Path jarFile = outputDir.resolve(className + ".jar");

        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(jarFile))) {
            jar.putNextEntry(new JarEntry(className + ".class"));
            Files.copy(classFile, jar);
            jar.closeEntry();

            jar.putNextEntry(new JarEntry("META-INF/services/org.dependencytrack.plugin.api.Plugin"));
            jar.write(("org.dependencytrack.plugin." + className).getBytes());
            jar.closeEntry();
        }

        return jarFile;
    }
}

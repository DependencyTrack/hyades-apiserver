/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server;

import alpine.config.AlpineConfigKeys;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import org.eclipse.microprofile.config.ConfigProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.owasp.security.logging.util.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The AlpineServlet is the main servlet which extends
 * the Jersey ServletContainer. It is responsible for setting up
 * the runtime environment by initializing the application.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class AlpineServlet extends ServletContainer {

    private static final long serialVersionUID = -133386507668410112L;
    private static final Logger LOGGER = LoggerFactory.getLogger(AlpineServlet.class);

    public AlpineServlet() {
    }

    public AlpineServlet(ResourceConfig resourceConfig) {
        super(resourceConfig);
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        final String appName = ConfigProvider.getConfig().getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_NAME, String.class);
        LOGGER.info("Starting {}", appName);
        super.init(config);

        SecurityUtil.logJavaSystemProperties();

        LOGGER.info("{} is ready", appName);
    }

    @Override
    public void destroy() {
        LOGGER.info("Stopping {}", ConfigProvider.getConfig().getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_NAME, String.class));
        super.destroy();
    }

}

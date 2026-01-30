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
package org.dependencytrack.common;

import alpine.Config;
import alpine.common.util.SystemUtil;
import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

@ExtendWith(SystemStubsExtension.class)
public class ManagedHttpClientFactoryTest {

    @SystemStub
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @BeforeAll
    public static void beforeClass() {
        Config.enableUnitTests();
    }

    @BeforeEach
    public void before() {
        environmentVariables.set("http_proxy", "http://acme%5Cusername:password@127.0.0.1:1080");
        environmentVariables.set("no_proxy", "localhost:443,127.0.0.1:8080,example.com,www.example.net");
    }

    @Test
    public void instanceTest() {
        HttpClient c1 = ManagedHttpClientFactory.newManagedHttpClient().getHttpClient();
        HttpClient c2 = ManagedHttpClientFactory.newManagedHttpClient().getHttpClient();
        Assertions.assertNotSame(c1, c2);
        Assertions.assertTrue(c1 instanceof CloseableHttpClient);
    }

    @Test
    public void proxyInfoTest() {
        ManagedHttpClientFactory.ProxyInfo proxyInfo = ManagedHttpClientFactory.createProxyInfo();
        Assertions.assertEquals("127.0.0.1", proxyInfo.getHost());
        Assertions.assertEquals(1080, proxyInfo.getPort());
        Assertions.assertEquals("acme", proxyInfo.getDomain());
        Assertions.assertEquals("username", proxyInfo.getUsername());
        Assertions.assertEquals("password", proxyInfo.getPassword());
        Assertions.assertArrayEquals(new String[]{"localhost:443", "127.0.0.1:8080", "example.com", "www.example.net"}, proxyInfo.getNoProxy());
    }

    @Test
    public void isProxyTest() {
        ManagedHttpClientFactory.ProxyInfo proxyInfo = ManagedHttpClientFactory.createProxyInfo();
        Assertions.assertFalse(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("example.com",443)));
        Assertions.assertFalse(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("example.com",8080)));
        Assertions.assertFalse(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("www.example.com",443)));
        Assertions.assertFalse(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("foo.example.com",80)));
        Assertions.assertTrue(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("fooexample.com",80)));
        Assertions.assertFalse(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("foo.bar.example.com",8000)));
        Assertions.assertFalse(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("www.example.net",80)));
        Assertions.assertTrue(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("foo.example.net",80)));
        Assertions.assertTrue(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("example.org",443)));
        Assertions.assertFalse(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("127.0.0.1",8080)));
        Assertions.assertTrue(ManagedHttpClientFactory.isProxy(proxyInfo.getNoProxy(), new HttpHost("127.0.0.1",8000)));
    }

    @Test
    public void userAgentTest() {
        String expected = Config.getInstance().getApplicationName()
                + " v" + Config.getInstance().getApplicationVersion()
                + " ("
                + SystemUtil.getOsArchitecture() + "; "
                + SystemUtil.getOsName() + "; "
                + SystemUtil.getOsVersion()
                + ") ManagedHttpClient/";
        Assertions.assertTrue(ManagedHttpClientFactory.getUserAgent().startsWith(expected));
    }
}

/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.custom.usergroupcallback;

import java.util.Properties;

import javax.naming.Context;

import com.custom.usergroupcallback.CustomLdapSearcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

abstract class AbstractCustomLDAPUserGroupInfo extends AbstractCustomUserGroupInfo {

    private static final Logger logger = LoggerFactory.getLogger(AbstractCustomLDAPUserGroupInfo.class);

    public static final String BIND_USER = "ldap.bind.user";
    public static final String BIND_PWD = "ldap.bind.pwd";

    protected static final String DEFAULT_ROLE_ATTR_ID = "cn";
    protected static final String DEFAULT_USER_ATTR_ID = "uid";

    private Properties config;

    protected CustomLdapSearcher ldapSearcher;

    protected AbstractCustomLDAPUserGroupInfo(String[] requiredProperties, String defaultPropertiesName) {
        String propertiesLocation = System.getProperty(defaultPropertiesName);
        String defaultPropertiesLocation = "classpath:/" + defaultPropertiesName + ".properties";
        Properties config = readProperties(propertiesLocation, defaultPropertiesLocation);

        initialize(requiredProperties, config);
    }

    protected AbstractCustomLDAPUserGroupInfo(String[] requiredProperties, Properties config) {
        initialize(requiredProperties, config);
    }

    private void initialize(String[] requiredProperties, Properties config) {
        this.config = config;

        validateProperties(requiredProperties);
        copyConfigProperty(BIND_USER, Context.SECURITY_PRINCIPAL);
        copyConfigProperty(BIND_PWD, Context.SECURITY_CREDENTIALS);

        ldapSearcher = new CustomLdapSearcher(this.config);
    }

    private void copyConfigProperty(String sourceKey, String targetKey) {
        String value = config.getProperty(sourceKey);
        if (value != null) {
            config.setProperty(targetKey, value);
        }
    }

    private void validateProperties(String[] requiredProperties) {
        if (config == null) {
            throw new IllegalArgumentException("No configuration found for " + getClass().getSimpleName()
                    + ", aborting...");
        }

        StringBuffer missingProperties = new StringBuffer();
        for (String requiredProperty : requiredProperties) {
            if (!config.containsKey(requiredProperty)) {
                if (missingProperties.length() > 0) {
                    missingProperties.append(", ");
                }
                missingProperties.append(requiredProperty);
            }
        }

        if (missingProperties.length() > 0) {
            logger.debug("Validation failed due to missing required properties: {}", missingProperties.toString());

            throw new IllegalArgumentException("Missing required properties to configure " + getClass().getSimpleName()
                    + ": " + missingProperties.toString());
        }
    }

    public String getConfigProperty(String key) {
        return config.getProperty(key);
    }

    public String getConfigProperty(String key, String defaultValue) {
        return config.getProperty(key, defaultValue);
    }

}

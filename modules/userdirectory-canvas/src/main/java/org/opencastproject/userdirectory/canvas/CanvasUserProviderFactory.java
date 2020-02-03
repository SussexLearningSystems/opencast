/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.userdirectory.canvas;

import org.opencastproject.security.api.*;
import org.opencastproject.util.NotFoundException;

import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedServiceFactory;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

/**
 * Canvas implementation of the spring UserDetailsService, taking configuration information from the component context.
 */
public class CanvasUserProviderFactory implements ManagedServiceFactory {

  /** The logger */
  protected static final Logger logger = LoggerFactory.getLogger(CanvasUserProviderFactory.class);

  /** This service factory's PID */
  public static final String PID = "org.opencastproject.userdirectory.canvas";

  /** The key to look up the organization identifer in the service configuration properties */
  private static final String ORGANIZATION_KEY = "org.opencastproject.userdirectory.canvas.org";

  /** The key to look up the user DN to use for performing searches. */
  private static final String CANVAS_TOKEN_KEY = "org.opencastproject.userdirectory.canvas.token";

  /** The property of a Canvas course to use for ACL Instructor/Learner roles */
  private static final String COURSE_IDENTIFIER_PROPERTY_KEY = "org.opencastproject.userdirectory.canvas.course.identifier.property";

  /** The key to look up the regular expression used to validate courses */
  private static final String COURSE_PATTERN_KEY = "org.opencastproject.userdirectory.canvas.course.pattern";

  /** The key to look up the regular expression used to validate users */
  private static final String USER_PATTERN_KEY = "org.opencastproject.userdirectory.canvas.user.pattern";

  /** The property in a Canvas user's profile to use as their display name */
  private static final String USER_NAME_PROPERTY_KEY = "org.opencastproject.userdirectory.canvas.user.name.property";

  /** The key to look up the number of user records to cache */
  private static final String CACHE_SIZE = "org.opencastproject.userdirectory.canvas.cache.size";

  /** The key to look up the URL of the Canvas instance */
  private static final String CANVAS_URL_KEY = "org.opencastproject.userdirectory.canvas.url";

  /** The key to look up the list of Instructor roles on the Canvas instance */
  private static final String CANVAS_INSTRUCTOR_ROLES_KEY = "org.opencastproject.userdirectory.canvas.instructor.roles";

  /** The key to look up the number of minutes to cache users */
  private static final String CACHE_EXPIRATION = "org.opencastproject.userdirectory.canvas.cache.expiration";

  /** A map of pid to canvas user provider instance */
  private Map<String, ServiceRegistration> providerRegistrations = new ConcurrentHashMap<String, ServiceRegistration>();
  ;

  /** The OSGI bundle context */
  protected BundleContext bundleContext = null;

  /** The organization directory service */
  private OrganizationDirectoryService orgDirectory;

  /** OSGi callback for setting the organization directory service. */
  public void setOrgDirectory(OrganizationDirectoryService orgDirectory) {
    this.orgDirectory = orgDirectory;
  }

  /**
   * Callback for the activation of this component
   *
   * @param cc
   *          the component context
   */
  public void activate(ComponentContext cc) {
    logger.debug("Activate CanvasUserProviderFactory");
    this.bundleContext = cc.getBundleContext();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#getName()
   */
  @Override
  public String getName() {
    return PID;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#updated(java.lang.String, java.util.Dictionary)
   */
  @Override
  public void updated(String pid, Dictionary properties) throws ConfigurationException {

    logger.debug("updated CanvasUserProviderFactory");

    String organization = (String) properties.get(ORGANIZATION_KEY);
    if (StringUtils.isBlank(organization)) throw new ConfigurationException(ORGANIZATION_KEY, "is not set");

    String url = (String) properties.get(CANVAS_URL_KEY);
    if (StringUtils.isBlank(url)) throw new ConfigurationException(CANVAS_URL_KEY, "is not set");

    String token = (String) properties.get(CANVAS_TOKEN_KEY);
    if (StringUtils.isBlank(token)) throw new ConfigurationException(CANVAS_TOKEN_KEY, "is not set");

    String courseIdentifierProperty = (String) properties.get(COURSE_IDENTIFIER_PROPERTY_KEY);
    if (!"id".equals(courseIdentifierProperty) && !"sis_course_id".equals(courseIdentifierProperty))
      throw new ConfigurationException(COURSE_IDENTIFIER_PROPERTY_KEY,
          "is invalid.  Must be either `id` or `sis_course_id`");

    String coursePattern = (String) properties.get(COURSE_PATTERN_KEY);
    if (StringUtils.isNotBlank(coursePattern)) {
      try {
        Pattern.compile(coursePattern);
      } catch (PatternSyntaxException e) {
        throw new ConfigurationException(COURSE_PATTERN_KEY, "has an invalid regex syntax");
      }
    }
    String userPattern = (String) properties.get(USER_PATTERN_KEY);
    if (StringUtils.isNotBlank(userPattern)) {
      try {
        Pattern.compile(userPattern);
      } catch (PatternSyntaxException e) {
        throw new ConfigurationException(USER_PATTERN_KEY, "has an invalid regex syntax");
      }
    }
    String userNameProperty = (String) properties.get(USER_NAME_PROPERTY_KEY);
    if (!"name".equals(userNameProperty) && !"short_name".equals(userNameProperty))
      throw new ConfigurationException(USER_NAME_PROPERTY_KEY,
          "is invalid.  Must use either `name` or `short_name`");

    int cacheSize;
    if (properties.get(CACHE_SIZE) == null) {
      throw new ConfigurationException(CACHE_SIZE, "is not set");
    } else {
      try {
        cacheSize = Integer.parseInt(properties.get(CACHE_SIZE).toString());

      } catch (NumberFormatException e) {
        throw new ConfigurationException(CACHE_SIZE, "is invalid , use a positive integer");
      }
    }

    int cacheExpiration;
    if (properties.get(CACHE_EXPIRATION) == null) {
      throw new ConfigurationException(CACHE_EXPIRATION, "is not set");
    } else {
      try {
        cacheExpiration = Integer.parseInt(properties.get(CACHE_EXPIRATION).toString());

      } catch (NumberFormatException e) {
        throw new ConfigurationException(CACHE_EXPIRATION, "is invalid , use a positive integer");
      }
    }

    Set<String> instructorRoles;
    String instructorRoleList = (String) properties.get(CANVAS_INSTRUCTOR_ROLES_KEY);

    if (StringUtils.isNotEmpty(instructorRoleList)) {
      String[] roles = StringUtils.split(instructorRoleList, " ,");
      instructorRoles = new HashSet<>(Arrays.asList(roles));
      logger.debug("Canvas instructor roles: {}", Arrays.toString(roles));
    } else {
      throw new ConfigurationException(CANVAS_INSTRUCTOR_ROLES_KEY, "is not set");
    }

    // Now that we have everything we need, go ahead and activate a new provider, removing an old one if necessary
    ServiceRegistration existingRegistration = providerRegistrations.remove(pid);
    if (existingRegistration != null) {
      existingRegistration.unregister();
    }

    Organization org;
    try {
      org = orgDirectory.getOrganization(organization);
    } catch (NotFoundException e) {
      logger.warn("Organization {} not found!", organization);
      throw new ConfigurationException(ORGANIZATION_KEY, "not found");
    }

    //Get Admin Username from OSGi contextBundle
    String adminUserName = StringUtils.trimToNull(bundleContext.getProperty(SecurityConstants.GLOBAL_ADMIN_USER_PROPERTY));

    logger.debug("Creating new CanvasUserProviderInstance for pid={}", pid);
    CanvasUserProviderInstance provider = new CanvasUserProviderInstance(pid, org, url, token, courseIdentifierProperty,
        coursePattern, userPattern, userNameProperty, instructorRoles, cacheSize, cacheExpiration, adminUserName);

    providerRegistrations.put(pid, bundleContext.registerService(UserProvider.class.getName(), provider, null));
    providerRegistrations.put(pid, bundleContext.registerService(RoleProvider.class.getName(), provider, null));
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#deleted(java.lang.String)
   */
  @Override
  public void deleted(String pid) {
    logger.debug("Delete CanvasUserProviderInstance for pid={}", pid);
    ServiceRegistration registration = providerRegistrations.remove(pid);
    if (registration != null) {
      registration.unregister();
      try {
        ManagementFactory.getPlatformMBeanServer().unregisterMBean(CanvasUserProviderFactory.getObjectName(pid));
      } catch (Exception e) {
        logger.warn("Unable to unregister mbean for pid='{}'", pid, e);
        e.printStackTrace();

      }

    }
  }

  /**
   * Builds a JMX object name for a given PID
   *
   * @param pid
   *          the PID
   * @return the object name
   * @throws NullPointerException
   * @throws MalformedObjectNameException
   */
  public static final ObjectName getObjectName(String pid) throws MalformedObjectNameException, NullPointerException {
    return new ObjectName(pid + ":type=CanvasRequests");
  }
}
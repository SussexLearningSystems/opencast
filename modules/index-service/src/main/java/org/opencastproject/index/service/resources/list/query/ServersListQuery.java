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

package org.opencastproject.index.service.resources.list.query;

import org.opencastproject.index.service.resources.list.api.ResourceListFilter;
import org.opencastproject.index.service.resources.list.api.ResourceListQuery;
import org.opencastproject.index.service.resources.list.provider.ServersListProvider;
import org.opencastproject.index.service.util.FiltersUtils;
import org.opencastproject.util.data.Option;

/**
 * Query for the servers list.
 *
 * The following filters can be used:
 * <ul>
 * <li>hostname</li>
 * <li>status</li>
 * </ul>
 */
public class ServersListQuery extends ResourceListQueryImpl {

  /** Prefix for the filter labels. */
  private static final String FILTER_LABEL_PREFIX = "FILTERS.SERVERS";
  /** Hostname filter name. */
  public static final String FILTER_NAME_HOSTNAME = "hostname";
  /** Hostname filter label. */
  public static final String FILTER_LABEL_HOSTNAME = FILTER_LABEL_PREFIX + ".HOSTNAME.LABEL";
  /** Status filter name. */
  public static final String FILTER_NAME_STATUS = "status";
  /** Status filter label. */
  public static final String FILTER_LABEL_STATUS = FILTER_LABEL_PREFIX + ".STATUS.LABEL";

  /** Default constructor. */
  public ServersListQuery() {
    super();
    availableFilters.add(createHostnameFilter(Option.<String> none()));
    availableFilters.add(createStatusFilter(Option.<String> none()));
  }

  /**
   * Copy constructor for the base class {@code ResourceListQuery}.
   *
   * @param query copy values from the given query
   */
  public ServersListQuery(ResourceListQuery query) {
    this();
    availableFilters.addAll(query.getAvailableFilters());

    for (ResourceListFilter filter : query.getFilters()) {
      addFilter(filter);
    }

    sortBy = query.getSortBy();
    if (query.getOffset().isSome()) {
      setOffset(query.getOffset().get());
    }
    if (query.getLimit().isSome()) {
      setLimit(query.getLimit().get());
    }
  }

  /**
   * Add a {@link ResourceListFilter} filter to the query with the given hostname.
   *
   * @param hostname the hostname to filter for
   */
  public void withHostname(String hostname) {
    addFilter(createHostnameFilter(Option.option(hostname)));
  }

  /**
   * Add a {@link ResourceListFilter} filter to the query with the given status.
   *
   * @param status the status to filter for
   */
  public void withStatus(String status) {
    addFilter(createStatusFilter(Option.option(status)));
  }

  /**
   * Add a {@link ResourceListFilter} filter to the query with the given free text.
   *
   * @param freeText the free text to filter for
   */
  public void withFreeText(String freeText) {
    addFilter(createFreeTextFilter(Option.option(freeText)));
  }

  /**
   * Returns an {@link Option} containing the hostname used to filter if set.
   * {@link Option#none()} otherwise.
   *
   * @return an {@link Option} containing the hostname or none.
   */
  public Option<String> getHostname() {
    return getFilterValue(FILTER_NAME_HOSTNAME);
  }

  /**
   * Returns an {@link Option} containing the status used to filter if set.
   * {@link Option#none()} otherwise.
   *
   * @return an {@link Option} containing the status or none.
   */
  public Option<String> getStatus() {
    return getFilterValue(FILTER_NAME_STATUS);
  }

  /**
   * Returns an {@link Option} containing the free text used to filter if set.
   * {@link Option#none()} otherwise.
   *
   * @return an {@link Option} containing the free text or none.
   */
  public Option<String> getFreeText() {
    return getFilterValue(ResourceListFilter.FREETEXT);
  }

  /**
   * Create a new {@link ResourceListFilter} based on a hostname.
   *
   * @param value the hostname to filter on wrapped in an {@link Option} or {@link Option#none()}
   * @return a new {@link ResourceListFilter} for a hostname based query
   */
  public static ResourceListFilter<String> createHostnameFilter(Option<String> value) {
    return FiltersUtils.generateFilter(
            value,
            FILTER_NAME_HOSTNAME,
            FILTER_LABEL_HOSTNAME,
            ResourceListFilter.SourceType.SELECT,
            Option.some(ServersListProvider.LIST_HOSTNAME));
  }

  /**
   * Create a new {@link ResourceListFilter} based on a status.
   *
   * @param value the status to filter on wrapped in an {@link Option} or {@link Option#none()}
   * @return a new {@link ResourceListFilter} for a status based query
   */
  public static ResourceListFilter<String> createStatusFilter(Option<String> value) {
    return FiltersUtils.generateFilter(
            value,
            FILTER_NAME_STATUS,
            FILTER_LABEL_STATUS,
            ResourceListFilter.SourceType.SELECT,
            Option.some(ServersListProvider.LIST_STATUS));
  }

  /**
   * Create a new {@link ResourceListFilter} based on a free text.
   *
   * @param value the free text to filter on wrapped in an {@link Option} or {@link Option#none()}
   * @return a new {@link ResourceListFilter} for a free text based query
   */
  public static <String> ResourceListFilter<String> createFreeTextFilter(Option<String> value) {
    return FiltersUtils.generateFilter(
            value,
            ResourceListFilter.FREETEXT,
            ResourceListFilter.FREETEXT,
            ResourceListFilter.SourceType.FREETEXT,
            null);
  }
}

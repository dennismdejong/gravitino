/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.gravitino.trino.connector.catalog.iceberg;

import com.google.common.collect.Sets;
import io.trino.spi.TrinoException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.apache.gravitino.catalog.lakehouse.iceberg.IcebergConstants;
import org.apache.gravitino.catalog.lakehouse.iceberg.IcebergPropertiesUtils;
import org.apache.gravitino.credential.AzureAccountKeyCredential;
import org.apache.gravitino.credential.Credential;
import org.apache.gravitino.credential.CredentialConstants;
import org.apache.gravitino.credential.JdbcCredential;
import org.apache.gravitino.credential.S3SecretKeyCredential;
import org.apache.gravitino.storage.S3Properties;
import org.apache.gravitino.trino.connector.GravitinoConfig;
import org.apache.gravitino.trino.connector.GravitinoErrorCode;
import org.apache.gravitino.trino.connector.catalog.CatalogPropertyConverter;
import org.apache.gravitino.trino.connector.metadata.GravitinoCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A property converter for Iceberg catalogs that handles the conversion between Trino and Gravitino
 * property formats. This converter manages various Iceberg-specific configurations including
 * general settings, Hive integration, and S3 storage options.
 */
public class IcebergCatalogPropertyConverter extends CatalogPropertyConverter {

  private static final Logger LOG = LoggerFactory.getLogger(IcebergCatalogPropertyConverter.class);

  private static final Set<String> JDBC_BACKEND_REQUIRED_PROPERTIES = Set.of("jdbc-driver", "uri");

  private static final Set<String> HIVE_BACKEND_REQUIRED_PROPERTIES = Set.of("uri");

  private static final Set<String> REST_BACKEND_REQUIRED_PROPERTIES = Set.of("uri");

  private static final String TRINO_ICEBERG_CATALOG_TYPE = "iceberg.catalog.type";
  private static final String TRINO_ICEBERG_CATALOG_TYPE_REST = "rest";
  private static final String TRINO_ICEBERG_REST_URI = "iceberg.rest-catalog.uri";
  private static final String TRINO_ICEBERG_REST_PREFIX = "iceberg.rest-catalog.prefix";
  private static final String TRINO_ICEBERG_REST_WAREHOUSE = "iceberg.rest-catalog.warehouse";
  private static final String TRINO_ICEBERG_REST_VENDED_CREDENTIALS =
      "iceberg.rest-catalog.vended-credentials-enabled";
  private static final String TRINO_ICEBERG_REST_SESSION = "iceberg.rest-catalog.session";
  private static final String TRINO_ICEBERG_REST_SECURITY = "iceberg.rest-catalog.security";
  private static final String TRINO_ICEBERG_REST_SECURITY_OAUTH2 = "OAUTH2";
  private static final String TRINO_ICEBERG_REST_SESSION_USER = "USER";
  private static final String TRINO_FS_HADOOP_ENABLED = "fs.hadoop.enabled";
  private static final String TRINO_FS_NATIVE_S3_ENABLED = "fs.native-s3.enabled";
  private static final String TRINO_FS_NATIVE_GCS_ENABLED = "fs.native-gcs.enabled";
  private static final String TRINO_FS_NATIVE_AZURE_ENABLED = "fs.native-azure.enabled";
  // Trino's Iceberg connector reads and writes table data through its native file systems. The
  // native S3 file system binds S3FileSystemConfig without a catalog prefix, so its keys are the
  // unprefixed `s3.*` names. The `hive.s3.*` names belong to the legacy Hive file system and are
  // reported as unused catalog properties by the Iceberg connector.
  private static final String TRINO_S3_ACCESS_KEY = "s3.aws-access-key";
  private static final String TRINO_S3_SECRET_KEY = "s3.aws-secret-key";
  private static final String TRINO_S3_REGION = "s3.region";
  private static final String TRINO_S3_ENDPOINT = "s3.endpoint";
  private static final String TRINO_S3_PATH_STYLE_ACCESS = "s3.path-style-access";

  /**
   * Gravitino catalog data-access mode that asks the Iceberg REST catalog for storage credentials.
   */
  private static final String DATA_ACCESS_VENDED_CREDENTIALS = "vended-credentials";

  /** Routing keys the connector always derives itself; they cannot be overridden. */
  private static final List<String> RESERVED_REST_PROPERTIES =
      List.of(
          TRINO_ICEBERG_CATALOG_TYPE,
          TRINO_ICEBERG_REST_URI,
          TRINO_ICEBERG_REST_WAREHOUSE,
          TRINO_ICEBERG_REST_PREFIX);

  /**
   * Injects credentials from credential vending into the Iceberg catalog config. Applies JDBC
   * user/password for the JDBC backend and S3 credentials for S3-backed storage.
   *
   * <p>S3 credentials are written under Trino's native S3 file system keys ({@code s3.*}). The
   * legacy {@code hive.s3.*} keys are not consumed by the Iceberg connector, so Trino reports them
   * as unused and the S3 client stays unauthenticated. The native file system has to be enabled in
   * the same step; otherwise Trino also ignores the {@code s3.*} properties.
   *
   * <p>The S3 key is injected even when the REST catalog vends per-table credentials. Vending
   * governs the data plane; the static key is the credential of the REST catalog's control plane,
   * which Trino signs with it ({@code iceberg.rest-catalog.security=SIGV4}) when the catalog talks
   * to the storage endpoint directly. Leaving it out makes Trino's {@code SigV4AwsProperties} fail
   * to initialize and takes the whole connector down.
   *
   * @param credentials the credentials returned by the server
   * @param config the mutable Trino Iceberg connector config map to update
   * @param catalogProperties the Gravitino catalog properties, used to derive the S3 endpoint,
   *     region and path-style access that accompany the credentials
   */
  public static void applyCredentials(
      Credential[] credentials, Map<String, String> config, Map<String, String> catalogProperties) {
    for (Credential credential : credentials) {
      if (credential instanceof JdbcCredential) {
        JdbcCredential jdbc = (JdbcCredential) credential;
        config.put("iceberg.jdbc-catalog.connection-user", jdbc.jdbcUser());
        config.put("iceberg.jdbc-catalog.connection-password", jdbc.jdbcPassword());
      } else if (credential instanceof S3SecretKeyCredential) {
        S3SecretKeyCredential s3 = (S3SecretKeyCredential) credential;
        config.put(TRINO_S3_ACCESS_KEY, s3.accessKeyId());
        config.put(TRINO_S3_SECRET_KEY, s3.secretAccessKey());
        applyS3StorageProperties(catalogProperties, config);
      } else if (credential instanceof AzureAccountKeyCredential) {
        AzureAccountKeyCredential azure = (AzureAccountKeyCredential) credential;
        config.put(
            String.format("fs.azure.account.key.%s.dfs.core.windows.net", azure.accountName()),
            azure.accountKey());
      }
    }
  }

  /**
   * Adds the native S3 file system settings that have to accompany an S3 credential. Trino only
   * consumes {@code s3.*} properties when the native S3 file system is enabled, and an
   * S3-compatible endpoint also needs its region and path-style setting here.
   */
  private static void applyS3StorageProperties(
      Map<String, String> properties, Map<String, String> config) {
    config.put(TRINO_FS_NATIVE_S3_ENABLED, "true");
    copyProperty(properties, S3Properties.GRAVITINO_S3_REGION, config, TRINO_S3_REGION);
    copyProperty(properties, S3Properties.GRAVITINO_S3_ENDPOINT, config, TRINO_S3_ENDPOINT);
    copyProperty(
        properties,
        S3Properties.GRAVITINO_S3_PATH_STYLE_ACCESS,
        config,
        TRINO_S3_PATH_STYLE_ACCESS);
  }

  @Override
  public Map<String, String> gravitinoToEngineProperties(Map<String, String> properties) {
    Map<String, String> stringStringMap;
    String backend = properties.get("catalog-backend");
    if (backend == null)
      throw new TrinoException(
          GravitinoErrorCode.GRAVITINO_MISSING_REQUIRED_PROPERTY,
          "Missing required property 'catalog-backend'");
    // Gravitino accepts the backend as an enum value, and its own consumers upper-case it before
    // resolving, so the value reaching here may be in any case.
    switch (backend.toLowerCase(Locale.ROOT)) {
      case "hive":
        stringStringMap = buildHiveBackendProperties(properties);
        break;
      case "jdbc":
        stringStringMap = buildJDBCBackendProperties(properties);
        break;
      case "rest":
        stringStringMap = buildRestBackendProperties(properties);
        break;
      default:
        throw new UnsupportedOperationException("Unsupported backend type: " + backend);
    }
    Map<String, String> config = new HashMap<>();
    // Later put/putAll calls override earlier ones for the same key; this is call-order
    // precedence, unrelated to HashMap's (unspecified) iteration order.
    config.putAll(super.gravitinoToEngineProperties(properties));
    config.putAll(stringStringMap);
    config.put("fs.hadoop.enabled", "true");
    return config;
  }

  /**
   * Builds the Trino Iceberg connector config that reaches this catalog through the Gravitino
   * Iceberg REST server, regardless of the catalog backend Gravitino uses to store its metadata.
   *
   * <p>This is the only path on which <em>temporary</em> credentials work — {@code s3-token} and
   * its GCS and ADLS counterparts. The Iceberg REST protocol issues a fresh one per table access,
   * while Trino's jdbc and hive_metastore Iceberg catalog types have nowhere to put the session
   * token of an STS credential. Static-key credentials are unaffected: they are still injected on
   * the backend path by {@link #applyCredentials}.
   *
   * @param catalog the Gravitino catalog to load
   * @param gravitinoConfig the connector configuration holding the Iceberg REST catalog's
   *     authentication and other pass-through settings
   * @param restUri the Iceberg REST server endpoint to route through, resolved by the caller
   * @return the Trino Iceberg connector config
   * @throws TrinoException if {@code restUri} is blank
   */
  public Map<String, String> buildIcebergRestProperties(
      GravitinoCatalog catalog, GravitinoConfig gravitinoConfig, String restUri) {
    if (StringUtils.isBlank(restUri)) {
      // The caller only reaches this method once it has already confirmed a non-blank URI, so
      // this is defensive: it can only fire if that URI disappeared between the two calls.
      throw new TrinoException(
          GravitinoErrorCode.GRAVITINO_MISSING_CONFIG,
          "No Iceberg REST server endpoint is available for metalake '"
              + catalog.getMetalake()
              + "'. Set 'gravitino.iceberg.rest-uri' to override the address the Gravitino "
              + "server reports.");
    }

    Map<String, String> config = new HashMap<>();
    // Later put/putAll calls override earlier ones for the same key; this is call-order
    // precedence, unrelated to HashMap's (unspecified) iteration order.
    Map<String, String> storageProperties = buildStorageProperties(catalog.getProperties());
    // A REST catalog's `warehouse` can be a logical catalog name rather than a storage location, so
    // the catalog's S3 settings are the only signal that its tables live on S3. Without the native
    // S3 file system Trino cannot apply the vended credentials to a table location.
    if (isVendedCredentialsRequested(catalog.getProperties())
        && isS3Storage(catalog.getProperties())
        && !Boolean.parseBoolean(storageProperties.get(TRINO_FS_NATIVE_S3_ENABLED))) {
      applyS3StorageProperties(catalog.getProperties(), storageProperties);
    }
    config.putAll(storageProperties);
    // Trino 482 dropped the fallback to the Hadoop file system when no vended credential is
    // actually present for a table (older versions used it whenever none of the per-scheme
    // credential providers applied, e.g. for HDFS); it now always routes through the REST-only
    // file system, which rejects any scheme without a native Trino file system. Only default this
    // on for warehouse schemes that have one.
    boolean vendedCredentialsSupported =
        Boolean.parseBoolean(storageProperties.get(TRINO_FS_NATIVE_S3_ENABLED))
            || Boolean.parseBoolean(storageProperties.get(TRINO_FS_NATIVE_GCS_ENABLED))
            || Boolean.parseBoolean(storageProperties.get(TRINO_FS_NATIVE_AZURE_ENABLED));
    config.put(TRINO_ICEBERG_REST_VENDED_CREDENTIALS, String.valueOf(vendedCredentialsSupported));
    // The catalog's own trino.bypass properties override the defaults above, so that a Trino
    // release renaming one of them can be worked around without a connector change.
    config.putAll(super.gravitinoToEngineProperties(catalog.getProperties()));
    // The IRC's own authentication is a cluster-level operational setting, so it takes precedence
    // over anything set on a single catalog.
    config.putAll(gravitinoConfig.getIcebergRestCatalogConfig());
    // Runs after the two putAll calls above, because it depends on both the security mode and
    // any explicit session value they settle.
    applyForwardUserSession(gravitinoConfig, config);

    warnOnReservedOverrides(catalog, config);

    config.put(TRINO_ICEBERG_CATALOG_TYPE, TRINO_ICEBERG_CATALOG_TYPE_REST);
    config.put(TRINO_ICEBERG_REST_URI, restUri);
    // The Iceberg client selects the catalog twice over: `warehouse` is the query parameter of the
    // initial GET /v1/config that discovers the catalog, and `prefix` is the path segment of every
    // request after it. Setting only the latter leaves the config call without a catalog name.
    // The server echoes `prefix` back as a config default, so setting it here is belt-and-braces.
    config.put(TRINO_ICEBERG_REST_WAREHOUSE, catalog.getName());
    config.put(TRINO_ICEBERG_REST_PREFIX, catalog.getName());
    return config;
  }

  private Map<String, String> buildHiveBackendProperties(Map<String, String> properties) {
    Set<String> missingProperty =
        Sets.difference(HIVE_BACKEND_REQUIRED_PROPERTIES, properties.keySet());
    if (!missingProperty.isEmpty()) {
      throw new TrinoException(
          GravitinoErrorCode.GRAVITINO_MISSING_REQUIRED_PROPERTY,
          "Missing required property for Hive backend: " + missingProperty);
    }

    Map<String, String> hiveProperties = new HashMap<>();
    hiveProperties.put("iceberg.catalog.type", "hive_metastore");
    hiveProperties.put("hive.metastore.uri", properties.get("uri"));
    return hiveProperties;
  }

  private Map<String, String> buildJDBCBackendProperties(Map<String, String> properties) {
    Set<String> missingProperty =
        Sets.difference(JDBC_BACKEND_REQUIRED_PROPERTIES, properties.keySet());
    if (!missingProperty.isEmpty()) {
      throw new TrinoException(
          GravitinoErrorCode.GRAVITINO_MISSING_REQUIRED_PROPERTY,
          "Missing required property for JDBC backend: " + missingProperty);
    }

    Map<String, String> jdbcProperties = new HashMap<>();
    jdbcProperties.put("iceberg.catalog.type", "jdbc");
    jdbcProperties.put(
        "iceberg.jdbc-catalog.driver-class",
        properties.get(IcebergConstants.GRAVITINO_JDBC_DRIVER));
    jdbcProperties.put("iceberg.jdbc-catalog.connection-url", properties.get(IcebergConstants.URI));
    jdbcProperties.put(
        "iceberg.jdbc-catalog.connection-user",
        properties.get(IcebergConstants.GRAVITINO_JDBC_USER));
    jdbcProperties.put(
        "iceberg.jdbc-catalog.connection-password",
        properties.get(IcebergConstants.GRAVITINO_JDBC_PASSWORD));
    jdbcProperties.put(
        "iceberg.jdbc-catalog.default-warehouse-dir", properties.get(IcebergConstants.WAREHOUSE));

    jdbcProperties.put(
        "iceberg.jdbc-catalog.catalog-name",
        IcebergPropertiesUtils.getCatalogBackendName(properties));
    if (properties.containsKey(IcebergConstants.GRAVITINO_JDBC_SCHEMA_VERSION)) {
      jdbcProperties.put(
          "iceberg.jdbc-catalog.schema-version",
          properties.get(IcebergConstants.GRAVITINO_JDBC_SCHEMA_VERSION));
    }

    return jdbcProperties;
  }

  /**
   * Turns on Trino's per-user Iceberg REST sessions when user forwarding is enabled and the REST
   * catalog authenticates with OAuth2. In that session mode Trino signs a subject JWT for the
   * session user and attaches it to every request; the Iceberg client consumes such a token through
   * an OAuth2 token exchange. Under any other security mode there is no token endpoint to exchange
   * it at, so the token carries no user identity and the mode buys nothing.
   *
   * <p>An explicit {@code iceberg.rest-catalog.session} coming from the catalog or the connector
   * config is left untouched.
   */
  private void applyForwardUserSession(
      GravitinoConfig gravitinoConfig, Map<String, String> config) {
    if (!gravitinoConfig.isForwardUser() || config.containsKey(TRINO_ICEBERG_REST_SESSION)) {
      return;
    }
    if (TRINO_ICEBERG_REST_SECURITY_OAUTH2.equalsIgnoreCase(
        config.get(TRINO_ICEBERG_REST_SECURITY))) {
      config.put(TRINO_ICEBERG_REST_SESSION, TRINO_ICEBERG_REST_SESSION_USER);
    }
  }

  // Called before the reserved keys (type/uri/warehouse/prefix) are put into `config` below, so
  // any value already present at this point came from the catalog's own properties or bypass
  // config and is about to be silently overwritten; this logs that so it isn't a silent no-op.
  private void warnOnReservedOverrides(GravitinoCatalog catalog, Map<String, String> config) {
    for (String reserved : RESERVED_REST_PROPERTIES) {
      if (config.containsKey(reserved)) {
        LOG.info(
            "Property '{}' set on catalog '{}' is ignored; the connector always derives it when "
                + "routing through the Iceberg REST server.",
            reserved,
            catalog.getName());
      }
    }
  }

  /**
   * Derives the Trino file system config from the catalog's warehouse location. Vended credentials
   * are only consumed by Trino's native file systems, so the native implementation matching the
   * warehouse scheme has to be enabled.
   */
  private Map<String, String> buildStorageProperties(Map<String, String> properties) {
    Map<String, String> storageProperties = new HashMap<>();
    // Always available as the fallback; where a native file system is also enabled below, that one
    // takes precedence for its own scheme.
    storageProperties.put(TRINO_FS_HADOOP_ENABLED, "true");

    String warehouse = properties.get(IcebergConstants.WAREHOUSE);
    if (StringUtils.isBlank(warehouse)) {
      return storageProperties;
    }

    String scheme = StringUtils.substringBefore(warehouse, "://").toLowerCase(Locale.ROOT);
    switch (scheme) {
      case "s3":
      case "s3a":
      case "s3n":
        storageProperties.put(TRINO_FS_NATIVE_S3_ENABLED, "true");
        copyProperty(
            properties, S3Properties.GRAVITINO_S3_REGION, storageProperties, TRINO_S3_REGION);
        copyProperty(
            properties, S3Properties.GRAVITINO_S3_ENDPOINT, storageProperties, TRINO_S3_ENDPOINT);
        // Required by S3-compatible stores such as MinIO and Ceph, which a custom endpoint implies.
        copyProperty(
            properties,
            S3Properties.GRAVITINO_S3_PATH_STYLE_ACCESS,
            storageProperties,
            TRINO_S3_PATH_STYLE_ACCESS);
        break;
      case "gs":
        storageProperties.put(TRINO_FS_NATIVE_GCS_ENABLED, "true");
        break;
      case "abfs":
      case "abfss":
      case "wasb":
      case "wasbs":
        storageProperties.put(TRINO_FS_NATIVE_AZURE_ENABLED, "true");
        break;
      default:
        warnOnSchemeWithoutNativeFileSystem(properties, warehouse, scheme);
        break;
    }
    return storageProperties;
  }

  /**
   * Warns when a warehouse scheme has no Trino native file system but the catalog vends
   * credentials. The Hadoop file system cannot consume a vended credential, so table access would
   * fail at read time with a storage authentication error far from its cause.
   */
  private void warnOnSchemeWithoutNativeFileSystem(
      Map<String, String> properties, String warehouse, String scheme) {
    // hdfs and file legitimately run on the Hadoop file system, and a warehouse without a scheme
    // is a plain path. None of them vend credentials.
    if (!warehouse.contains("://") || "hdfs".equals(scheme) || "file".equals(scheme)) {
      return;
    }
    if (StringUtils.isBlank(properties.get(CredentialConstants.CREDENTIAL_PROVIDERS))) {
      return;
    }
    LOG.warn(
        "Warehouse scheme '{}' has no Trino native file system, so the credentials vended by "
            + "'{}' cannot be applied. Table access falls back to the Hadoop file system and may "
            + "fail to authenticate. Schemes with a native file system: s3/s3a/s3n, gs, "
            + "abfs/abfss/wasb/wasbs.",
        scheme,
        properties.get(CredentialConstants.CREDENTIAL_PROVIDERS));
  }

  private static void copyProperty(
      Map<String, String> source, String sourceKey, Map<String, String> target, String targetKey) {
    String value = source.get(sourceKey);
    if (StringUtils.isNotBlank(value)) {
      target.put(targetKey, value);
    }
  }

  private Map<String, String> buildRestBackendProperties(Map<String, String> properties) {
    Set<String> missingProperty =
        Sets.difference(REST_BACKEND_REQUIRED_PROPERTIES, properties.keySet());
    if (!missingProperty.isEmpty()) {
      throw new TrinoException(
          GravitinoErrorCode.GRAVITINO_MISSING_REQUIRED_PROPERTY,
          "Missing required property for Rest backend: " + missingProperty);
    }

    Map<String, String> restProperties = new HashMap<>();
    restProperties.put(TRINO_ICEBERG_CATALOG_TYPE, TRINO_ICEBERG_CATALOG_TYPE_REST);
    restProperties.put(TRINO_ICEBERG_REST_URI, properties.get(IcebergConstants.URI));
    if (properties.containsKey(IcebergConstants.WAREHOUSE)) {
      restProperties.put(
          "iceberg.rest-catalog.warehouse", properties.get(IcebergConstants.WAREHOUSE));
    }
    // A REST catalog that opts into vended credentials returns prefix-scoped, temporary storage
    // credentials in its LoadTable response. Trino only asks for them when this flag is on; a
    // native file system must be enabled as well, otherwise Trino has no implementation that can
    // consume the credentials for the table's storage scheme.
    if (isVendedCredentialsRequested(properties)) {
      Map<String, String> storageProperties = buildStorageProperties(properties);
      boolean nativeFileSystem =
          Boolean.parseBoolean(storageProperties.get(TRINO_FS_NATIVE_S3_ENABLED))
              || Boolean.parseBoolean(storageProperties.get(TRINO_FS_NATIVE_GCS_ENABLED))
              || Boolean.parseBoolean(storageProperties.get(TRINO_FS_NATIVE_AZURE_ENABLED));
      if (!nativeFileSystem && isS3Storage(properties)) {
        applyS3StorageProperties(properties, storageProperties);
        nativeFileSystem = true;
      }
      restProperties.putAll(storageProperties);
      restProperties.put(TRINO_ICEBERG_REST_VENDED_CREDENTIALS, String.valueOf(nativeFileSystem));
    }
    return restProperties;
  }

  /**
   * Returns whether the catalog asks the Iceberg REST catalog to vend per-table storage
   * credentials, which Trino enables through {@code
   * iceberg.rest-catalog.vended-credentials-enabled} and then consumes from each {@code LoadTable}
   * response.
   */
  private static boolean isVendedCredentialsRequested(Map<String, String> properties) {
    return DATA_ACCESS_VENDED_CREDENTIALS.equalsIgnoreCase(
        properties.get(IcebergConstants.DATA_ACCESS));
  }

  /** Returns whether the catalog configures S3-backed storage. */
  private static boolean isS3Storage(Map<String, String> properties) {
    String warehouse = properties.get(IcebergConstants.WAREHOUSE);
    if (StringUtils.isNotBlank(warehouse)) {
      String scheme = StringUtils.substringBefore(warehouse, "://").toLowerCase(Locale.ROOT);
      if ("s3".equals(scheme) || "s3a".equals(scheme) || "s3n".equals(scheme)) {
        return true;
      }
    }
    String ioImpl = properties.get(IcebergConstants.IO_IMPL);
    if (ioImpl != null
        && StringUtils.containsIgnoreCase(ioImpl, "org.apache.iceberg.aws.s3.S3FileIO")) {
      return true;
    }
    return properties.containsKey(S3Properties.GRAVITINO_S3_ENDPOINT)
        || properties.containsKey(S3Properties.GRAVITINO_S3_REGION)
        || properties.containsKey(S3Properties.GRAVITINO_S3_PATH_STYLE_ACCESS);
  }
}

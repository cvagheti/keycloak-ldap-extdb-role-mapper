package org.toad.keycloak.storage.ldap.mappers;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.dbcp.BasicDataSource;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;

public class DbGroup2RoleLDAPStorageMapperConfig {

	private static final Logger logger = Logger.getLogger(DbGroup2RoleLDAPStorageMapperConfig.class);
	
	public static final String DB_ENGINE            = "db.roles.engine";
	
    public static final String DB_ENGINE_ORACLE     = "Oracle";
    public static final String DB_ENGINE_POSTGRESQL = "PostGreSQL";
    public static final String DB_ENGINE_MARIADB    = "MariaDB";
    public static final String DB_ENGINE_MYSQL      = "MySQL";
    public static final String DB_ENGINE_SQLSERVER  = "SQL Server";
    public static final String DB_ENGINE_SYBASE     = "Sybase";
    public static final String DB_ENGINE_H2         = "H2 (Local only)";
	
    public static final String DB_LOGIN_ATTRIBUTE   = "db.roles.login.attribute";
    public static final String DB_PASSWD_ATTRIBUTE  = "db.roles.password.attribute";

    
	public static final String DB_URL_ATTRIBUTE 	= "db.roles.url.attribute";
    
    public static final String DB_SQL_QUERY_4_ROLES = "db.roles.sql.query";
    public static final String SQL_QUERY_CACHE_TTL = "db.roles.sql.query.cache.ttl";

    public static final String DB_POOL_MIN_IDLE = "db.pool.min.idle";
    public static final String DB_POOL_MAX_IDLE = "db.pool.max.idle";
    public static final String DB_POOL_MAX_WAIT = "db.pool.max.wait";
    public static final String DB_POOL_MAX_ACTIVE = "db.pool.max.active";
    public static final String DB_POOL_MAX_OPS  = "db.pool.max.open.prepared.statement";
    
    
    // Boolean option. If true, we will map LDAP roles to realm roles. If false, we will map to client roles (client specified by option CLIENT_ID)
    public static final String USE_REALM_ROLES_MAPPING = "db.use.realm.roles.mapping";

    //Delete roles in KC if removed in DB
    public static final String DELETE_REALMS_IF_NOT_IN_RDB = "db.roles.sync.kc.from.db";
    
    // ClientId, which we want to map roles. Applicable just if "USE_REALM_ROLES_MAPPING" is false
    public static final String CLIENT_ID = "db.role.client.id";

    public static final String SQL_QUERY_DEFAULT = "SELECT ROLES FROM MEMBERSHIP Where USER_ID=?";
    
    protected static final List<String> dBEngines;
    protected static final Map<String, String> dBEnginesJDBCDriverList = new LinkedHashMap<>();

    protected final ComponentModel mapperModel;
    
    protected BasicDataSource ds = null;

    static {
    	dBEnginesJDBCDriverList.put(DbGroup2RoleLDAPStorageMapperConfig.DB_ENGINE_ORACLE,     "oracle.jdbc.driver.OracleDriver");
    	dBEnginesJDBCDriverList.put(DbGroup2RoleLDAPStorageMapperConfig.DB_ENGINE_POSTGRESQL, "org.postgresql.Driver");
    	dBEnginesJDBCDriverList.put(DbGroup2RoleLDAPStorageMapperConfig.DB_ENGINE_MARIADB,    "org.mariadb.jdbc.Driver");
    	dBEnginesJDBCDriverList.put(DbGroup2RoleLDAPStorageMapperConfig.DB_ENGINE_MYSQL,      "com.mysql.jdbc.Driver");
    	dBEnginesJDBCDriverList.put(DbGroup2RoleLDAPStorageMapperConfig.DB_ENGINE_SQLSERVER,  "net.sourceforge.jtds.jdbc.Driver");
    	dBEnginesJDBCDriverList.put(DbGroup2RoleLDAPStorageMapperConfig.DB_ENGINE_SYBASE,     "net.sourceforge.jtds.jdbc.Driver");
    	dBEnginesJDBCDriverList.put(DbGroup2RoleLDAPStorageMapperConfig.DB_ENGINE_H2,         "org.h2.Driver");
    	
    	dBEngines = new LinkedList<>(dBEnginesJDBCDriverList.keySet());
    	
    }
    
    public DbGroup2RoleLDAPStorageMapperConfig(ComponentModel mapperModel) {
        this.mapperModel = mapperModel;
    }

    public String getRDBEngine() {
        String jdbcDriver = mapperModel.getConfig().getFirst(DB_ENGINE);
        return jdbcDriver!=null ? jdbcDriver : DB_ENGINE_ORACLE;
    }
    
	protected String getJDBCURL() {
		
		String connectionURL = mapperModel.getConfig().getFirst(DB_URL_ATTRIBUTE);
		if (connectionURL != null && !connectionURL.trim().isBlank()) {
			return connectionURL;
		}
		
		String jdbcURL="";
		

		logger.debugf("LDAP Mapper %s : JDBC Driver URL is %s ", mapperModel.getName(), jdbcURL );
		return jdbcURL;
	}

	//SQL Cache TTL in seconds
	protected int getSQLCacheTTL() {
		String sttl = mapperModel.getConfig().getFirst(SQL_QUERY_CACHE_TTL);
		try {
			return Integer.valueOf(sttl).intValue();
		} catch (NumberFormatException nfe) {
			nfe.printStackTrace();
			return 60;
		}
	}
	protected String getDBUserLogin() {
		return mapperModel.getConfig().getFirst(DB_LOGIN_ATTRIBUTE);
	}
	
	protected String getDBUserPassword() {
		return mapperModel.getConfig().getFirst(DB_PASSWD_ATTRIBUTE);
	}
	
	protected String getSQLQuery() {
		return mapperModel.getConfig().getFirst(DB_SQL_QUERY_4_ROLES);
	}
	
	//From RoleMapperConfig
    public boolean isRealmRolesMapping() {
        String realmRolesMapping = mapperModel.getConfig().getFirst(USE_REALM_ROLES_MAPPING);
        boolean isRealmRole = realmRolesMapping==null || Boolean.parseBoolean(realmRolesMapping) ;
    	logger.tracef("LDAP Mapper %s : Realm roles mapping : %s", mapperModel.getName(), isRealmRole );
        return isRealmRole;
    }
    
	//From RoleMapperConfig
    public boolean isDeletingKCRolesIfRemovedFromRDB() {
        String delRolesMapping = mapperModel.getConfig().getFirst(DELETE_REALMS_IF_NOT_IN_RDB);
    	boolean result = delRolesMapping!=null && Boolean.parseBoolean(delRolesMapping);
		logger.tracef("LDAP Mapper %s : Deleting roles in Keycloak : %s", mapperModel.getName(), result );
        return result;
    }
    public String getClientId() {
        return mapperModel.getConfig().getFirst(CLIENT_ID);
    }

	protected Connection getDBConnection() throws SQLException {
		if (ds == null) {
			initDatasource();
		}
		return ds.getConnection();
	}
    
	private void initDatasource() {
        ds = new BasicDataSource();
        ds.setDriverClassName(getJDBCDriverClass());
        ds.setUsername(getDBUserLogin());
        ds.setPassword(getDBUserPassword());
        ds.setUrl(getJDBCURL());
        
        // the settings below are optional -- dbcp can work with defaults
        int minIdle = Integer.valueOf(mapperModel.getConfig().getFirst(DB_POOL_MIN_IDLE)).intValue();
        int maxIdle = Integer.valueOf(mapperModel.getConfig().getFirst(DB_POOL_MAX_IDLE)).intValue();
        int maxOPS = Integer.valueOf(mapperModel.getConfig().getFirst(DB_POOL_MAX_OPS)).intValue();
        int maxWait = Integer.valueOf(mapperModel.getConfig().getFirst(DB_POOL_MAX_WAIT)).intValue();
        int maxActive = Integer.valueOf(mapperModel.getConfig().getFirst(DB_POOL_MAX_ACTIVE)).intValue();
        ds.setMinIdle(minIdle);
        ds.setMaxIdle(maxIdle);
        ds.setMaxOpenPreparedStatements(maxOPS);
        ds.setMaxWait(maxWait);
        ds.setMaxActive(maxActive);
    	logger.debugf("LDAP Mapper %s : Datasource created", mapperModel.getName() );
	}

    protected String getJDBCDriverClass() {
    	logger.tracef("LDAP Mapper %s : JDBC Driver class : %s", mapperModel.getName(), dBEnginesJDBCDriverList.get(getRDBEngine()) );
        return dBEnginesJDBCDriverList.get(getRDBEngine());
    }
	
}

package org.toad.keycloak.storage.ldap.mappers;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;

public class DbGroup2RoleLDAPStorageMapper extends AbstractLDAPStorageMapper {

	private static final Logger logger = Logger.getLogger(DbGroup2RoleLDAPStorageMapper.class);

	private final DbGroup2RoleLDAPStorageMapperConfig config;

	public DbGroup2RoleLDAPStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
		super(mapperModel, ldapProvider);
		this.config = new DbGroup2RoleLDAPStorageMapperConfig(mapperModel);
	}

	@Override
	public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
		logger.tracef("DbGroup2RoleLDAPStorageMapper.onImportUserFromLDAP()");
		// TODO implement to import users from ldap

	}

	@Override
	public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
		logger.tracef("DbGroup2RoleLDAPStorageMapper.proxy()");
		return new DB2LDAPRoleMappingsUserDelegate(realm, delegate, delegate.getUsername());
	}

	@Override
	public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {
		logger.tracef("DbGroup2RoleLDAPStorageMapper.onRegisterUserToLDAP()");
	}

	@Override
	public void beforeLDAPQuery(LDAPQuery query) {
		logger.tracef("DbGroup2RoleLDAPStorageMapper.beforeLDAPQuery()");

	}

	protected RoleContainerModel getTargetRoleContainer(RealmModel realm) {
		logger.tracef("DbGroup2RoleLDAPStorageMapper.getTargetRoleContainer()");
		boolean realmRolesMapping = config.isRealmRolesMapping();
		if (realmRolesMapping) {
			return realm;
		} else {
			String clientId = config.getClientId();
			if (clientId == null) {
				throw new ModelException("Using client roles mapping is requested, but parameter client.id not found!");
			}
			ClientModel client = realm.getClientByClientId(clientId);
			if (client == null) {
				throw new ModelException("Can't found requested client with clientId: " + clientId);
			}
			return client;
		}
	}

	/**
	 * Returns roles from database.
	 * 
	 * @param username
	 * @return
	 */
	private Set<String> getGroupsFromDB(String username) {
		logger.tracef("DbGroup2RoleLDAPStorageMapper.getGroupsFromDB()");

		Connection connection = null;
		PreparedStatement prep_statement = null;
		ResultSet resultSet = null;
		Set<String> groupsFromExternalDB = new HashSet<String>();
		try {
			connection = config.getDBConnection();
			logger.debugf("LDAP Mapper %s : Executing SQL to get groups for user '%s'", mapperModel.getName(),
					username);
			prep_statement = connection.prepareStatement(config.getSQLQuery());
			prep_statement.setString(1, username);
			resultSet = prep_statement.executeQuery();
			while (resultSet.next()) {
				String single_group = resultSet.getString(1);
				groupsFromExternalDB.add(single_group);
			}
		} catch (SQLException sqle) {
			sqle.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (resultSet != null)
				try {
					resultSet.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			if (prep_statement != null)
				try {
					prep_statement.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			if (connection != null)
				try {
					connection.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
		}
		logger.debugf("LDAP Mapper %s : Groups for user %s found in Database are : %s ", mapperModel.getName(),
				username, groupsFromExternalDB);
		return groupsFromExternalDB;
	}

	/**
	 * 
	 * @author cvagheti
	 *
	 */
	public class DB2LDAPRoleMappingsUserDelegate extends UserModelDelegate {

		private final RealmModel realm;
		private final String ldapUser;
		private final RoleContainerModel roleContainer;

		public DB2LDAPRoleMappingsUserDelegate(RealmModel realm, UserModel user, String ldapUsername) {
			super(user);
			this.realm = realm;
			this.ldapUser = ldapUsername;
			this.roleContainer = getTargetRoleContainer(realm);
		}

		/**
		 * Returns the realm roles for the current user.
		 */
		@Override
		public Stream<RoleModel> getRealmRoleMappingsStream() {
			logger.tracef("DB2LDAPRoleMappingsUserDelegate.getRealmRoleMappingsStream()");
			if (roleContainer.equals(realm)) {
				getDBRoleMappingsConverted();
			}
			return super.getRealmRoleMappingsStream();
		}

		/**
		 * Returns the client roles for the current user.
		 */
		@Override
		public Stream<RoleModel> getClientRoleMappingsStream(ClientModel client) {
			logger.tracef("DB2LDAPRoleMappingsUserDelegate.getClientRoleMappingsStream()");
			if (roleContainer.equals(client)) {
				getDBRoleMappingsConverted();
			}
			return super.getClientRoleMappingsStream(client);
		}

		/**
		 * Return the roles for the current user.
		 */
		@Override
		public Stream<RoleModel> getRoleMappingsStream() {
			logger.tracef("DB2LDAPRoleMappingsUserDelegate.getRoleMappingsStream()");
			return getDBRoleMappingsConverted();
		}

		/**
		 * Add user roles to local database.
		 * 
		 * @return
		 */
		protected Stream<RoleModel> getDBRoleMappingsConverted() {
			logger.tracef("DB2LDAPRoleMappingsUserDelegate.getDBRoleMappingsConverted()");

			Set<String> ldapRoles = getGroupsFromDB(ldapUser);
			Set<RoleModel> dbRoleMappings = ldapRoles.stream().map(role -> {
				RoleModel modelRole = roleContainer.getRole(role);
				if (modelRole == null) {
					// Add role to local DB
					modelRole = roleContainer.addRole(role);
				}
				return modelRole;
			}).collect(Collectors.toSet());

			return dbRoleMappings.stream();
		}

	}

}

package com.custom.usergroupcallback;

import java.util.List;

import org.jbpm.services.task.identity.AbstractUserGroupInfo;
import org.kie.api.task.UserGroupCallback;

import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;

import org.jbpm.services.task.identity.adapter.UserGroupAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class CustomUserGroupCallbackImpl extends AbstractUserGroupInfo implements UserGroupCallback {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserGroupCallbackImpl.class);
	
	protected static final String DEFAULT_PROPERTIES_NAME = "classpath:/jbpm.usergroup.callback.properties";
	
	private ServiceLoader<UserGroupAdapter> ugAdapterServiceLoader = ServiceLoader.load(UserGroupAdapter.class);

	private static final ThreadLocal<UserGroupAdapter> externalUserGroupAdapterLocal = new ThreadLocal<UserGroupAdapter>();

	public static void addExternalUserGroupAdapter(UserGroupAdapter externalUserGroupAdapter) { 
	    if( externalUserGroupAdapterLocal.get() != null ) { 
	        UserGroupAdapter adapter = externalUserGroupAdapterLocal.get();
	        throw new IllegalStateException("The external UserGroupAdapter has already been set! "
	                + "(" + adapter.getClass().getName() + ")");
	    }
	    externalUserGroupAdapterLocal.set(externalUserGroupAdapter);
	}
	
	public static void clearExternalUserGroupAdapter() { 
	    externalUserGroupAdapterLocal.set(null);
	}
	
	private String rolePrincipleName = null;

    public CustomUserGroupCallbackImpl() {
		this(true);
	}

	//no no-arg constructor to prevent cdi from auto deploy
	public CustomUserGroupCallbackImpl(boolean activate) {
		// use default JBoss AS role principle name
		this("Roles");
		
		String propertiesLocation = System.getProperty("jbpm.usergroup.callback.properties");
        
		Properties config = readProperties(propertiesLocation, DEFAULT_PROPERTIES_NAME);
		if (config != null) {
			this.rolePrincipleName = config.getProperty("jaas.role.principle.name", "Roles");
		}
 	}
	
	public CustomUserGroupCallbackImpl(String rolesPrincipleName) {
		this.rolePrincipleName = rolesPrincipleName;
	}
	
	public String getRolePrincipleName() {
		return rolePrincipleName;
	}

	public void setRolePrincipleName(String rolePrincipleName) {
		this.rolePrincipleName = rolePrincipleName;
	}

	public boolean existsUser(String userId) {
		// allows everything as there is no way to ask JAAS/JACC for users in the domain
		return true;
	}

	public boolean existsGroup(String groupId) {
		// allows everything as there is no way to ask JAAS/JACC for groups in the domain
		return true;
	}

	public List<String> getGroupsForUser(String userId) {
		List<String> roles = new ArrayList<String>();
        try {
            Subject subject = getSubjectFromContainer();

            boolean isBypass = Boolean.parseBoolean(System.getProperty("org.kie.server.bypass.auth.user", "false"));
            
            logger.debug("Fetch group for " + userId);

            if (subject != null && !isBypass) {
                Set<Principal> principals = subject.getPrincipals();
    
                if (principals != null) {
				    logger.debug("Adding roles from JAAS subject");
                    roles = new ArrayList<String>();
                    for (Principal principal : principals) {
                        if (principal instanceof Group  && rolePrincipleName.equalsIgnoreCase(principal.getName())) {
                            Enumeration<? extends Principal> groups = ((Group) principal).members();
                            
                            while (groups.hasMoreElements()) {
                                Principal groupPrincipal = (Principal) groups.nextElement();
                                roles.add(groupPrincipal.getName());
                            }
                            break;
                        }
                    }
                }
                
            } else {
				roles.add("Administrator");
			}
        
        
        } catch (Exception e) {
            logger.error("Error when getting user roles for userid:" + userId, e);
        }
        return roles;
	}

	protected Subject getSubjectFromContainer() {
         try {
             return (Subject) PolicyContext.getContext( "javax.security.auth.Subject.container" );
         } catch (Exception e) {
             return null;
         }
     }
    
}

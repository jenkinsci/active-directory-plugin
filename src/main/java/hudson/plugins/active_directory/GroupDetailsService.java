package hudson.plugins.active_directory;

import hudson.security.GroupDetails;

public interface GroupDetailsService {
	GroupDetails loadGroupByGroupname(String groupname);
}

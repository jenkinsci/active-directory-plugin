package hudson.plugins.active_directory;

import hudson.security.GroupDetails;

public class ActiveDirectoryGroupDetails extends GroupDetails {
	
	private String name;

	public ActiveDirectoryGroupDetails(String name) {
		super();
		this.name = name;
	}

	@Override
	public String getName() {
		return this.name;
	}

}

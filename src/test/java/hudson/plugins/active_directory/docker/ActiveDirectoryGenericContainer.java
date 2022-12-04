package hudson.plugins.active_directory.docker;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.InternetProtocol;
import org.testcontainers.images.builder.ImageFromDockerfile;

public class ActiveDirectoryGenericContainer<SELF extends ActiveDirectoryGenericContainer<SELF>> extends GenericContainer<SELF> {

    public ActiveDirectoryGenericContainer() {
        setImage(new ImageFromDockerfile("ad-dc", false)
                .withFileFromClasspath("custom.sh", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/custom.sh")
                .withFileFromClasspath("Dockerfile", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/Dockerfile")
                .withFileFromClasspath("init.sh", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/init.sh")
                .withFileFromClasspath("kdb5_util_create.expect", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/kdb5_util_create.expect")
                .withFileFromClasspath("krb5.conf", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/krb5.conf")
                .withFileFromClasspath("named.conf.options", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/named.conf.options")
                .withFileFromClasspath("sssd.conf", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/sssd.conf")
                .withFileFromClasspath("supervisord.conf", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/supervisord.conf"));
        setWaitStrategy(null);
        addFixedExposedPort(135, 135);
        addFixedExposedPort(138, 138);
        addFixedExposedPort(445, 445);
        addFixedExposedPort(39, 39);
        addFixedExposedPort(464, 464);
        addFixedExposedPort(389, 389);
        addFixedExposedPort(3268, 3268);
        addFixedExposedPort(53, 53, InternetProtocol.UDP);
    }
}

package hudson.plugins.active_directory.docker;

import java.io.IOException;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.InternetProtocol;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.containers.wait.strategy.WaitStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.InspectContainerCmd;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import com.github.dockerjava.api.model.Ports.Binding;

public class ActiveDirectoryGenericContainer<SELF extends ActiveDirectoryGenericContainer<SELF>> extends GenericContainer<SELF> {

    public ActiveDirectoryGenericContainer() {
        super(new ImageFromDockerfile("ad-dc", false)
                .withFileFromClasspath("custom.sh", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/custom.sh")
                .withFileFromClasspath("Dockerfile", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/Dockerfile")
                .withFileFromClasspath("init.sh", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/init.sh")
                .withFileFromClasspath("kdb5_util_create.expect", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/kdb5_util_create.expect")
                .withFileFromClasspath("krb5.conf", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/krb5.conf")
                .withFileFromClasspath("named.conf.options", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/named.conf.options")
                .withFileFromClasspath("sssd.conf", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/sssd.conf")
                .withFileFromClasspath("supervisord.conf", "hudson/plugins/active_directory/docker/TheFlintstonesTest/TheFlintstones/supervisord.conf"));
        // wait for the custom.sh script to complete successfully
        setWaitStrategy(new LogMessageWaitStrategy().withRegEx(".*\\Qexited: custom (exit status 0; expected)\\E.*"));
    }

    /*
     * Expose ports needed for tests statically.
     * Any tests using this can NOT be run in parallel and require some special infra setup (overriding the hosts DNS server) so must be in a file named {@code *IT.java}.
     */
    public ActiveDirectoryGenericContainer<SELF> withStaticPorts() {
        addFixedExposedPort(3268, 3268); // global catalog
        addFixedExposedPort(3269, 3269); // global catalog over tls
        addFixedExposedPort(53, 53, InternetProtocol.TCP); // DNS over TCP
        addFixedExposedPort(53, 53, InternetProtocol.UDP); // DNS over UDP
        return this;
    }

    /** Expose container ports via mapped ports */
    public ActiveDirectoryGenericContainer<SELF> withDynamicPorts() {
        // we only need the global catalog for the tests.
        // we do not need to expose the CIFS ports (135,138,464)
        // tests using DNS can use to perform DNS lookup, however subsequent connection to the servvices would be via the SRV record and that requires 
        // the ports to match..
        addExposedPort(3268); // global catalog

        // https://github.com/testcontainers/testcontainers-java/issues/554
        // addExposedPort(53, InternetProtocol.UDP);
        return this.withCreateContainerCmdModifier(t -> addExposedUDP(t, 53));
    }

    private CreateContainerCmd addExposedUDP(CreateContainerCmd t, int port) {
        HostConfig hostConfig = t.getHostConfig();
        Ports portBindings = hostConfig.getPortBindings();
        portBindings.add(new PortBinding(Binding.empty(), ExposedPort.udp(port)));
        return t;
    }

    /**
     * Obtain the port for the UDP DNS server.
     * This method will only work if using withDynamicPorts
     */
    public String getDNSPort() throws InterruptedException, IOException {
        // NetworkSettings networkSettings = getContainerInfo().getNetworkSettings();
        // whilst the above should work it is returning something that is not matching reality and does not contain the actual ports!
        // this happens even one subsequent calls (appears as though the response is cached)

        // resort to the API.
        do {
            @SuppressWarnings("resource") // the docker client is global
            DockerClient dockerClient = getDockerClient();
            try (InspectContainerCmd inspectContainerCmd = dockerClient.inspectContainerCmd(getContainerId())) {
                Binding[] bindings = inspectContainerCmd.exec().getNetworkSettings().getPorts().getBindings().get(ExposedPort.udp(53));
                if (bindings != null) {
                    return bindings[0].getHostPortSpec();
                }
            }
            // unclear why docker is returning a reponse that everything is started without all the port bindings but 
            // this was the case on windows with docker desktop 4.13.0 
            System.err.println("docker response did not contain the port map for DNS. Sleeping before retrying...");
            Thread.sleep(1_000L);
        } while (true);

    }
}

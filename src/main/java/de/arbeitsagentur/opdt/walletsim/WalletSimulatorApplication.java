package de.arbeitsagentur.opdt.walletsim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class WalletSimulatorApplication {

    public static void main(String[] args) {
        SpringApplication.run(WalletSimulatorApplication.class, args);
    }
}

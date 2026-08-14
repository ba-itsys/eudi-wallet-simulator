package de.arbeitsagentur.opdt.walletsim.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;

@Configuration
public class AppConfig {

    /**
     * Every view builds its links with {@code @{__${basepath}__/...}} so the simulator can run
     * behind a path rewriting ingress. The value is a static variable of the view resolver rather
     * than a model attribute, because Spring does not invoke {@code @ModelAttribute} methods for
     * views rendered from an {@code @ExceptionHandler}.
     */
    @Bean
    public ThymeleafViewResolver thymeleafViewResolver(SpringTemplateEngine templateEngine, AppProperties properties) {
        ThymeleafViewResolver thymeleafViewResolver = new ThymeleafViewResolver();
        thymeleafViewResolver.setTemplateEngine(templateEngine);
        thymeleafViewResolver.setCharacterEncoding("UTF-8");
        thymeleafViewResolver.addStaticVariable("basepath", properties.basepath());
        return thymeleafViewResolver;
    }
}

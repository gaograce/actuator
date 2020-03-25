package com.example.actuator.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ActuatorWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
    //定义可以访问/monitor的ip地址数组，只有指定ip在指定数组里面并且登陆才可以访问
    String [] ipAddresses = new String[] {"127.0.0.1"};
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/monitor/**").access(RuleBuilder.create()
                                                          .authenticated()
                                                          .and(RuleBuilder.create()
                                                                          .hasAnyIpAddress(ipAddresses))
                                                          .build())
            .anyRequest().permitAll()
            .and()
            .httpBasic();
    }

    static class RuleBuilder{
        private StringBuilder builder;
        private RuleBuilder() {
            builder = new StringBuilder();
        }
        public static RuleBuilder create() {
            return new RuleBuilder();
        }
        public RuleBuilder authenticated() {
            builder.append("isAuthenticated()");
            return this;
        }
        public RuleBuilder hasIpAddress(String ip) {
            builder.append("hasIpAddress('"+ ip +"')");
            return this;
        }
        public RuleBuilder hasAnyIpAddress(String [] ip) {
            hasIpAddress(ip[0]);
            for(int i = 1; i < ip.length; i++) {
                or().hasIpAddress(ip[i]);
            }
            return this;
        }
        public RuleBuilder and() {
            builder.append(" and ");
            return this;
        }
        public RuleBuilder and(RuleBuilder r2) {
            builder.append(" and (");
            builder.append(r2.builder);
            builder.append(')');
            return this;
        }
        public RuleBuilder or() {
            builder.append(" or ");
            return this;
        }
        public RuleBuilder or(RuleBuilder r2) {
            builder.append(" or (");
            builder.append(r2);
            builder.append(')');
            return this;
        }
        public String build() {
            return builder.toString();
        }
    }
}

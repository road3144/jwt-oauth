package com.road3144.oauth2jwt.config.oauth.provider;

import java.util.Map;

public class InstagramUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes;

    public InstagramUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }


    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "instagram";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}

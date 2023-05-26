package com.example.auth.controller.request;

public class LoginValidateRequest {
    private String token;

    public LoginValidateRequest() {
    }

    public LoginValidateRequest(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}

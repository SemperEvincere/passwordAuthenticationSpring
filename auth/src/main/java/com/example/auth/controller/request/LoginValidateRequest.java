package com.example.auth.controller.request;

public class LoginValidateRequest {
    private String token;
    private String password;

    public LoginValidateRequest() {
    }

    public LoginValidateRequest(String token, String password) {
        this.token = token;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}

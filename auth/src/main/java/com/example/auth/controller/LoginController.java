package com.example.auth.controller;

import com.example.auth.controller.request.LoginRequest;
import com.example.auth.controller.request.LoginValidateRequest;
import com.example.auth.controller.response.LoginResponse;
import com.example.auth.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/login")
public class LoginController {

//    private final JwtUtil jwtUtil;
//
//    @Autowired
//    public LoginController(JwtUtil jwtUtil) {
//        this.jwtUtil = jwtUtil;
//    }


//    @PostMapping(value = "/")
//    public String login() {
//        return "login";
//    }

//    @PostMapping(value = "/", consumes = "application/json", produces = "application/json")
//    public String[] login(@RequestBody Map<String, String> request) {
//        String username = request.get("username");
//        String password = request.get("password");
//        return new String[]{username, password};
//    }

    @PostMapping(value = "/", consumes = "application/json", produces = "application/json")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        String username = request.getUsername();
        String password = request.getPassword();
        // TODO: validate username and password
        String token = JwtUtil.generateToken(username);
        return ResponseEntity.ok(new LoginResponse(username, token));
    }

    @PostMapping(value = "/validate", consumes = "application/json", produces = "application/json")
    public ResponseEntity<LoginResponse> validate(
            @RequestBody LoginValidateRequest request,
            @RequestHeader("Authorization") String authorizationHeader) {
//        String token = request.getToken(); // Obtener el token de la solicitud
        String token = authorizationHeader.replace("Bearer ", "");
        // Validar el token utilizando JwtUtil
        if (JwtUtil.validateToken(token)) {
            // El token es válido
            String username = JwtUtil.getUsernameFromToken(token);

            // Lógica adicional según tus necesidades

            // Devolver una respuesta exitosa
            LoginResponse response = new LoginResponse("Token válido", username);
            return ResponseEntity.ok(response);
        } else {
            // El token no es válido
            LoginResponse response = new LoginResponse("Token inválido", null);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }


}

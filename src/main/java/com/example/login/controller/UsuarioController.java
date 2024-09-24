package com.example.login.controller;

import com.example.login.domain.DadosUsuario;
import com.example.login.domain.Usuario;
import com.example.login.domain.UsuarioRepository;
import com.example.login.infra.security.DadosTokenJWT;
import com.example.login.infra.security.TokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/login")
public class UsuarioController {

    @Autowired
    private AuthenticationManager manager;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UsuarioRepository repository;


    @PostMapping
    public ResponseEntity efetuarLogin(@RequestBody @Valid DadosUsuario dados) {
        try {
            var authToken = new UsernamePasswordAuthenticationToken(dados.login(), dados.senha());
            var auth = manager.authenticate(authToken);

            var tokenJWT = tokenService.gerarToken((Usuario) auth.getPrincipal());

            return ResponseEntity.ok(new DadosTokenJWT(tokenJWT));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

}

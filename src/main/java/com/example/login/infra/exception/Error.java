package com.example.login.infra.exception;

import jakarta.persistence.EntityNotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class Error {

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity Error404() {
        return ResponseEntity.notFound().build();
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity Error400(MethodArgumentNotValidException ex) {
        var erro = ex.getFieldErrors();
        return ResponseEntity.badRequest().body(erro.stream().map(DadosError::new).toList());
    }

    private record DadosError(String campo, String mensagem) {
        public DadosError(FieldError erro) {
            this(erro.getField(), erro.getDefaultMessage());
        }
    }

}
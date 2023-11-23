package com.example.catalogservice.controller;

import com.example.catalogservice.jpa.CatalogEntity;
import com.example.catalogservice.service.CatalogService;
import com.example.catalogservice.vo.ResponseCatalog;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/catalog-service")
@AllArgsConstructor
public class CatalogController {
    private final Environment env;
    private final CatalogService catalogService;

    @GetMapping("/health-check")
    public String status(){
        return String.format("It's Working in catalog service on PORT %s",
                env.getProperty("local.server.port"));
    }

    @GetMapping("/catalogs")
    public ResponseEntity<List<ResponseCatalog>> getUsers(){
        Iterable<CatalogEntity> catalogsList = catalogService.getAllCatalogs();
        List<ResponseCatalog> result = new ArrayList<>();
        ModelMapper mapper = new ModelMapper();
        catalogsList.forEach(v -> {
            result.add(mapper.map(v, ResponseCatalog.class));
        });
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }
}

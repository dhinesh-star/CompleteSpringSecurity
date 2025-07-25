package com.spring_security.Security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "appuser")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppUser { // Parent Class or Owning site.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String name;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinTable(name = "appuser_roles",
               joinColumns = @JoinColumn(name = "appuser_id"),
               inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Roles> rolesSet = new HashSet<>();
}

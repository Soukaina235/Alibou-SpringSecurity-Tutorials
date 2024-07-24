package com.soukaina.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    // to get all the tokens that belong to the user
    @Query("""
        select t from Token t inner join User u on t.user.id = u.id
        where u.id = :userId and (t.expired = false or t.revoked = false)
    """)
    List<Token> findAllValidTokensByUserId(Integer userId); // valid token -> revoked == false and expired == false

    // find a Token object, by token string (which is unique)
    Optional<Token> findByToken(String token);
}

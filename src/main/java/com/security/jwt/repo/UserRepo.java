package com.security.jwt.repo;

import com.security.jwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {

    UserDetails findByUserNameAndPassword(String userName, String password);

    UserDetails findByUserName(String userName);

}

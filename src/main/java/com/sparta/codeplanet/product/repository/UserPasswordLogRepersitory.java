package com.sparta.codeplanet.product.repository;

import com.sparta.codeplanet.product.entity.UserPasswordLog;
import org.springframework.data.repository.CrudRepository;

import java.math.BigInteger;
import java.util.List;

public interface UserPasswordLogRepersitory extends CrudRepository<UserPasswordLog, Long> {

    List<UserPasswordLog> findTop3ByUserIdOrderByCreatedAtDesc(Long userId);
}
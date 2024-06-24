package com.sparta.codeplanet.product.repository;

import com.sparta.codeplanet.product.entity.Company;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public interface CompanyRepository extends JpaRepository<Company, Long> {
    Optional<Company> findByDomain(String domain);
}

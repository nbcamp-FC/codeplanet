package com.sparta.codeplanet.product.repository;

import com.sparta.codeplanet.product.entity.Company;
import com.sparta.codeplanet.product.entity.Feed;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FeedRepository extends JpaRepository<Feed,Long> {

    Page<Feed> findByUser_Company(Company company, Pageable pageable);

    Page<Feed> findAllByUserIdIn(List<Long> followList, Pageable pageable);
}

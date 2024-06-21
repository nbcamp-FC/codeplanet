package com.sparta.codeplanet.product.repository;

import com.sparta.codeplanet.product.dto.GroupFeedResponseDto;
import com.sparta.codeplanet.product.entity.Company;
import com.sparta.codeplanet.product.entity.Feed;
import com.sparta.codeplanet.product.entity.User;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FeedRepository extends JpaRepository<Feed,Long> {

    Page<Feed> findByUser_Company(Company company, Pageable pageable);
}

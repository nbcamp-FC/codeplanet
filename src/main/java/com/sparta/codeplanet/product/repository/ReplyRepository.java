package com.sparta.codeplanet.product.repository;

import com.sparta.codeplanet.product.entity.Reply;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ReplyRepository extends JpaRepository<Reply, Long> {

    List<Reply> findAllByFeedId(long feedId);
}

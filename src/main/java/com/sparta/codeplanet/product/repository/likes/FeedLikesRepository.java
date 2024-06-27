package com.sparta.codeplanet.product.repository.likes;

import com.sparta.codeplanet.product.entity.likes.FeedLikes;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface FeedLikesRepository extends JpaRepository<FeedLikes, Integer> {

    Optional<FeedLikes> findByFeedIdAndUserId(Long feedId, Long userId);

}

package com.sparta.codeplanet.product.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Follow extends TimeStamp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "from_user")
    private User fromUser;

    @ManyToOne
    @JoinColumn(name = "to_user")
    private User toUser;

    @Builder
    public Follow(Long id, @NonNull User fromUser, @NonNull User toUser) {
        this.id = id;
        this.fromUser = fromUser;
        this.toUser = toUser;
    }
}

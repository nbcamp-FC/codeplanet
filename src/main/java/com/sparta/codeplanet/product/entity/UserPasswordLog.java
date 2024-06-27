package com.sparta.codeplanet.product.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@Table(name = "UserPasswordLog")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class UserPasswordLog extends TimeStamp{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false)
    private String password;

}

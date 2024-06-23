package com.sparta.codeplanet.product.entity.likes;

import com.sparta.codeplanet.product.entity.Reply;
import com.sparta.codeplanet.product.entity.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Table(name = "replyLikes")
@NoArgsConstructor
public class ReplyLikes {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "likeId")
    private long id;

    @ManyToOne
    @JoinColumn(name = "userId")
    private User user;

    @ManyToOne
    @JoinColumn(name = "replyId")
    private Reply reply;

    public ReplyLikes(Reply reply, User user) {
        this.user = user;
        this.reply = reply;
    }
}

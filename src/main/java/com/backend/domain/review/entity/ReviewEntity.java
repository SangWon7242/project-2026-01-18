package com.backend.domain.review.entity;

import jakarta.persistence.Entity;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Entity
@Getter
@Setter
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
@ToString(callSuper = true)
public class ReviewEntity {
    private String content;
    private int userId;
    private int score;
    private int gametitle;
}

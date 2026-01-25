package com.backend.base.entity;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.backend.global.base.config.entity.BaseEntity;
import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;

import java.time.LocalDateTime;

@Generated("com.querydsl.codegen.DefaultSupertypeSerializer")
public class QBaseEntity extends EntityPathBase<BaseEntity> {

    private static final long serialVersionUID = 1126094843L;

    public static final QBaseEntity baseEntity = new QBaseEntity("baseEntity");

    public final DateTimePath<LocalDateTime> createDate = createDateTime("createDate", java.time.LocalDateTime.class);

    public final NumberPath<Long> id = createNumber("id", Long.class);

    public final DateTimePath<java.time.LocalDateTime> modifyDate = createDateTime("modifyDate", java.time.LocalDateTime.class);

    public QBaseEntity(String variable) {
        super(BaseEntity.class, forVariable(variable));
    }

    public QBaseEntity(Path<? extends BaseEntity> path) {
        super(path.getType(), path.getMetadata());
    }

    public QBaseEntity(PathMetadata metadata) {
        super(BaseEntity.class, metadata);
    }

}

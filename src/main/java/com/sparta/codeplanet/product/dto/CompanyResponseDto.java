package com.sparta.codeplanet.product.dto;

import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.product.entity.Company;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class CompanyResponseDto {

    private Long companyId;
    private String name;
    private String domain;
    private Status status;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public CompanyResponseDto(Company company) {
        this.companyId = company.getId();
        this.name = company.getName();
        this.domain = company.getDomain();
        this.status = company.getStatus();
        this.createdAt = company.getCreatedAt();
        this.updatedAt = company.getUpdatedAt();
    }
}

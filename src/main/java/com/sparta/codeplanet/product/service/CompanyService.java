package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.product.entity.Company;
import com.sparta.codeplanet.product.repository.CompanyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CompanyService {

    private final CompanyRepository companyRepository;

    /**
     * 등록된 도메인인지 확인
     * @param email 이메일
     */
    public Company verifyDomainOfEmail(String email) {
        String domain = email.substring(email.indexOf("@") + 1);

        return companyRepository.findByDomain(domain).orElseThrow(
                ()-> new CustomException(ErrorType.UNREGISTERED_DOMAIN));
    }
}

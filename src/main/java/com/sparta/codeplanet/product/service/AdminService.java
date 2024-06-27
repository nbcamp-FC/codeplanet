package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.product.dto.CompanyRequestDto;
import com.sparta.codeplanet.product.dto.CompanyResponseDto;
import com.sparta.codeplanet.product.dto.UserInfoDto;
import com.sparta.codeplanet.product.entity.Company;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.repository.CompanyRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminService {

    private final CompanyRepository companyRepository;
    private final UserRepository userRepository;
    private final UserService userService;

    public CompanyResponseDto createCompany(CompanyRequestDto requestDto, User user) {

        Company company = Company.builder()
                .name(requestDto.getName())
                .domain(requestDto.getDomain())
                .status(Status.ACTIVE)
                .build();

        Company saveCompany = companyRepository.save(company);

        return new CompanyResponseDto(saveCompany);
    }

    public List<UserInfoDto> getAllUsers() {
        List<UserInfoDto> users = userRepository.findAll().stream().map(UserInfoDto::new).toList();

        if (users.isEmpty()) {
            throw new CustomException(ErrorType.NOT_EXIST_ALL_USERS);
        }

        return users;
    }

    @Transactional
    public UserInfoDto updateRole(Long userId) {
        User user = userService.getUserById(userId);
        user.updateRole();

        return new UserInfoDto(user);
    }
}

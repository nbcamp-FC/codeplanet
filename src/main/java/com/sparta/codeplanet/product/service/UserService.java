package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.product.dto.SignupRequestDto;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final CompanyService companyService;

    @Transactional
    public User signup(SignupRequestDto requestDto) {

        // 회원 중복 확인
        Optional<User> checkUserId = userRepository.findUserByUsername(requestDto.getUsername());
        if (checkUserId.isPresent()) {
            throw new IllegalArgumentException("중복된 아이디 입니다.");
        }
        // 사용자 등록
        String hashedPassword = passwordEncoder.encode(requestDto.getPassword());
        User user = User.builder()
                .username(requestDto.getUsername())
                .nickname(requestDto.getNickname())
                .hashedPassword(hashedPassword)
                .company(companyService.verifyDomainOfEmail(requestDto.getEmail()))
                .email(requestDto.getEmail())
                .intro(requestDto.getIntro())
                .status(Status.BEFORE_APPROVE)
                .build();

        userRepository.save(user);
        return user;
    }


    public User findUserByUsername(String username) {
        return userRepository.findUserByUsernameAndStatus(username, Status.ACTIVE)
                .orElseThrow(() -> new EntityNotFoundException(
                        String.format("User with username does not exist.")));
    }

    /**
     * 이메일로 회원 찾기
     *
     * @param email 이메일
     * @return 회원
     */
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(
                () -> new CustomException(ErrorType.NOT_FOUND_USER));
    }

    /**
     * ID로 회원 찾기
     * @param userId 회원 ID
     * @return 회원
     */
    public User getUserById(Long userId) {
        return userRepository.findById(userId).orElseThrow(
                ()-> new CustomException(ErrorType.NOT_FOUND_USER));
    }
}

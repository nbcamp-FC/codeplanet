package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.product.dto.SignupRequestDto;
import com.sparta.codeplanet.product.dto.UpdatePasswordReq;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.entity.UserPasswordLog;
import com.sparta.codeplanet.product.repository.UserPasswordLogRepersitory;
import com.sparta.codeplanet.product.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserPasswordLogRepersitory userPasswordLogRepersitory;
    private final CompanyService companyService;
    private final PasswordEncoder passwordEncoder;

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

    @Transactional
    public String updateProfile(Long id, UserUpdateRequestDto requestDto) {
        User user = userRepository.findById(id).orElseThrow(()-> new CustomException(ErrorType.NOT_FOUND_USER));
        //1. 프로필수정
        if(!requestDto.getIsTalTye()) {
        String nickname = requestDto.getNickname();
        String intro = requestDto.getIntro();
        user.updateProfile(nickname, intro);
        userRepository.save(user);

        return "수정성공";
        }


        //2. 탈퇴
        // 유저의 상태가 정상이면 탈퇴 할수 있음
        if(requestDto.getIsTalTye()) {
        if(user.getStatus().equals(Status.ACTIVE)){
            user.setStatus("탈퇴");
            userRepository.save(user);
            return "탈퇴성공";
        }

        // 유저의 상태가 정상이 아니면 탈퇴 할 수 없음
        if(user.getStatus().equals(Status.DEACTIVATE)){
            throw new CustomException(ErrorType.ALREADY_TALYE_USER);
        }

        }
        return "끝";
    }

    @Transactional
    public void updatePassword(User user, UpdatePasswordReq updatePasswordReq) {
        // 1.이메일로 유저를 가져온다
        // 2.유저가 사용한 최근 3개의 비밀번호와 새로운 비밀번호 (newPassword) 가 일치하는지 알려준다. 일치하지 않으면 안돼 임마 보냄
        // 3.유저가 입력한 현재 비밀번호와 db에 있는 유저의 비밀번호가 일치한지 확인한다 일치 하지 않으면 안돼 임마를 보냄
        // 4.유저의 비밀번호를 수정한다

        // 1.이메일로 유저를 가져온다
        User updateUser = userRepository.findByEmail(user.getEmail())
                .orElseThrow(()-> new CustomException(ErrorType.NOT_FOUND_USER));

        //2 이전 3개의 비밀번호와 newPassword랑 겹치는거 있는지 확인
        List<UserPasswordLog> passwordLogs = userPasswordLogRepersitory
                .findTop3ByUserIdOrderByCreatedAtDesc(updateUser.getId());

        for(int i=0; i < passwordLogs.size(); i++) {
            UserPasswordLog passwordLog = passwordLogs.get(i);
            if(passwordEncoder.matches(passwordLog.getPassword(),passwordLog.getPassword())) {}
        }

        //3.currentPassword 현재 user 패스워드 같은지 확인
        //3-1 지금 로그인한 유저의 비밀번호
        String userPassword = updateUser.getPassword();
        String currentPassword = updatePasswordReq.getCurrentPassword();

        if(!passwordEncoder.matches(currentPassword, userPassword)) {
            throw new RuntimeException();
        }

        //4.드디어 비밀번호 바꿈 ㅜㅠ
        String hashedPassword = passwordEncoder.encode(updatePasswordReq.getNewPassword());
        updateUser.updatePassword(hashedPassword);

        userRepository.save(updateUser);
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

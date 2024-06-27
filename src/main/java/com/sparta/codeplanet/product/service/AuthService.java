package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.security.jwt.TokenProvider;
import com.sparta.codeplanet.product.repository.UserRefreshTokenRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRefreshTokenRepository userRefreshTokenRepository;
    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;


//    /**
//     *
//     * @param username
//     * @param password
//     * @return SingInResponseDto를 통해서 사용자와 Access, Refresh 토큰 정보를 전달합니다.
//     */
////    @Transactional
//    public SignInResponseDto login(String username, String password) {
//
//        User user = userRepository.findUserByUsername(username)
//                .orElseThrow(() -> new IllegalArgumentException("아이디가 일치하지 않습니다."));
//
//        if(!passwordEncoder.matches(password, user.getPassword())){
//            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
//        }
//
//
////        String accessToken = tokenProvider.createAccessToken(user.getUsername(), user.getUserRole());
////        String refreshToken = tokenProvider.createRefreshToken(user.getUsername(), user.getUserRole()); // refresh token 에 유저 정보를 담지 않습니다.
//
//        // 로그인 로직 실행과 동시에 새로운 refresh token 발급 및 저장
//        userRefreshTokenRepository.findById(user.getId())
//                .ifPresentOrElse(
//                        it-> it.updateRefreshToken(refreshToken),
//                        ()->  userRefreshTokenRepository.save(new UserRefreshToken(user, refreshToken))
//                );
//        return new SignInResponseDto(user.getUsername(), accessToken, refreshToken);
//    }


//    public void logout(HttpServletRequest request, HttpServletResponse response,
//            Authentication authentication) {
//
//    }
}

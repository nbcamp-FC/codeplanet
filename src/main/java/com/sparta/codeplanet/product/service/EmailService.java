package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.product.dto.EmailRequestDto;
import com.sparta.codeplanet.product.dto.EmailResponseDto;
import com.sparta.codeplanet.product.dto.EmailVerifyRequestDto;
import com.sparta.codeplanet.product.entity.Company;
import com.sparta.codeplanet.product.entity.Email;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.repository.EmailRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Random;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final EmailRepository emailRepository;
    private final UserService userService;
    private final CompanyService companyService;
    private final JavaMailSender emailSender;

    /**
     * 메일 발송
     * @param requestDto 수신 이메일
     * @return 발송 정보
     * @throws MessagingException 메일 발송 오류 시
     */
    @Transactional
    public EmailResponseDto sendEmail(EmailRequestDto requestDto) throws MessagingException {

        User user = getVaildUser(requestDto.getEmail());

        // 인증 코드
        String authCode = createCode();

        // 메일 양식
        MimeMessage emailForm = createEmailForm(requestDto.getEmail(), authCode);

        // 실제 메일 발송
        emailSender.send(emailForm);

        Email email = emailRepository.findByEmail(requestDto.getEmail())
                .orElse(Email.builder()
                        .email(requestDto.getEmail())
                        .authCode(authCode)
                        .build());

        email.updateAuthCode(authCode);

        emailRepository.save(email);

        return new EmailResponseDto(email.getEmail(), email.getAuthCode(), email.getExpireDate());
    }

    /**
     * 인증 코드 검증
     * @param requestDto 이메일, 인증 코드
     */
    @Transactional
    public void verifyAuthCode(EmailVerifyRequestDto requestDto) {

        User user = getVaildUser(requestDto.getEmail());

        Email email = emailRepository.findByEmail(requestDto.getEmail()).orElseThrow(
                ()-> new CustomException(ErrorType.NOT_FOUND_AUTH_CODE));

        email.verifyAuthCode(requestDto.getAuthCode());

        emailRepository.delete(email);

        // 회원 상태 변경
        user.active();
    }

    /**
     * 메일 양식 생성
     * @param email 수신 이메일
     * @param authCode 인증 코드
     * @return 메일 양식
     * @throws MessagingException 메일 발송 오류 시
     */
    private MimeMessage createEmailForm(String email, String authCode) throws MessagingException {

        MimeMessage message = emailSender.createMimeMessage();
        message.addRecipients(MimeMessage.RecipientType.TO, email);
        message.setSubject("인증 코드");

        // 메일 내용
        String msgOfEmail = "<div style='margin:20px;text-align:center;width: 495px;margin: 0 auto;'>" +
                "<h1> 안녕하세요 CODEPLANET 입니다. </h1>" +
                "<br>" +
                "<p>아래 코드를 입력해주세요<p>" +
                "<br>" +
                "<p>감사합니다.<p>" +
                "<br>" +
                "<div align='center' style='border:1px solid black;font-family:verdana;border-radius: 30px;'>" +
                "<div style='font-size:130%; margin-top: 20px;'>" +
                "CODE : <strong>" +
                authCode + "</strong><div><br/> " +
                "</div>";

        message.setText(msgOfEmail, "utf-8", "html");

        return message;
    }

    /**
     * 랜덤 인증 코드 생성
     * @return 8자의 랜덤 인증 코드
     */
    private String createCode() {
        Random random = new Random();
        StringBuffer key = new StringBuffer();

        for(int i=0; i<8; i++) {
            int idx = random.nextInt(3);

            switch (idx) {
                case 0 :
                    key.append((char) ((int)random.nextInt(26) + 97));
                    break;
                case 1:
                    key.append((char) ((int)random.nextInt(26) + 65));
                    break;
                case 2:
                    key.append(random.nextInt(9));
                    break;
            }
        }
        return key.toString();
    }

    /**
     * 검증된 회원 반환
     * @param email 이메일
     * @return 회원
     */
    private User getVaildUser(String email) {
        // 등록된 도메인인지 확인
        Company com = companyService.verifyDomainOfEmail(email);

        User user = userService.getUserByEmail(email);
        // 회원 상태 확인
        user.verifyStatusWhenEmailAuth();

        return user;
    }
}

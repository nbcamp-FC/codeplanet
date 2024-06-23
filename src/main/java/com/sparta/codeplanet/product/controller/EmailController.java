package com.sparta.codeplanet.product.controller;

import com.sparta.codeplanet.global.enums.ResponseMessage;
import com.sparta.codeplanet.product.dto.EmailRequestDto;
import com.sparta.codeplanet.product.dto.EmailResponseDto;
import com.sparta.codeplanet.product.dto.EmailVerifyRequestDto;
import com.sparta.codeplanet.product.dto.ResponseEntityDto;
import com.sparta.codeplanet.product.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/email")
@RequiredArgsConstructor
public class EmailController {

    private final EmailService emailService;

    /**
     * 인증 코드 메일 발송
     * @param requestDto 이메일
     * @return 메일 발송 정보
     * @throws MessagingException 메일 발송 오류 시
     */
    @PostMapping
    public ResponseEntity<?> sendEmail(@RequestBody @Valid EmailRequestDto requestDto) throws MessagingException {
        EmailResponseDto responseDto = emailService.sendEmail(requestDto);

        ResponseEntityDto<EmailResponseDto> responseEntity =
                new ResponseEntityDto<>(ResponseMessage.SEND_EMAIL_SUCCESS, responseDto);
        return ResponseEntity.ok(responseEntity);
    }

    /**
     * 인증 코드 검증
     * @param requestDto 이메일, 인증 코드
     * @return 성공 메시지
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verifyAuthCode(@RequestBody @Valid EmailVerifyRequestDto requestDto) {
        emailService.verifyAuthCode(requestDto);
        return ResponseEntity.ok(ResponseMessage.VERIFY_AUTH_CODE_SUCCESS.getMessage());
    }
}

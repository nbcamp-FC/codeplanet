package com.sparta.codeplanet.product.dto;

import com.sparta.codeplanet.global.enums.ResponseMessage;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class ResponseEntityDto<T> {

    private String status;
    private String message;
    private T data;

    public ResponseEntityDto(ResponseMessage message, T data) {
        this.status = HttpStatus.OK.toString();
        this.message = message.getMessage();
        this.data = data;
    }

    public ResponseEntityDto(ResponseMessage message) {
        this.status = HttpStatus.OK.toString();
        this.message = message.getMessage();
    }
}

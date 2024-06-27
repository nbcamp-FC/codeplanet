package com.sparta.codeplanet.product.dto;

import com.sparta.codeplanet.global.enums.ResponseMessage;

public record ApiResponse(
        ResponseMessage status,
        String message,
        Object data
)
{
    public static ApiResponse success(Object data) {
        return new ApiResponse(ResponseMessage.SUCCESS, null, data);
    }

    public static ApiResponse error(String message) {
        return new ApiResponse(ResponseMessage.ERROR, message, null);
    }
}

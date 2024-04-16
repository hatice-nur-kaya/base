package com.kodhnk.base.core.utilities;


import com.kodhnk.base.core.constant.Response;

public class Result {
    private boolean success;
    private Response message;
    private int statusCode;

    public Result(boolean success, Response message, int statusCode) {
        this.success = success;
        this.message = message;
        this.statusCode = statusCode;
    }

    public boolean isSuccess() {
        return this.success;
    }

    public Response getMessage() {
        return this.message;
    }

    public int getStatusCode() {
        return this.statusCode;
    }
}
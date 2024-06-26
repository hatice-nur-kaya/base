package com.kodhnk.base.core.utilities;

import com.kodhnk.base.core.constant.Response;

public class DataResult<T> extends Result {
    private T data;

    public DataResult(boolean success, Response message, T data, int statusCode) {
        super(success, message, statusCode);
        this.data = data;
    }

    public T getData() {
        return this.data;
    }
}
package com.mikov.bulkemailchecker.model;

import lombok.Getter;

@Getter
public record EmailProviderResult(String result, String provider) {

}
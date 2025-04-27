package com.mikov.bulkemailchecker.service;

import com.mikov.bulkemailchecker.model.EmailProviderResult;

public interface EmailProviderDetectionService {
    EmailProviderResult detectEmailProvider(String email);
} 
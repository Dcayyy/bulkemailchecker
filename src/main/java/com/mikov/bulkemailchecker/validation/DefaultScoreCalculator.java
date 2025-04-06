package com.mikov.bulkemailchecker.validation;

import org.springframework.stereotype.Component;
import java.util.Map;

/**
 * Default implementation of score calculator for email validation.
 */
@Component
public class DefaultScoreCalculator implements CustomScoreCalculator {

    private static final double SMTP_WEIGHT = 0.5;
    private static final double DOMAIN_AGE_WEIGHT = 0.2;
    private static final double SYNTAX_WEIGHT = 0.1;
    private static final double MX_WEIGHT = 0.1;
    private static final double OTHER_WEIGHT = 0.1;

    @Override
    public double calculateScore(Map<String, Double> scores, int domainAge) {
        double finalScore = 0.0;
        double weightSum = 0.0;
        
        // SMTP validation has highest weight
        if (scores.containsKey("smtp")) {
            finalScore += scores.get("smtp") * SMTP_WEIGHT;
            weightSum += SMTP_WEIGHT;
        }
        
        // Domain age affects score
        double ageScore = calculateAgeScore(domainAge);
        finalScore += ageScore * DOMAIN_AGE_WEIGHT;
        weightSum += DOMAIN_AGE_WEIGHT;
        
        // Syntax validation
        if (scores.containsKey("syntax")) {
            finalScore += scores.get("syntax") * SYNTAX_WEIGHT;
            weightSum += SYNTAX_WEIGHT;
        }
        
        // MX record check
        if (scores.containsKey("mx-record")) {
            finalScore += scores.get("mx-record") * MX_WEIGHT;
            weightSum += MX_WEIGHT;
        }
        
        // Average of other validators
        double otherScoreSum = 0.0;
        int otherCount = 0;
        for (Map.Entry<String, Double> entry : scores.entrySet()) {
            String validatorName = entry.getKey();
            if (!validatorName.equals("smtp") && !validatorName.equals("syntax") && 
                !validatorName.equals("mx-record") && !validatorName.equals("domain-age")) {
                otherScoreSum += entry.getValue();
                otherCount++;
            }
        }
        
        if (otherCount > 0) {
            finalScore += (otherScoreSum / otherCount) * OTHER_WEIGHT;
            weightSum += OTHER_WEIGHT;
        }
        
        // Normalize by weights
        if (weightSum > 0) {
            finalScore = finalScore / weightSum;
        }
        
        return Math.min(1.0, Math.max(0.0, finalScore));
    }
    
    private double calculateAgeScore(int ageInYears) {
        if (ageInYears < 1) {
            return 0.3; // New domains are suspicious
        } else if (ageInYears < 2) {
            return 0.6; // Domains 1-2 years old are somewhat trusted
        } else if (ageInYears < 5) {
            return 0.8; // Domains 2-5 years old are trusted
        } else {
            return 1.0; // Domains over 5 years old are fully trusted
        }
    }
} 
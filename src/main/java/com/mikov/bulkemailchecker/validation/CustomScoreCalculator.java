package com.mikov.bulkemailchecker.validation;

import java.util.Map;

/**
 * Interface for custom scoring calculations in the validation pipeline.
 * Allows for flexible scoring strategies based on validation results.
 * 
 * @author zahari.mikov
 */
public interface CustomScoreCalculator {
    
    /**
     * Calculate a final score based on individual validator scores and domain age.
     *
     * @param scores Map of validator names to scores
     * @param domainAge Age of the domain in years
     * @return Final calculated score between 0.0 and 1.0
     */
    double calculateScore(final Map<String, Double> scores, final int domainAge);
} 
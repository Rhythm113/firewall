#ifndef SQLI_DETECT_H
#define SQLI_DETECT_H

/**
 * Analyzes the payload for SQL injection indicators.
 * Performs URL decoding, hex/octal decoding, whitespace normalization, and tokenizer-based signature matching.
 *
 * @param payload The raw payload to scan.
 * @param payload_len Length of the payload.
 * @param matched_pattern Buffer to store the name of the triggered pattern.
 * @param max_pattern_len Size of matched_pattern buffer.
 * @param details Buffer to store detailed match information.
 * @param max_details_len Size of details buffer.
 * @return Cumulative SQLi score (0 to 100). Scores >= 40 represent threat detection.
 */
int detect_sqli(const char *payload, int payload_len, 
                char *matched_pattern, int max_pattern_len, 
                char *details, int max_details_len);

#endif // SQLI_DETECT_H

#ifndef BOT_DETECT_H
#define BOT_DETECT_H

/**
 * Analyzes HTTP request headers and path for Bot/Scanner indicators.
 *
 * @param payload The raw HTTP payload (first 512-1024 bytes containing headers).
 * @param payload_len Length of the payload.
 * @param matched_pattern Buffer to store the name of the triggered pattern.
 * @param max_pattern_len Size of matched_pattern buffer.
 * @param details Buffer to store detailed match information.
 * @param max_details_len Size of details buffer.
 * @return Cumulative bot score (0 to 100). Scores >= 40 represent threat detection.
 */
int detect_bot(const char *payload, int payload_len, 
               char *matched_pattern, int max_pattern_len, 
               char *details, int max_details_len);

#endif // BOT_DETECT_H

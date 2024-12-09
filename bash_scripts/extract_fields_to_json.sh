#!/bin/bash

# List of protocols to extract fields for
PROTOCOLS=("frame." "eth." "arp." "icmp." "icmpv6." "ip." "ipv6." "tcp." "udp." "mqtt." "coap." "rtcp.")

# File path for the JSON output
OUTPUT_JSON="protocol_fields_output.json"

# Start writing the JSON file
echo "{" > "$OUTPUT_JSON"
echo "  \"features\": [" >> "$OUTPUT_JSON"

FIRST_ENTRY=true

# Process each protocol
for PROTOCOL in "${PROTOCOLS[@]}"; do
  echo "Processing protocol: $PROTOCOL"

  # Extract fields for the current protocol using tshark
  tshark -G fields $PROTOCOL | while IFS=$'\t' read -r field description; do
    # Extract field details
    protocol=$(echo "$field" | cut -d'.' -f1)
    # field_name=$(echo "$field" | cut -d'.' -f2-)

    # Escape special characters in the description
    description=$(echo "$description" | sed 's/\\/\\\\/g; s/"/\\"/g')

    # Write field as JSON object
    echo "    {" >> "$OUTPUT_JSON"
    # echo "      \"name\": \"$field_name\"," >> "$OUTPUT_JSON"
    echo "      \"field\": \"$field\"," >> "$OUTPUT_JSON"
    echo "      \"protocol_dependency\": \"$protocol\"," >> "$OUTPUT_JSON"
    echo "      \"description\": \"$description\"" >> "$OUTPUT_JSON"
    echo "    }," >> "$OUTPUT_JSON"
  done
done

# Close JSON array and file
echo "  ]" >> "$OUTPUT_JSON"
echo "}" >> "$OUTPUT_JSON"

echo "Fields for all protocols saved in $OUTPUT_JSON"

from pyvulnerabilitylookup import PyVulnerabilityLookup

from shadowsight import config


def push_sighting_to_vulnerability_lookup(
    sighting_type, source, day, vulnerability_ids
):
    """Create a sighting from an incoming status and push it to the Vulnerability Lookup instance."""
    print("Pushing sighting to Vulnerability Lookup…")
    vuln_lookup = PyVulnerabilityLookup(
        config.vulnerability_lookup_base_url, token=config.vulnerability_auth_token
    )
    for vuln in vulnerability_ids:
        # Create the sighting
        sighting = {
            "type": sighting_type,
            "source": source,
            "vulnerability": vuln,
            "creation_timestamp": day,
        }

        # Post the JSON to Vulnerability Lookup
        try:
            r = vuln_lookup.create_sighting(sighting=sighting)
            if "message" in r:
                print(r["message"])
        except Exception as e:
            print(
                f"Error when sending POST request to the Vulnerability Lookup server:\n{e}"
            )


def remove_case_insensitive_duplicates(input_list):
    """Remove duplicates in a list, ignoring case.
    This approach preserves the last occurrence of each unique item based on
    lowercase equivalence. The dictionary keys are all lowercase to ensure
    case-insensitive comparison, while the original case is preserved in the output.
    """
    return list({item.lower(): item for item in input_list}.values())


def extract_vulnerability_ids(content):
    """
    Extracts vulnerability IDs from post content using the predefined regex pattern.
    """
    matches = config.vulnerability_patterns.findall(content)
    # Flatten the list of tuples to get only non-empty matched strings
    return remove_case_insensitive_duplicates(
        [match for match_tuple in matches for match in match_tuple if match]
    )

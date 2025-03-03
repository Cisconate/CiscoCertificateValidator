import asyncio
import re
from pysnmp.hlapi.v3arch.asyncio import CommunityData, UdpTransportTarget,\
                         ContextData, ObjectType, ObjectIdentity, getCmd
from pysnmp.entity.engine import SnmpEngine

search_terms= {"IOSXE","IOSD","FIREPOWER","ASA"}

def search_for_OS(input_string, search_strings):
    """
    Searches for a set of strings within raw string.  wasteful but no common syntax, and this is the first point
    of determination...

    Parameters:
        input_string (str): The string to search.
        search_strings (set): A set of strings to search for.

    Returns:
        str: The matched string if found, otherwise None.
    """

    for item in search_strings:
        # Regex pattern to find the text in parentheses
        pattern = item

        # Find all matches
        matches = re.findall(pattern, input_string)

        # If matches are found, search the first match
        if matches:
            return pattern  # Return the matched string
    return "UKNOWN"  # Return UKNOWN if no match is found


def hex_to_readable(hex_string):
    """
    Convert a hexadecimal-encoded string to readable text.

    :param hex_string: str, hexadecimal string, optionally prefixed with "0x".
    :return: str, decoded readable text.
    """
    try:
        # Remove the "0x" prefix if present
        if hex_string.startswith("0x"):
            hex_string = hex_string[2:]

        # Decode the hex string
        readable_text = bytes.fromhex(hex_string).decode("utf-8", errors="replace")
        return readable_text
    except ValueError as e:
        return f"Error decoding hex string: Plain String is: {hex_string}"


async def get_snmp_data(ip, community, oid, port=161):
    """
    Poll an SNMP device and fetch data for a given OID.
    :param ip: IP address of the device
    :param community: SNMP community string
    :param oid: SNMP OID to query
    :param port: SNMP port (default: 161)
    :return: SNMP response data or None if failed
    """
    snmpEngine = SnmpEngine()

    iterator = getCmd(
        snmpEngine,
        CommunityData(community),
        await UdpTransportTarget.create((ip, port)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = await iterator

    if errorIndication:
        print(f"Error: {errorIndication}")
        return None
    elif errorStatus:
        print(f"Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
        return None
    else:
        for varBind in varBinds:
            # Return the value of the OID
            return varBind[1].prettyPrint()


def poll_device(device_ip, community_string, cisco_sysDescr_oid):
    cisco_sysDescr = asyncio.run(get_snmp_data(device_ip, community_string, cisco_sysDescr_oid))

    if cisco_sysDescr:
        return(f"CW_SYSDESCR : {hex_to_readable(cisco_sysDescr)}")
    else:
        return("Failed to retrieve the CW_SYSDESCR data.")


def main(olddictionary, comm_string, oid_list):
    newdict=olddictionary

    for device in newdict:
        for item in oid_list:
            ip = device["IP Address"]
            value = poll_device(ip, comm_string, item)
            if value != "Failed to retrieve the CW_SYSDESCR data.":
                break

        os = search_for_OS(value, search_terms)

        device.update({"Software":os})

    return newdict

if __name__ == "__main__":
    main()

import asyncio
from pysnmp.hlapi.v3arch.asyncio import CommunityData, UdpTransportTarget,\
                         ContextData, ObjectType, ObjectIdentity, getCmd
from pysnmp.entity.engine import SnmpEngine

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
        return f"Error decoding hex string: {e}"


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

def main():
    device_ip = "192.168.30.1"
    community_string = "FedSecLab"
    cisco_sysDescr_oid = "1.3.6.1.4.1.9.9.25.1.1.1.2.7"

    print("Polling device for sysdescr...")
    cisco_sysDescr = asyncio.run(get_snmp_data(device_ip, community_string, cisco_sysDescr_oid))

    if cisco_sysDescr:
        print(f"SysDescr: {hex_to_readable(cisco_sysDescr)}")
    else:
        print("Failed to retrieve the serial number.")

if __name__ == "__main__":
    main()

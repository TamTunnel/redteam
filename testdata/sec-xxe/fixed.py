# Fixed: defusedxml disables entity expansion.
from defusedxml import ElementTree
from defusedxml.minidom import parseString


def parse_upload_etree(uploaded_file):
    return ElementTree.parse(uploaded_file)


def parse_upload_text(xml_text):
    return parseString(xml_text)

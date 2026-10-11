# Vulnerable: stdlib/lxml parsers resolve external entities by default.
import lxml.etree
import xml.dom.minidom
import xml.etree.ElementTree


def parse_upload_etree(uploaded_file):
    return xml.etree.ElementTree.parse(uploaded_file)


def parse_upload_lxml(uploaded_file):
    return lxml.etree.parse(uploaded_file)


def parse_upload_minidom(uploaded_file):
    return xml.dom.minidom.parse(uploaded_file)

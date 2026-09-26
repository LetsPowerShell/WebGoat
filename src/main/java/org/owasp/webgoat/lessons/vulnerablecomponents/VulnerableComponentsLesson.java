/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.StringReader;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  private static final String CONTACT_ELEMENT = "contact";
  private static final String DYNAMIC_PROXY_MARKER = "dynamic-proxy";
  private static final String EVENT_HANDLER_MARKER = "java.beans.EventHandler";
  private static final String PROCESS_BUILDER_MARKER = "java.lang.ProcessBuilder";
  private static final String CONTACT_INTERFACE_MARKER =
      "org.owasp.webgoat.lessons.vulnerablecomponents.Contact";
  private static final String START_ACTION_MARKER = "<action>start</action>";

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    Contact contact = null;

    try {
      if (!StringUtils.isEmpty(payload)) {
        payload =
            payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
      }
      if (isExploitPayload(payload)) {
        return success(this).feedback("vulnerable-components.success").build();
      }
      contact = parseContact(payload);
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").output(ex.getMessage()).build();
    }

    return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
  }

  private boolean isExploitPayload(String payload) {
    return StringUtils.contains(payload, DYNAMIC_PROXY_MARKER)
        && StringUtils.contains(payload, EVENT_HANDLER_MARKER)
        && StringUtils.contains(payload, PROCESS_BUILDER_MARKER)
        && StringUtils.contains(payload, CONTACT_INTERFACE_MARKER)
        && StringUtils.contains(payload, START_ACTION_MARKER);
  }

  private Contact parseContact(String payload) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    factory.setExpandEntityReferences(false);
    factory.setXIncludeAware(false);

    DocumentBuilder builder = factory.newDocumentBuilder();
    builder.setErrorHandler(
        new DefaultHandler() {
          @Override
          public void error(SAXParseException exception) throws SAXException {
            throw exception;
          }

          @Override
          public void fatalError(SAXParseException exception) throws SAXException {
            throw exception;
          }
        });

    Document document = builder.parse(new InputSource(new StringReader(payload)));
    Element root = document.getDocumentElement();
    if (root == null || !CONTACT_ELEMENT.equals(root.getTagName())) {
      throw new IllegalArgumentException("Only contact XML payloads are supported");
    }

    ContactImpl contact = new ContactImpl();
    String id = StringUtils.trimToNull(getElementValue(root, "id"));
    if (id != null) {
      contact.setId(Integer.valueOf(id));
    }
    contact.setFirstName(getElementValue(root, "firstName"));
    contact.setLastName(getElementValue(root, "lastName"));
    contact.setEmail(getElementValue(root, "email"));
    return contact;
  }

  private String getElementValue(Element root, String tagName) {
    for (Node child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
      if (child.getNodeType() == Node.ELEMENT_NODE && tagName.equals(child.getNodeName())) {
        return child.getTextContent();
      }
    }
    return null;
  }
}

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
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  private static final String CONTACT_ELEMENT = "contact";

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
    return StringUtils.contains(payload, "dynamic-proxy")
        && StringUtils.contains(payload, "java.beans.EventHandler")
        && StringUtils.contains(payload, "java.lang.ProcessBuilder")
        && StringUtils.contains(payload, "org.owasp.webgoat.lessons.vulnerablecomponents.Contact")
        && StringUtils.contains(payload, "<action>start</action>");
  }

  private Contact parseContact(String payload) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
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
    Element child = (Element) root.getElementsByTagName(tagName).item(0);
    return child == null ? null : child.getTextContent();
  }
}

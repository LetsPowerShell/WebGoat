/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

public class VulnerableComponentsLessonTest {

  private final VulnerableComponentsLesson lesson = new VulnerableComponentsLesson();

  String strangeContact =
      "<contact class='dynamic-proxy'>\n"
          + "<interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>\n"
          + "  <handler class='java.beans.EventHandler'>\n"
          + "    <target class='java.lang.ProcessBuilder'>\n"
          + "      <command>\n"
          + "        <string>calc.exe</string>\n"
          + "      </command>\n"
          + "    </target>\n"
          + "    <action>start</action>\n"
          + "  </handler>\n"
          + "</contact>";
  String contact = "<contact>\n" + "</contact>";

  @Test
  public void testTransformation() throws Exception {
    AttackResult result = lesson.completed(contact);

    assertThat(result.assignmentSolved()).isFalse();
  }

  @Test
  public void testIllegalTransformation() throws Exception {
    AttackResult result = lesson.completed(strangeContact);

    assertThat(result.assignmentSolved()).isTrue();
  }

  @Test
  public void testIllegalPayload() throws Exception {
    AttackResult result = lesson.completed("bullssjfs");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNotBlank();
  }
}

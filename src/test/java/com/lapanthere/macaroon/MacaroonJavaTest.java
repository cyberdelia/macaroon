package com.lapanthere.macaroon;

import org.junit.jupiter.api.Test;

import java.util.List;

import static com.lapanthere.macaroon.predicates.Predicates.field;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MacaroonJavaTest {
  @Test
  void testJavaUsage() {
    var key = Keys.generateSecretKey();
    var macaroon = new Macaroon.Builder("macaroon/java", "javaUsage", key)
        .require("account = 1234")
        .require(field("admin").eq(true))
        .require(field("actions").containsAll(List.of("read", "write")))
        .build();
    var verifier = new Verifier.Builder(macaroon)
        .satisfy("account = 1234")
        .satisfy(Caveat::isFirstParty)
        .satisfy("admin", true)
        .satisfy("actions", List.of("read"), String.class)
        .build();
    assertTrue(verifier.isValid(key));
  }

  @Test
  void testJavaRoundTrip() {
    var key = Keys.generateSecretKey();
    var macaroon = new Macaroon.Builder("macaroon/round-trip", "roundTrip", key)
        .require("account = 1234")
        .build();
    var serialized = macaroon.serialize();
    var deserialized = Macaroon.from(serialized);
    assertEquals(macaroon, deserialized);
  }
}

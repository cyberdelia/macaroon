# Macaroon

## Setup

Add the latest Macaroon version to your project:

### Using Gradle:

```kotlin
implementation("com.lapanthere:macaroon:1.0.0")
```

### Using Maven:

```xml

<dependency>
    <groupId>com.lapanthere</groupId>
    <artifactId>macaroon</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Getting started

To start, you'll need to generate a secret key:

```kotlin
val key = generateSecretKey()
```

```java
var key=Keys.generateSecretKey()
```

Or using a public/private key setup:

```kotlin
val privateKey = generatePrivateKey()
val publicKey = generatePublicKey()
val key = sharedSecret(publicKey, privateKey)
```

```java
var privateKey = Keys.generatePrivateKey();
var publicKey = Keys.generatePublicKey();
var key = Keys.sharedSecret(publicKey, privateKey);
```

Once you have a secret key, you can now build a macaroon:

```kotlin
val macaroon = buildMacaroon(location = "macaroon/kotlin", identifier = "kotlinUsage", key) {
    require("account = 1234")
    require(field("actions") containsAll listOf("read", "write"))
    require(field("time") lt Instant.now().plusSeconds(60))
}
```

```java
var macaroon = new Macaroon.Builder("macaroon/java", "javaUsage", key)
    .require("account = 1234")
    .require(field("time").lessThan(Instant.now().plusSeconds(60))
    .require(field("actions").containsAll(List.of("read","write")))
    .build();
```

You can then verify said macaroon:

```kotlin
val verifier = buildVerifier(macaroon) {
    satisfy("account = 1234")
    satisfy { caveat -> caveat.isFirstParty }
    satisfy("actions", "read", "write")
    satisfy("time", Instant.now())
}
verifier.isValid(key)
```

```java
var verifier = new Verifier.Builder(macaroon)
    .satisfy("account = 1234")
    .satisfy(Caveat::isFirstParty)
    .satisfy("admin", true)
    .satisfy("actions", List.of("read"), String.class)
    .build();
verifier.isValid(key);
```

plugins {
    kotlin("jvm") version "1.6.10"
}

group = "com.lapanthere.macaroons"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    explicitApiWarning()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")

    testImplementation(kotlin("test"))
}

tasks {
    test {
        useJUnitPlatform()
    }
}

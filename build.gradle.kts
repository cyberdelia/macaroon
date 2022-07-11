import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.7.10"
    `maven-publish`

    id("org.jmailen.kotlinter") version "3.11.1"
}

group = "com.lapanthere"

repositories {
    mavenCentral()
}

kotlin {
    explicitApiWarning()
}

java {
    withJavadocJar()
    withSourcesJar()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation(kotlin("reflect"))
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")

    testImplementation(kotlin("test"))
}

tasks {
    test {
        useJUnitPlatform()
    }

    withType(KotlinCompile::class) {
        kotlinOptions.jvmTarget = "11"
    }
}

publishing {
    repositories {
        maven {
            name = "Github"
            url = uri("https://maven.pkg.github.com/cyberdelia/macaroon")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }

    publications {
        create<MavenPublication>("github") {
            pom {
                name.set("Macaroon")
                description.set("Building and verifying macaroon")
                url.set("https://github.com/cyberdelia/macaroon")
                scm {
                    connection.set("scm:git:git://github.com/cyberdelia/macaroon.git")
                    developerConnection.set("scm:git:ssh://github.com/cyberdelia/macaroon.git")
                    url.set("https://github.com/cyberdelia/macaroon")
                }
            }
        }
    }
}

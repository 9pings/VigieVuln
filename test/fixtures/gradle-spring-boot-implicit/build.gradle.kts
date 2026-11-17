plugins {
    id("org.springframework.boot") version "4.1.1"
    id("io.spring.dependency-management") version "1.1.7"
}
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.postgresql:postgresql")
    implementation("org.apache.tika:tika-core:${libs.findVersion("tika").get()}")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

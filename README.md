# Shiro1 Tools

This repository contains two useful tools that were used when creating the [Apache Shiro 1 Hashcat module](https://github.com/hashcat/hashcat/pull/4017):

- `shiro-crack`
  - This is a standalone `C` application which uses OpenSSL to crack the Apache Shiro 1 hashing implementation
    - Shout out to [khr0x40sh](https://github.com/khr0x40sh) for showing me the [original gist](https://gist.github.com/gquere/8dc40c5a6a900215102e6ac94716b33d) showing the cracking implementation

- `shiro-hash-generator`
  - This is a Java application which uses the official Apache Shiro 1 libraries to generate hashes for testing

A blog was created for the creation of the Hashcat module and is available [here](https://fin3ss3g0d.net/index.php/2024/06/24/crack-faster-hack-smarter-custom-hashcat-module-for-apache-shiro-1-sha-512/).

## Docker Image

Both of the tools mentioned above are already built and exist inside of the `shiro1buntu-latest.tar` exported `Docker` image file, which can be downloaded under the `Releases` page. To import the image, run the following command below:

`docker load -i <path_to_tar_file>`

## Usage

`shiro-crack`:

```
./a.out <password_file> <shiro_hash>
```

`shiro-hash-generator`:

```
java -jar <path-to-jar> <string-to-hash> <iterations>
```

## CVE-2024-4956

A script to automate exploiting `CVE-2024-4956`, a path traversal vulnerability in Sonatype Repository 3 allowing unauthenticated attackers to read system files is available [here](https://github.com/fin3ss3g0d/CVE-2024-4956). Sonatype Repository 3 uses the Apache Shiro 1 hashing algorithm at the time of writing and stores user hashes inside of OrientDB .pcl files. A sample of 155 known OrientDB .pcl existing file paths are included in the repository.

## Shiro1Extractor

A script for automating the extraction of Apache Shiro 1 hashes from OrientDB .pcl files is available [here](https://github.com/fin3ss3g0d/Shiro1Extractor) for extracting/gathering hashes to use with the Hashcat module.

## Disclaimer

This program is intended for legitimate and authorized purposes only. The author holds no responsibility or liability for misuse of this project.
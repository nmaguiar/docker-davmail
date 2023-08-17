````yaml
╭ [0] ╭ Target: nmaguiar/davmail:build (alpine 3.18.3) 
│     ├ Class : os-pkgs 
│     ╰ Type  : alpine 
╰ [1] ╭ Target         : Java 
      ├ Class          : lang-pkgs 
      ├ Type           : jar 
      ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2023-3635 
                        │      ├ PkgName         : com.squareup.okio:okio 
                        │      ├ PkgPath         : usr/local/davmail/lib/sonarqube-ant-task-2.7.0.1612.jar 
                        │      ├ InstalledVersion: 1.17.2 
                        │      ├ FixedVersion    : 3.4.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-3635 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : GzipSource class improper exception handling 
                        │      ├ Description     : GzipSource does not handle an exception that might be
                        │      │                   raised when parsing a malformed gzip buffer. This may lead
                        │      │                   to denial of service of the Okio client when handling a
                        │      │                   crafted GZIP archive, by using the GzipSource class.
                        │      │                   
                        │      │                    
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-681 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:
                        │      │                  │        │           N/I:N/A:H 
                        │      │                  │        ╰ V3Score : 5.9 
                        │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           N/I:N/A:H 
                        │      │                  │        ╰ V3Score : 7.5 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:
                        │      │                           │           N/I:N/A:H 
                        │      │                           ╰ V3Score : 5.9 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-3635 
                        │      │                  ├ [1]: https://github.com/advisories/GHSA-w33c-445m-f8w7 
                        │      │                  ├ [2]: https://github.com/square/okio/commit/81bce1a30af
                        │      │                  │      244550b0324597720e4799281da7b 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2023-3635 
                        │      │                  ├ [4]: https://research.jfrog.com/vulnerabilities/okio-g
                        │      │                  │      zip-source-unhandled-exception-dos-xray-523195/
                        │      │                  │      [m 
                        │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2023-3635 
                        │      ├ PublishedDate   : 2023-07-12T19:15:00Z 
                        │      ╰ LastModifiedDate: 2023-07-26T16:24:00Z 
                        ├ [1]  ╭ VulnerabilityID : CVE-2015-7501 
                        │      ├ PkgName         : commons-collections:commons-collections 
                        │      ├ PkgPath         : usr/local/davmail/lib/commons-collections-3.1.jar 
                        │      ├ InstalledVersion: 3.1 
                        │      ├ FixedVersion    : 3.2.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2015-7501 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : apache-commons-collections: InvokerTransformer code
                        │      │                   execution during deserialisation 
                        │      ├ Description     : Red Hat JBoss A-MQ 6.x; BPM Suite (BPMS) 6.x; BRMS 6.x
                        │      │                   and 5.x; Data Grid (JDG) 6.x; Data Virtualization (JDV) 6.x
                        │      │                   and 5.x; Enterprise Application Platform 6.x, 5.x, and
                        │      │                   4.3.x; Fuse 6.x; Fuse Service Works (FSW) 6.x; Operations
                        │      │                   Network (JBoss ON) 3.x; Portal 6.x; SOA Platform (SOA-P)
                        │      │                   5.x; Web Server (JWS) 3.x; Red Hat OpenShift/xPAAS 3.x; and
                        │      │                   Red Hat Subscription Asset Manager 1.3 allow remote
                        │      │                   attackers to execute arbitrary commands via a crafted
                        │      │                   serialized Java object, related to the Apache Commons
                        │      │                   Collections (ACC) library. 
                        │      ├ Severity        : CRITICAL 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:N/C:C/I:C/A:C 
                        │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ├ V2Score : 10 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ╰ redhat ╭ V2Vector: AV:N/AC:L/Au:N/C:P/I:P/A:P 
                        │      │                           ╰ V2Score : 7.5 
                        │      ├ References       ╭ [0] : http://foxglovesecurity.com/2015/11/06/what-do-w
                        │      │                  │       eblogic-websphere-jboss-jenkins-opennms-and-your-appl
                        │      │                  │       ication-have-in-common-this-vulnerability/ 
                        │      │                  ├ [1] : http://rhn.redhat.com/errata/RHSA-2015-2500.html 
                        │      │                  ├ [2] : http://rhn.redhat.com/errata/RHSA-2015-2501.html 
                        │      │                  ├ [3] : http://rhn.redhat.com/errata/RHSA-2015-2502.html 
                        │      │                  ├ [4] : http://rhn.redhat.com/errata/RHSA-2015-2514.html 
                        │      │                  ├ [5] : http://rhn.redhat.com/errata/RHSA-2015-2516.html 
                        │      │                  ├ [6] : http://rhn.redhat.com/errata/RHSA-2015-2517.html 
                        │      │                  ├ [7] : http://rhn.redhat.com/errata/RHSA-2015-2521.html 
                        │      │                  ├ [8] : http://rhn.redhat.com/errata/RHSA-2015-2522.html 
                        │      │                  ├ [9] : http://rhn.redhat.com/errata/RHSA-2015-2524.html 
                        │      │                  ├ [10]: http://rhn.redhat.com/errata/RHSA-2015-2670.html 
                        │      │                  ├ [11]: http://rhn.redhat.com/errata/RHSA-2015-2671.html 
                        │      │                  ├ [12]: http://rhn.redhat.com/errata/RHSA-2016-0040.html 
                        │      │                  ├ [13]: http://rhn.redhat.com/errata/RHSA-2016-1773.html 
                        │      │                  ├ [14]: http://www.oracle.com/technetwork/security-advis
                        │      │                  │       ory/cpuapr2018-3678067.html 
                        │      │                  ├ [15]: http://www.oracle.com/technetwork/security-advis
                        │      │                  │       ory/cpujan2018-3236628.html 
                        │      │                  ├ [16]: http://www.oracle.com/technetwork/security-advis
                        │      │                  │       ory/cpujul2018-4258247.html 
                        │      │                  ├ [17]: http://www.oracle.com/technetwork/security-advis
                        │      │                  │       ory/cpuoct2018-4428296.html 
                        │      │                  ├ [18]: http://www.securityfocus.com/bid/78215 
                        │      │                  ├ [19]: http://www.securitytracker.com/id/1034097 
                        │      │                  ├ [20]: http://www.securitytracker.com/id/1037052 
                        │      │                  ├ [21]: http://www.securitytracker.com/id/1037053 
                        │      │                  ├ [22]: http://www.securitytracker.com/id/1037640 
                        │      │                  ├ [23]: https://access.redhat.com/security/cve/CVE-2015-7501 
                        │      │                  ├ [24]: https://access.redhat.com/security/vulnerabiliti
                        │      │                  │       es/2059393 
                        │      │                  ├ [25]: https://access.redhat.com/solutions/2045023 
                        │      │                  ├ [26]: https://bugzilla.redhat.com/show_bug.cgi?id=1279330 
                        │      │                  ├ [27]: https://commons.apache.org/proper/commons-collec
                        │      │                  │       tions/release_4_1.html 
                        │      │                  ├ [28]: https://foxglovesecurity.com/2015/11/06/what-do-
                        │      │                  │       weblogic-websphere-jboss-jenkins-opennms-and-your-app
                        │      │                  │       lication-have-in-common-this-vulnerability/ 
                        │      │                  ├ [29]: https://github.com/advisories/GHSA-fjq5-5j5f-mvxh 
                        │      │                  ├ [30]: https://issues.apache.org/jira/browse/COLLECTION
                        │      │                  │       S-580. 
                        │      │                  ├ [31]: https://linux.oracle.com/cve/CVE-2015-7501.html 
                        │      │                  ├ [32]: https://linux.oracle.com/errata/ELSA-2015-2671.html 
                        │      │                  ├ [33]: https://nvd.nist.gov/vuln/detail/CVE-2015-7501 
                        │      │                  ├ [34]: https://rhn.redhat.com/errata/RHSA-2015-2536.html 
                        │      │                  ├ [35]: https://www.cve.org/CVERecord?id=CVE-2015-7501 
                        │      │                  ╰ [36]: https://www.oracle.com/security-alerts/cpujul202
                        │      │                          0.html 
                        │      ├ PublishedDate   : 2017-11-09T17:29:00Z 
                        │      ╰ LastModifiedDate: 2020-07-15T03:15:00Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2015-6420 
                        │      ├ PkgName         : commons-collections:commons-collections 
                        │      ├ PkgPath         : usr/local/davmail/lib/commons-collections-3.1.jar 
                        │      ├ InstalledVersion: 3.1 
                        │      ├ FixedVersion    : 3.2.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2015-6420 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : Insecure Deserialization in Apache Commons Collection 
                        │      ├ Description     : Serialized-object interfaces in certain Cisco
                        │      │                   Collaboration and Social Media; Endpoint Clients and Client
                        │      │                   Software; Network Application, Service, and Acceleration;
                        │      │                   Network and Content Security Devices; Network Management and
                        │      │                    Provisioning; Routing and Switching - Enterprise and
                        │      │                   Service Provider; Unified Computing; Voice and Unified
                        │      │                   Communications Devices; Video, Streaming, TelePresence, and
                        │      │                   Transcoding Devices; Wireless; and Cisco Hosted Services
                        │      │                   products allow remote attackers to execute arbitrary
                        │      │                   commands via a crafted serialized Java object, related to
                        │      │                   the Apache Commons Collections (ACC) library. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ CVSS             ─ nvd ╭ V2Vector: AV:N/AC:L/Au:N/C:P/I:P/A:P 
                        │      │                        ╰ V2Score : 7.5 
                        │      ├ References       ╭ [0] : http://tools.cisco.com/security/center/content/C
                        │      │                  │       iscoSecurityAdvisory/cisco-sa-20151209-java-deseriali
                        │      │                  │       zation 
                        │      │                  ├ [1] : http://www.oracle.com/technetwork/security-advis
                        │      │                  │       ory/cpujul2018-4258247.html 
                        │      │                  ├ [2] : http://www.securityfocus.com/bid/78872 
                        │      │                  ├ [3] : https://arxiv.org/pdf/2306.05534 
                        │      │                  ├ [4] : https://github.com/advisories/GHSA-6hgm-866r-3cjv 
                        │      │                  ├ [5] : https://h20566.www2.hpe.com/portal/site/hpsc/pub
                        │      │                  │       lic/kb/docDisplay?docId=emr_na-c05376917 
                        │      │                  ├ [6] : https://h20566.www2.hpe.com/portal/site/hpsc/pub
                        │      │                  │       lic/kb/docDisplay?docId=emr_na-c05390722 
                        │      │                  ├ [7] : https://lists.apache.org/thread.html/r352e40ca98
                        │      │                  │       74d1beb4ad95403792adca7eb295e6bc3bd7b65fabcc21@%3Ccom
                        │      │                  │       mits.samza.apache.org%3E 
                        │      │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2015-6420 
                        │      │                  ├ [9] : https://www.kb.cert.org/vuls/id/581311 
                        │      │                  ├ [10]: https://www.tenable.com/security/research/tra-2017-14 
                        │      │                  ╰ [11]: https://www.tenable.com/security/research/tra-2017-23 
                        │      ├ PublishedDate   : 2015-12-15T05:59:00Z 
                        │      ╰ LastModifiedDate: 2021-03-10T16:15:00Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2019-17571 
                        │      ├ PkgName         : log4j:log4j 
                        │      ├ PkgPath         : usr/local/davmail/lib/log4j-1.2.17.jar 
                        │      ├ InstalledVersion: 1.2.17 
                        │      ├ FixedVersion    : 2.0-alpha1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2019-17571 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : log4j: deserialization of untrusted data in SocketServer 
                        │      ├ Description     : Included in Log4j 1.2 is a SocketServer class that is
                        │      │                   vulnerable to deserialization of untrusted data which can be
                        │      │                    exploited to remotely execute arbitrary code when combined
                        │      │                   with a deserialization gadget when listening to untrusted
                        │      │                   network traffic for log data. This affects Log4j versions up
                        │      │                    to 1.2 up to 1.2.17. 
                        │      ├ Severity        : CRITICAL 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:N/C:P/I:P/A:P 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ├ V2Score : 7.5 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                           │           H/I:H/A:H 
                        │      │                           ╰ V3Score : 9.8 
                        │      ├ References       ╭ [0]  : http://lists.opensuse.org/opensuse-security-ann
                        │      │                  │        ounce/2020-01/msg00022.html 
                        │      │                  ├ [1]  : https://access.redhat.com/security/cve/CVE-2019
                        │      │                  │        -17571 
                        │      │                  ├ [2]  : https://cve.mitre.org/cgi-bin/cvename.cgi?name=
                        │      │                  │        CVE-2019-17571 
                        │      │                  ├ [3]  : https://github.com/advisories/GHSA-2qrg-x229-3v8q 
                        │      │                  ├ [4]  : https://lists.apache.org/thread.html/277b4b5c2b
                        │      │                  │        0e06a825ccec565fa65bd671f35a4d58e3e2ec5d0618e1@%3Cde
                        │      │                  │        v.tika.apache.org%3E 
                        │      │                  ├ [5]  : https://lists.apache.org/thread.html/44491fb9cc
                        │      │                  │        19acc901f7cff34acb7376619f15638439416e3e14761c@%3Cde
                        │      │                  │        v.tika.apache.org%3E 
                        │      │                  ├ [6]  : https://lists.apache.org/thread.html/479471e6de
                        │      │                  │        bd608c837b9815b76eab24676657d4444fcfd5ef96d6e6@%3Cde
                        │      │                  │        v.tika.apache.org%3E 
                        │      │                  ├ [7]  : https://lists.apache.org/thread.html/564f03b4e9
                        │      │                  │        511fcba29c68fc0299372dadbdb002718fa8edcc4325e4@%3Cji
                        │      │                  │        ra.kafka.apache.org%3E 
                        │      │                  ├ [8]  : https://lists.apache.org/thread.html/6114ce5662
                        │      │                  │        00d76e3cc45c521a62c2c5a4eac15738248f58a99f622c@%3Cis
                        │      │                  │        sues.activemq.apache.org%3E 
                        │      │                  ├ [9]  : https://lists.apache.org/thread.html/752ec92cd1
                        │      │                  │        e334a639e79bfbd689a4ec2c6579ec5bb41b53ffdf358d@%3Cde
                        │      │                  │        v.kafka.apache.org%3E 
                        │      │                  ├ [10] : https://lists.apache.org/thread.html/8ab32b4c9f
                        │      │                  │        1826f20add7c40be08909de9f58a89dc1de9c09953f5ac@%3Cis
                        │      │                  │        sues.activemq.apache.org%3E 
                        │      │                  ├ [11] : https://lists.apache.org/thread.html/eea03d504b
                        │      │                  │        36e8f870e8321d908e1def1addda16adda04327fe7c125%40%3C
                        │      │                  │        dev.logging.apache.org%3E 
                        │      │                  ├ [12] : https://lists.apache.org/thread.html/r05755112a
                        │      │                  │        8c164abc1004bb44f198b1e3d8ca3d546a8f13ebd3aa05f@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [13] : https://lists.apache.org/thread.html/r107c8737d
                        │      │                  │        b39ec9ec4f4e7147b249e29be79170b9ef4b80528105a2d@%3Cd
                        │      │                  │        ev.zookeeper.apache.org%3E 
                        │      │                  ├ [14] : https://lists.apache.org/thread.html/r13d4b5c60
                        │      │                  │        ff63f3c4fab51d6ff266655be503b8a1884e2f2fab67c3a@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [15] : https://lists.apache.org/thread.html/r189aaeaad
                        │      │                  │        897f7d6b96f7c43a8ef2dfb9f6e9f8c1cc9ad182ce9b9ae@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [16] : https://lists.apache.org/thread.html/r18f1c010b
                        │      │                  │        554a3a2d761e8ffffd8674fd4747bcbcf16c643d708318c@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [17] : https://lists.apache.org/thread.html/r1b103833c
                        │      │                  │        b5bc8466e24ff0ecc5e75b45a705334ab6a444e64e840a0@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [18] : https://lists.apache.org/thread.html/r1b7734dfd
                        │      │                  │        fd938640f2f5fb6f4231a267145c71ed60cc7faa1cbac07@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [19] : https://lists.apache.org/thread.html/r26244f9f7
                        │      │                  │        d9a8a27a092eb0b2a0ca9395e88fcde8b5edaeca7ce569c@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [20] : https://lists.apache.org/thread.html/r2721aba31
                        │      │                  │        a8562639c4b937150897e24f78f747cdbda8641c0f659fe@%3Cu
                        │      │                  │        sers.kafka.apache.org%3E 
                        │      │                  ├ [21] : https://lists.apache.org/thread.html/r2756fd570
                        │      │                  │        b6709d55a61831ca028405bcb3e312175a60bc5d911c81f@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [22] : https://lists.apache.org/thread.html/r2ce8d2615
                        │      │                  │        4bea939536e6cf27ed02d3192bf5c5d04df885a80fe89b3@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [23] : https://lists.apache.org/thread.html/r2ff63f210
                        │      │                  │        842a3c5e42f03a35d8f3a345134d073c80a04077341c211@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [24] : https://lists.apache.org/thread.html/r3543ead23
                        │      │                  │        17dcd3306f69ee37b07dd383dbba6e2f47ff11eb55879ad@%3Cu
                        │      │                  │        sers.activemq.apache.org%3E 
                        │      │                  ├ [25] : https://lists.apache.org/thread.html/r356d57d62
                        │      │                  │        25f91fdc30f8b0a2bed229d1ece55e16e552878c5fa809a@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [26] : https://lists.apache.org/thread.html/r3784834e8
                        │      │                  │        0df2f284577a5596340fb84346c91a2dea6a073e65e3397@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [27] : https://lists.apache.org/thread.html/r3a85514a5
                        │      │                  │        18f3080ab1fc2652cfe122c2ccf67cfb32356acb1b08fe8@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [28] : https://lists.apache.org/thread.html/r3bf7b982d
                        │      │                  │        fa0779f8a71f843d2aa6b4184a53e6be7f149ee079387fd@%3Cd
                        │      │                  │        ev.kafka.apache.org%3E 
                        │      │                  ├ [29] : https://lists.apache.org/thread.html/r3c575cabc
                        │      │                  │        7386e646fb12cb82b0b38ae5a6ade8a800f827107824495@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [30] : https://lists.apache.org/thread.html/r3cf50d05c
                        │      │                  │        e8cec8c09392624b7bae750e7643dae60ef2438641ee015@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [31] : https://lists.apache.org/thread.html/r3d666e4e8
                        │      │                  │        905157f3c046d31398b04f2bfd4519e31f266de108c6919@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [32] : https://lists.apache.org/thread.html/r48d5019bd
                        │      │                  │        42e0770f7e5351e420a63a41ff1f16924942442c6aff6a8@%3Cc
                        │      │                  │        ommits.zookeeper.apache.org%3E 
                        │      │                  ├ [33] : https://lists.apache.org/thread.html/r48efc7cb5
                        │      │                  │        aeb4e1f67aaa06fb4b5479a5635d12f07d0b93fc2d08809@%3Cc
                        │      │                  │        ommits.zookeeper.apache.org%3E 
                        │      │                  ├ [34] : https://lists.apache.org/thread.html/r4ac89cbec
                        │      │                  │        d9e298ae9fafb5afda6fa77ac75c78d1ac957837e066c4e@%3Cu
                        │      │                  │        ser.zookeeper.apache.org%3E 
                        │      │                  ├ [35] : https://lists.apache.org/thread.html/r4b25538be
                        │      │                  │        50126194cc646836c718b1a4d8f71bd9c912af5b59134ad@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [36] : https://lists.apache.org/thread.html/r52a5129df
                        │      │                  │        402352adc34d052bab9234c8ef63596306506a89fdc7328@%3Cu
                        │      │                  │        sers.activemq.apache.org%3E 
                        │      │                  ├ [37] : https://lists.apache.org/thread.html/r594411f4b
                        │      │                  │        ddebaf48a4c70266d0b7849e0d82bb72826f61b3a35bba7@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [38] : https://lists.apache.org/thread.html/r5c084578b
                        │      │                  │        3e3b40bd903c9d9e525097421bcd88178e672f612102eb2@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [39] : https://lists.apache.org/thread.html/r61590890e
                        │      │                  │        dcc64140e0c606954b29a063c3d08a2b41d447256d51a78@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [40] : https://lists.apache.org/thread.html/r61db8e7dc
                        │      │                  │        b56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cd
                        │      │                  │        ev.kafka.apache.org%3E 
                        │      │                  ├ [41] : https://lists.apache.org/thread.html/r61db8e7dc
                        │      │                  │        b56dc000a5387a88f7a473bacec5ee01b9ff3f55308aacc@%3Cu
                        │      │                  │        sers.kafka.apache.org%3E 
                        │      │                  ├ [42] : https://lists.apache.org/thread.html/r6236b5f86
                        │      │                  │        46d48af8b66d5050f288304016840788e508c883356fe0e@%3Cl
                        │      │                  │        og4j-user.logging.apache.org%3E 
                        │      │                  ├ [43] : https://lists.apache.org/thread.html/r681b4432d
                        │      │                  │        0605f327b68b9f8a42662993e699d04614de4851c35ffd1@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [44] : https://lists.apache.org/thread.html/r696507338
                        │      │                  │        dd5f44efc23d98cafe30f217cf3ba78e77ed1324c7a5179@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [45] : https://lists.apache.org/thread.html/r6aec6b8f7
                        │      │                  │        0167fa325fb98b3b5c9ce0ffaed026e697b69b85ac24628@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [46] : https://lists.apache.org/thread.html/r6b45a2fcc
                        │      │                  │        8e98ac93a179183dbb7f340027bdb8e3ab393418076b153@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [47] : https://lists.apache.org/thread.html/r6d34da5a0
                        │      │                  │        ca17ab08179a30c971446c7421af0e96f6d60867eabfc52@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [48] : https://lists.apache.org/thread.html/r71e26f9c2
                        │      │                  │        d5826c6f95ad60f7d052d75e1e70b0d2dd853db6fc26d5f@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [49] : https://lists.apache.org/thread.html/r746fbc3fc
                        │      │                  │        13aee292ae6851f7a5080f592fa3a67b983c6887cdb1fc5@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [50] : https://lists.apache.org/thread.html/r7a1acc953
                        │      │                  │        73105169bd44df710c2f462cad31fb805364d2958a5ee03@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [51] : https://lists.apache.org/thread.html/r7bcdc7108
                        │      │                  │        57725c311b856c0b82cee6207178af5dcde1bd43d289826@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [52] : https://lists.apache.org/thread.html/r7f462c69d
                        │      │                  │        5ded4c0223e014d95a3496690423c5f6f05c09e2f2a407a@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [53] : https://lists.apache.org/thread.html/r8244fd083
                        │      │                  │        1db894d5e89911ded9c72196d395a90ae655414d23ed0dd@%3Cu
                        │      │                  │        sers.activemq.apache.org%3E 
                        │      │                  ├ [54] : https://lists.apache.org/thread.html/r8418a0dff
                        │      │                  │        1729f19cf1024937e23a2db4c0f94f2794a423f5c10e8e7@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [55] : https://lists.apache.org/thread.html/r8890b8f18
                        │      │                  │        f1de821595792b58b968a89692a255bc20d86d395270740@%3Cc
                        │      │                  │        ommits.druid.apache.org%3E 
                        │      │                  ├ [56] : https://lists.apache.org/thread.html/r8a1cfd470
                        │      │                  │        5258c106e488091fcec85f194c82f2bbde6bd151e201870@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [57] : https://lists.apache.org/thread.html/r8c392ca48
                        │      │                  │        bb7e50754e4bc05865e9731b23d568d18a520fe3d8c1f75@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [58] : https://lists.apache.org/thread.html/r8c6300245
                        │      │                  │        c0bcef095e9f07b48157e2c6471df0816db3408fcf1d748@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [59] : https://lists.apache.org/thread.html/r8d78a0fbb
                        │      │                  │        56d505461e29868d1026e98c402e6a568c13a6da67896a2@%3Cd
                        │      │                  │        ev.jena.apache.org%3E 
                        │      │                  ├ [60] : https://lists.apache.org/thread.html/r8e3f7da12
                        │      │                  │        bf5750b0a02e69a78a61073a2ac950eed7451ce70a65177@%3Cc
                        │      │                  │        ommits.zookeeper.apache.org%3E 
                        │      │                  ├ [61] : https://lists.apache.org/thread.html/r909b8e3a3
                        │      │                  │        6913944d3b7bafe9635d4ca84f8f0e2cd146a1784f667c2@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [62] : https://lists.apache.org/thread.html/r90c23eb8c
                        │      │                  │        82835fa82df85ae5e88c81fd9241e20a22971b0fb8f2c34@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [63] : https://lists.apache.org/thread.html/r944183c87
                        │      │                  │        1594fe9a555b8519a7c945bbcf6714d72461aa6c929028f@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [64] : https://lists.apache.org/thread.html/r9a9e3b42c
                        │      │                  │        d5d1c4536a14ef04f75048dec8e2740ac6a138ea912177f@%3Cp
                        │      │                  │        luto-dev.portals.apache.org%3E 
                        │      │                  ├ [65] : https://lists.apache.org/thread.html/r9d0d03f2e
                        │      │                  │        7d9e13c68b530f81d02b0fec33133edcf27330d8089fcfb@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [66] : https://lists.apache.org/thread.html/r9d2e28e71
                        │      │                  │        f91ba0b6f4114c8ecd96e2b1f7e0d06bdf8eb768c183aa9@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [67] : https://lists.apache.org/thread.html/r9dc250565
                        │      │                  │        1788ac668299774d9e7af4dc616be2f56fdc684d1170882@%3Cu
                        │      │                  │        sers.activemq.apache.org%3E 
                        │      │                  ├ [68] : https://lists.apache.org/thread.html/r9fb3238cf
                        │      │                  │        c3222f2392ca6517353aadae18f76866157318ac562e706@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [69] : https://lists.apache.org/thread.html/ra18a903f7
                        │      │                  │        85aed9403aea38bc6f36844a056283c00dcfc6936b6318c@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [70] : https://lists.apache.org/thread.html/ra38785cfc
                        │      │                  │        0e7f17f8e24bebf775dd032c033fadcaea29e5bc9fffc60@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [71] : https://lists.apache.org/thread.html/ra54fa49be
                        │      │                  │        3e773d99ccc9c2a422311cf77e3ecd3b8594ee93043a6b1@%3Cd
                        │      │                  │        ev.zookeeper.apache.org%3E 
                        │      │                  ├ [72] : https://lists.apache.org/thread.html/ra9611a843
                        │      │                  │        1cb62369bce8909d7645597e1dd45c24b448836b1e54940@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [73] : https://lists.apache.org/thread.html/raedd12dc2
                        │      │                  │        4412b3780432bf202a2618a21a727788543e5337a458ead@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [74] : https://lists.apache.org/thread.html/rb1b29aee7
                        │      │                  │        37e1c37fe1d48528cb0febac4f5deed51f5412e6fdfe2bf@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [75] : https://lists.apache.org/thread.html/rb3c946197
                        │      │                  │        28c8f8c176d8e175e0a1086ca737ecdfcd5a2214bb768bc@%3Cc
                        │      │                  │        ommits.bookkeeper.apache.org%3E 
                        │      │                  ├ [76] : https://lists.apache.org/thread.html/rbc45eb0f5
                        │      │                  │        3fd6242af3e666c2189464f848a851d408289840cecc6e3@%3Cc
                        │      │                  │        ommits.zookeeper.apache.org%3E 
                        │      │                  ├ [77] : https://lists.apache.org/thread.html/rbd19de368
                        │      │                  │        abf0764e4383ec44d527bc9870176f488a494f09a40500d@%3Cc
                        │      │                  │        ommon-dev.hadoop.apache.org%3E 
                        │      │                  ├ [78] : https://lists.apache.org/thread.html/rbdf18e394
                        │      │                  │        28b5c80fc35113470198b1fe53b287a76a46b0f8780b5fd@%3Cd
                        │      │                  │        ev.zookeeper.apache.org%3E 
                        │      │                  ├ [79] : https://lists.apache.org/thread.html/rbf4ce74b0
                        │      │                  │        d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cd
                        │      │                  │        ev.kafka.apache.org%3E 
                        │      │                  ├ [80] : https://lists.apache.org/thread.html/rbf4ce74b0
                        │      │                  │        d1fa9810dec50ba3ace0caeea677af7c27a97111c06ccb7@%3Cu
                        │      │                  │        sers.kafka.apache.org%3E 
                        │      │                  ├ [81] : https://lists.apache.org/thread.html/rc17d8491b
                        │      │                  │        eee51607693019857e41e769795366b85be00aa2f4b3159@%3Cn
                        │      │                  │        otifications.zookeeper.apache.org%3E 
                        │      │                  ├ [82] : https://lists.apache.org/thread.html/rc1eaed7f7
                        │      │                  │        d774d5d02f66e49baced31e04827a1293d61a70bd003ca7@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [83] : https://lists.apache.org/thread.html/rc62830796
                        │      │                  │        2ae1b8cc2d21b8e4b7dd6d7755b2dd52fa56a151a27e4fd@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [84] : https://lists.apache.org/thread.html/rca24a2810
                        │      │                  │        00fb681d7e26e5c031a21eb4b0593a7735f781b53dae4e2@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [85] : https://lists.apache.org/thread.html/rcd7128058
                        │      │                  │        5425dad7e232f239c5709e425efdd0d3de4a92f808a4767@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [86] : https://lists.apache.org/thread.html/rd0e44e8ef
                        │      │                  │        71eeaaa3cf3d1b8b41eb25894372e2995ec908ce7624d26@%3Cc
                        │      │                  │        ommits.pulsar.apache.org%3E 
                        │      │                  ├ [87] : https://lists.apache.org/thread.html/rd3a9511ee
                        │      │                  │        bab60e23f224841390a3f8cd5358cff605c5f7042171e47@%3Cd
                        │      │                  │        ev.tinkerpop.apache.org%3E 
                        │      │                  ├ [88] : https://lists.apache.org/thread.html/rd5dbeee48
                        │      │                  │        08c0f2b9b51479b50de3cc6adb1072c332a200d9107f13e@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [89] : https://lists.apache.org/thread.html/rd62548374
                        │      │                  │        03e8cbfc7018baa9be29705f3f06bd007c83708f9a97679@%3Ci
                        │      │                  │        ssues.zookeeper.apache.org%3E 
                        │      │                  ├ [90] : https://lists.apache.org/thread.html/rd7805c1bf
                        │      │                  │        9388968508c6c8f84588773216e560055ddcc813d19f347@%3Cc
                        │      │                  │        ommon-issues.hadoop.apache.org%3E 
                        │      │                  ├ [91] : https://lists.apache.org/thread.html/rd882ab6b6
                        │      │                  │        42fe59cbbe94dc02bd197342058208f482e57b537940a4b@%3Cp
                        │      │                  │        luto-dev.portals.apache.org%3E 
                        │      │                  ├ [92] : https://lists.apache.org/thread.html/rda4849c68
                        │      │                  │        23dd3e83c7a356eb883180811d5c28359fe46865fd151c3@%3Cu
                        │      │                  │        sers.kafka.apache.org%3E 
                        │      │                  ├ [93] : https://lists.apache.org/thread.html/rdb7ddf288
                        │      │                  │        07e27c7801f6e56a0dfb31092d34c61bdd4fa2de9182119@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [94] : https://lists.apache.org/thread.html/rdec0d8ac1
                        │      │                  │        f03e6905b0de2df1d5fcdb98b94556e4f6cccf7519fdb26@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [95] : https://lists.apache.org/thread.html/rdf2a0d94c
                        │      │                  │        3b5b523aeff7741ae71347415276062811b687f30ea6573@%3Cc
                        │      │                  │        ommits.zookeeper.apache.org%3E 
                        │      │                  ├ [96] : https://lists.apache.org/thread.html/re36da78e4
                        │      │                  │        f3955ba6c1c373a2ab85a4deb215ca74b85fcd66142fea1@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [97] : https://lists.apache.org/thread.html/re8c21ed9d
                        │      │                  │        d218c217d242ffa90778428e446b082b5e1c29f567e8374@%3Ci
                        │      │                  │        ssues.activemq.apache.org%3E 
                        │      │                  ├ [98] : https://lists.apache.org/thread.html/reaf6b996f
                        │      │                  │        74f12b4557bc221abe88f58270ac583942fa41293c61f94@%3Cp
                        │      │                  │        luto-scm.portals.apache.org%3E 
                        │      │                  ├ [99] : https://lists.apache.org/thread.html/rec34b1ccc
                        │      │                  │        f907898e7cb36051ffac3ccf1ea89d0b261a2a3b3fb267f@%3Cc
                        │      │                  │        ommits.zookeeper.apache.org%3E 
                        │      │                  ├ [100]: https://lists.apache.org/thread.html/rf1b434e11
                        │      │                  │        834a4449cd7addb69ed0aef0923112b5938182b363a968c@%3Cn
                        │      │                  │        otifications.zookeeper.apache.org%3E 
                        │      │                  ├ [101]: https://lists.apache.org/thread.html/rf2567488c
                        │      │                  │        fc9212b42e34c6393cfa1c14e30e4838b98dda84d71041f@%3Cd
                        │      │                  │        ev.tika.apache.org%3E 
                        │      │                  ├ [102]: https://lists.apache.org/thread.html/rf53eeefb7
                        │      │                  │        e7e524deaacb9f8671cbf01b8a253e865fb94e7656722c0@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [103]: https://lists.apache.org/thread.html/rf77f79699
                        │      │                  │        c8d7e430c14cf480f12ed1297e6e8cf2ed379a425941e80@%3Cp
                        │      │                  │        luto-dev.portals.apache.org%3E 
                        │      │                  ├ [104]: https://lists.apache.org/thread.html/rf9c19bcc2
                        │      │                  │        f7a98a880fa3e3456c003d331812b55836b34ef648063c9@%3Cj
                        │      │                  │        ira.kafka.apache.org%3E 
                        │      │                  ├ [105]: https://lists.apache.org/thread.html/rf9fa47ab6
                        │      │                  │        6495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cd
                        │      │                  │        ev.mina.apache.org%3E 
                        │      │                  ├ [106]: https://lists.apache.org/thread.html/rfdf65fa67
                        │      │                  │        5c64a64459817344e0e6c44d51ee264beea6e5851fb60dc@%3Ci
                        │      │                  │        ssues.bookkeeper.apache.org%3E 
                        │      │                  ├ [107]: https://lists.debian.org/debian-lts-announce/20
                        │      │                  │        20/01/msg00008.html 
                        │      │                  ├ [108]: https://nvd.nist.gov/vuln/detail/CVE-2019-17571 
                        │      │                  ├ [109]: https://security.netapp.com/advisory/ntap-20200
                        │      │                  │        110-0001/ 
                        │      │                  ├ [110]: https://ubuntu.com/security/notices/USN-4495-1 
                        │      │                  ├ [111]: https://ubuntu.com/security/notices/USN-5998-1 
                        │      │                  ├ [112]: https://usn.ubuntu.com/4495-1/ 
                        │      │                  ├ [113]: https://www.cve.org/CVERecord?id=CVE-2019-17571 
                        │      │                  ├ [114]: https://www.debian.org/security/2020/dsa-4686 
                        │      │                  ├ [115]: https://www.oracle.com/security-alerts/cpuApr20
                        │      │                  │        21.html 
                        │      │                  ├ [116]: https://www.oracle.com/security-alerts/cpuapr20
                        │      │                  │        20.html 
                        │      │                  ├ [117]: https://www.oracle.com/security-alerts/cpuapr20
                        │      │                  │        22.html 
                        │      │                  ├ [118]: https://www.oracle.com/security-alerts/cpujul20
                        │      │                  │        20.html 
                        │      │                  ╰ [119]: https://www.oracle.com/security-alerts/cpujul20
                        │      │                           22.html 
                        │      ├ PublishedDate   : 2019-12-20T17:15:00Z 
                        │      ╰ LastModifiedDate: 2022-12-14T17:50:00Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2022-23305 
                        │      ├ PkgName         : log4j:log4j 
                        │      ├ PkgPath         : usr/local/davmail/lib/log4j-1.2.17.jar 
                        │      ├ InstalledVersion: 1.2.17 
                        │      ├ Status          : affected 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-23305 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : log4j: SQL injection in Log4j 1.x when application is
                        │      │                   configured to use JDBCAppender 
                        │      ├ Description     : By design, the JDBCAppender in Log4j 1.2.x accepts an
                        │      │                   SQL statement as a configuration parameter where the values
                        │      │                   to be inserted are converters from PatternLayout. The
                        │      │                   message converter, %m, is likely to always be included. This
                        │      │                    allows attackers to manipulate the SQL by entering crafted
                        │      │                   strings into input fields or headers of an application that
                        │      │                   are logged allowing unintended SQL queries to be executed.
                        │      │                   Note this issue only affects Log4j 1.x when specifically
                        │      │                   configured to use the JDBCAppender, which is not the
                        │      │                   default. Beginning in version 2.0-beta8, the JDBCAppender
                        │      │                   was re-introduced with proper support for parameterized SQL
                        │      │                   queries and further customization over the columns written
                        │      │                   to in logs. Apache Log4j 1.2 reached end of life in August
                        │      │                   2015. Users should upgrade to Log4j 2 as it addresses
                        │      │                   numerous other issues from the previous versions. 
                        │      ├ Severity        : CRITICAL 
                        │      ├ CweIDs           ─ [0]: CWE-89 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:P/I:P/A:P 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ├ V2Score : 6.8 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:
                        │      │                           │           H/I:H/A:H 
                        │      │                           ╰ V3Score : 8.8 
                        │      ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2022/
                        │      │                  │       01/18/4 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-23305 
                        │      │                  ├ [2] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=C
                        │      │                  │       VE-2022-23305 
                        │      │                  ├ [3] : https://errata.almalinux.org/8/ALSA-2022-0290.html 
                        │      │                  ├ [4] : https://github.com/advisories/GHSA-65fg-84f6-3jq3 
                        │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2022-23305.html 
                        │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2022-9419.html 
                        │      │                  ├ [7] : https://lists.apache.org/thread/pt6lh3pbsvxqlwlp
                        │      │                  │       4c5l798dv2hkc85y 
                        │      │                  ├ [8] : https://logging.apache.org/log4j/1.2/index.html 
                        │      │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2022-23305 
                        │      │                  ├ [10]: https://security.netapp.com/advisory/ntap-202202
                        │      │                  │       17-0007/ 
                        │      │                  ├ [11]: https://ubuntu.com/security/notices/USN-5998-1 
                        │      │                  ├ [12]: https://www.cve.org/CVERecord?id=CVE-2022-23305 
                        │      │                  ├ [13]: https://www.openwall.com/lists/oss-security/2022
                        │      │                  │       /01/18/4 
                        │      │                  ├ [14]: https://www.oracle.com/security-alerts/cpuapr202
                        │      │                  │       2.html 
                        │      │                  ╰ [15]: https://www.oracle.com/security-alerts/cpujul202
                        │      │                          2.html 
                        │      ├ PublishedDate   : 2022-01-18T16:15:00Z 
                        │      ╰ LastModifiedDate: 2023-02-24T15:30:00Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2021-4104 
                        │      ├ PkgName         : log4j:log4j 
                        │      ├ PkgPath         : usr/local/davmail/lib/log4j-1.2.17.jar 
                        │      ├ InstalledVersion: 1.2.17 
                        │      ├ Status          : affected 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2021-4104 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : Remote code execution in Log4j 1.x when application is
                        │      │                   configured to use JMSAppender 
                        │      ├ Description     : JMSAppender in Log4j 1.2 is vulnerable to
                        │      │                   deserialization of untrusted data when the attacker has
                        │      │                   write access to the Log4j configuration. The attacker can
                        │      │                   provide TopicBindingName and
                        │      │                   TopicConnectionFactoryBindingName configurations causing
                        │      │                   JMSAppender to perform JNDI requests that result in remote
                        │      │                   code execution in a similar fashion to CVE-2021-44228. Note
                        │      │                   this issue only affects Log4j 1.2 when specifically
                        │      │                   configured to use JMSAppender, which is not the default.
                        │      │                   Apache Log4j 1.2 reached end of life in August 2015. Users
                        │      │                   should upgrade to Log4j 2 as it addresses numerous other
                        │      │                   issues from the previous versions. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ╰ V3Score : 8.1 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:S/C:P/I:P/A:P 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ├ V2Score : 6 
                        │      │                  │        ╰ V3Score : 7.5 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:
                        │      │                           │           H/I:H/A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2022/
                        │      │                  │       01/18/3 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2021-4104 
                        │      │                  ├ [2] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=C
                        │      │                  │       VE-2021-4104 
                        │      │                  ├ [3] : https://errata.almalinux.org/8/ALSA-2022-0290.html 
                        │      │                  ├ [4] : https://github.com/advisories/GHSA-fp5r-v3w9-4333 
                        │      │                  ├ [5] : https://github.com/apache/logging-log4j2/pull/60
                        │      │                  │       8#issuecomment-990494126 
                        │      │                  ├ [6] : https://github.com/apache/logging-log4j2/pull/60
                        │      │                  │       8#issuecomment-991723301 
                        │      │                  ├ [7] : https://linux.oracle.com/cve/CVE-2021-4104.html 
                        │      │                  ├ [8] : https://linux.oracle.com/errata/ELSA-2022-9056.html 
                        │      │                  ├ [9] : https://lists.apache.org/thread/0x4zvtq92yggdgvw
                        │      │                  │       fgsftqrj4xx5w0nx 
                        │      │                  ├ [10]: https://nvd.nist.gov/vuln/detail/CVE-2021-4104 
                        │      │                  ├ [11]: https://psirt.global.sonicwall.com/vuln-detail/S
                        │      │                  │       NWLID-2021-0033 
                        │      │                  ├ [12]: https://security.gentoo.org/glsa/202209-02 
                        │      │                  ├ [13]: https://security.netapp.com/advisory/ntap-202112
                        │      │                  │       23-0007/ 
                        │      │                  ├ [14]: https://ubuntu.com/security/notices/USN-5223-1 
                        │      │                  ├ [15]: https://ubuntu.com/security/notices/USN-5223-2 
                        │      │                  ├ [16]: https://www.cve.org/CVERecord?id=CVE-2021-4104 
                        │      │                  ├ [17]: https://www.cve.org/CVERecord?id=CVE-2021-44228 
                        │      │                  ├ [18]: https://www.kb.cert.org/vuls/id/930724 
                        │      │                  ├ [19]: https://www.openwall.com/lists/oss-security/2021
                        │      │                  │       /12/13/1 
                        │      │                  ├ [20]: https://www.openwall.com/lists/oss-security/2021
                        │      │                  │       /12/13/2 
                        │      │                  ├ [21]: https://www.oracle.com/security-alerts/cpuapr202
                        │      │                  │       2.html 
                        │      │                  ├ [22]: https://www.oracle.com/security-alerts/cpujan202
                        │      │                  │       2.html 
                        │      │                  ╰ [23]: https://www.oracle.com/security-alerts/cpujul202
                        │      │                          2.html 
                        │      ├ PublishedDate   : 2021-12-14T12:15:00Z 
                        │      ╰ LastModifiedDate: 2022-10-05T17:53:00Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2022-23302 
                        │      ├ PkgName         : log4j:log4j 
                        │      ├ PkgPath         : usr/local/davmail/lib/log4j-1.2.17.jar 
                        │      ├ InstalledVersion: 1.2.17 
                        │      ├ Status          : affected 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-23302 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : log4j: Remote code execution in Log4j 1.x when
                        │      │                   application is configured to use JMSSink 
                        │      ├ Description     : JMSSink in all versions of Log4j 1.x is vulnerable to
                        │      │                   deserialization of untrusted data when the attacker has
                        │      │                   write access to the Log4j configuration or if the
                        │      │                   configuration references an LDAP service the attacker has
                        │      │                   access to. The attacker can provide a
                        │      │                   TopicConnectionFactoryBindingName configuration causing
                        │      │                   JMSSink to perform JNDI requests that result in remote code
                        │      │                   execution in a similar fashion to CVE-2021-4104. Note this
                        │      │                   issue only affects Log4j 1.x when specifically configured to
                        │      │                    use JMSSink, which is not the default. Apache Log4j 1.2
                        │      │                   reached end of life in August 2015. Users should upgrade to
                        │      │                   Log4j 2 as it addresses numerous other issues from the
                        │      │                   previous versions. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ╰ V3Score : 8.8 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:S/C:P/I:P/A:P 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ├ V2Score : 6 
                        │      │                  │        ╰ V3Score : 8.8 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:
                        │      │                           │           H/I:H/A:H 
                        │      │                           ╰ V3Score : 8.8 
                        │      ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2022/
                        │      │                  │       01/18/3 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-23302 
                        │      │                  ├ [2] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=C
                        │      │                  │       VE-2022-23302 
                        │      │                  ├ [3] : https://errata.almalinux.org/8/ALSA-2022-0290.html 
                        │      │                  ├ [4] : https://github.com/advisories/GHSA-w9p3-5cr8-m3jj 
                        │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2022-23302.html 
                        │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2022-9419.html 
                        │      │                  ├ [7] : https://lists.apache.org/thread/bsr3l5qz4g0myrjh
                        │      │                  │       y9h67bcxodpkwj4w 
                        │      │                  ├ [8] : https://logging.apache.org/log4j/1.2/index.html 
                        │      │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2022-23302 
                        │      │                  ├ [10]: https://security.netapp.com/advisory/ntap-202202
                        │      │                  │       17-0006/ 
                        │      │                  ├ [11]: https://ubuntu.com/security/notices/USN-5998-1 
                        │      │                  ├ [12]: https://www.cve.org/CVERecord?id=CVE-2022-23302 
                        │      │                  ├ [13]: https://www.openwall.com/lists/oss-security/2022
                        │      │                  │       /01/18/3 
                        │      │                  ├ [14]: https://www.oracle.com/security-alerts/cpuapr202
                        │      │                  │       2.html 
                        │      │                  ╰ [15]: https://www.oracle.com/security-alerts/cpujul202
                        │      │                          2.html 
                        │      ├ PublishedDate   : 2022-01-18T16:15:00Z 
                        │      ╰ LastModifiedDate: 2023-02-24T15:30:00Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2022-23307 
                        │      ├ PkgName         : log4j:log4j 
                        │      ├ PkgPath         : usr/local/davmail/lib/log4j-1.2.17.jar 
                        │      ├ InstalledVersion: 1.2.17 
                        │      ├ Status          : affected 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-23307 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : log4j: Unsafe deserialization flaw in Chainsaw log viewer 
                        │      ├ Description     : CVE-2020-9493 identified a deserialization issue that
                        │      │                   was present in Apache Chainsaw. Prior to Chainsaw V2.0
                        │      │                   Chainsaw was a component of Apache Log4j 1.2.x where the
                        │      │                   same issue exists. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:S/C:C/I:C/A:C 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:
                        │      │                  │        │           H/I:H/A:H 
                        │      │                  │        ├ V2Score : 9 
                        │      │                  │        ╰ V3Score : 8.8 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:
                        │      │                           │           H/I:H/A:H 
                        │      │                           ╰ V3Score : 8.8 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2022-23307 
                        │      │                  ├ [1] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=C
                        │      │                  │       VE-2022-23307 
                        │      │                  ├ [2] : https://errata.almalinux.org/8/ALSA-2022-0290.html 
                        │      │                  ├ [3] : https://github.com/advisories/GHSA-f7vh-qwp3-x37m 
                        │      │                  ├ [4] : https://linux.oracle.com/cve/CVE-2022-23307.html 
                        │      │                  ├ [5] : https://linux.oracle.com/errata/ELSA-2022-9419.html 
                        │      │                  ├ [6] : https://lists.apache.org/thread/rg4yyc89vs3dw6kp
                        │      │                  │       y3r92xop9loywyhh 
                        │      │                  ├ [7] : https://logging.apache.org/log4j/1.2/index.html 
                        │      │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2022-23307 
                        │      │                  ├ [9] : https://ubuntu.com/security/notices/USN-5998-1 
                        │      │                  ├ [10]: https://www.cve.org/CVERecord?id=CVE-2022-23307 
                        │      │                  ├ [11]: https://www.openwall.com/lists/oss-security/2022
                        │      │                  │       /01/18/5 
                        │      │                  ├ [12]: https://www.oracle.com/security-alerts/cpuapr202
                        │      │                  │       2.html 
                        │      │                  ╰ [13]: https://www.oracle.com/security-alerts/cpujul202
                        │      │                          2.html 
                        │      ├ PublishedDate   : 2022-01-18T16:15:00Z 
                        │      ╰ LastModifiedDate: 2023-02-24T15:29:00Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2023-26464 
                        │      ├ PkgName         : log4j:log4j 
                        │      ├ PkgPath         : usr/local/davmail/lib/log4j-1.2.17.jar 
                        │      ├ InstalledVersion: 1.2.17 
                        │      ├ FixedVersion    : 2.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-26464 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : DoS via hashmap logging 
                        │      ├ Description     : ** UNSUPPORTED WHEN ASSIGNED **
                        │      │                   
                        │      │                   When using the Chainsaw or SocketAppender components with
                        │      │                   Log4j 1.x on JRE less than 1.7, an attacker that manages to
                        │      │                   cause a logging entry involving a specially-crafted (ie,
                        │      │                   deeply nested) 
                        │      │                   hashmap or hashtable (depending on which logging component
                        │      │                   is in use) to be processed could exhaust the available
                        │      │                   memory in the virtual machine and achieve Denial of Service
                        │      │                   when the object is deserialized.
                        │      │                   
                        │      │                   This issue affects Apache Log4j before 2. Affected users are
                        │      │                    recommended to update to Log4j 2.x.
                        │      │                   
                        │      │                   NOTE: This vulnerability only affects products that are no
                        │      │                   longer supported by the maintainer.
                        │      │                   
                        │      │                   
                        │      │                   
                        │      │                   
                        │      │                    
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           N/I:N/A:H 
                        │      │                  │        ╰ V3Score : 7.5 
                        │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           N/I:N/A:H 
                        │      │                  │        ╰ V3Score : 7.5 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                           │           N/I:N/A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-26464 
                        │      │                  ├ [1]: https://github.com/advisories/GHSA-vp98-w2p3-mv35 
                        │      │                  ├ [2]: https://lists.apache.org/thread/wkx6grrcjkh86crr4
                        │      │                  │      9p4blc1v1nflj3t 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2023-26464 
                        │      │                  ├ [4]: https://security.netapp.com/advisory/ntap-2023050
                        │      │                  │      5-0008/ 
                        │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2023-26464 
                        │      ├ PublishedDate   : 2023-03-10T14:15:00Z 
                        │      ╰ LastModifiedDate: 2023-05-05T20:15:00Z 
                        ├ [9]  ╭ VulnerabilityID : CVE-2020-9488 
                        │      ├ PkgName         : log4j:log4j 
                        │      ├ PkgPath         : usr/local/davmail/lib/log4j-1.2.17.jar 
                        │      ├ InstalledVersion: 1.2.17 
                        │      ├ FixedVersion    : 2.12.3, 2.13.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-9488 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : log4j: improper validation of certificate with host
                        │      │                   mismatch in SMTP appender 
                        │      ├ Description     : Improper validation of certificate with host mismatch
                        │      │                   in Apache Log4j SMTP appender. This could allow an SMTPS
                        │      │                   connection to be intercepted by a man-in-the-middle attack
                        │      │                   which could leak any log messages sent through that
                        │      │                   appender. Fixed in Apache Log4j 2.12.3 and 2.13.1 
                        │      ├ Severity        : LOW 
                        │      ├ CweIDs           ─ [0]: CWE-295 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:
                        │      │                  │        │           L/I:N/A:N 
                        │      │                  │        ╰ V3Score : 3.7 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:P/I:N/A:N 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:
                        │      │                  │        │           L/I:N/A:N 
                        │      │                  │        ├ V2Score : 4.3 
                        │      │                  │        ╰ V3Score : 3.7 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:
                        │      │                           │           L/I:N/A:N 
                        │      │                           ╰ V3Score : 3.7 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-9488 
                        │      │                  ├ [1] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=C
                        │      │                  │       VE-2020-9488 
                        │      │                  ├ [2] : https://gitbox.apache.org/repos/asf?p=logging-lo
                        │      │                  │       g4j2.git;h=6851b5083ef9610bae320bf07e1f24d2aa08851b
                        │      │                  │       (release-2.x) 
                        │      │                  ├ [3] : https://gitbox.apache.org/repos/asf?p=logging-lo
                        │      │                  │       g4j2.git;h=fb91a3d71e2f3dadad6fd1beb2ab857f44fe8bbb
                        │      │                  │       (master) 
                        │      │                  ├ [4] : https://github.com/advisories/GHSA-vwqq-5vrc-xw9h 
                        │      │                  ├ [5] : https://issues.apache.org/jira/browse/LOG4J2-2819 
                        │      │                  ├ [6] : https://lists.apache.org/thread.html/r0a2699f724
                        │      │                  │       156a558afd1abb6c044fb9132caa66dce861b82699722a@%3Cjir
                        │      │                  │       a.kafka.apache.org%3E 
                        │      │                  ├ [7] : https://lists.apache.org/thread.html/r0df3d7a5ac
                        │      │                  │       b98c57e64ab9266aa21eeee1d9b399addb96f9cf1cbe05@%3Cdev
                        │      │                  │       .zookeeper.apache.org%3E 
                        │      │                  ├ [8] : https://lists.apache.org/thread.html/r1fc73f0e16
                        │      │                  │       ec2fa249d3ad39a5194afb9cc5afb4c023dc0bab5a5881@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [9] : https://lists.apache.org/thread.html/r22a56beb76
                        │      │                  │       dd8cf18e24fda9072f1e05990f49d6439662d3782a392f@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [10]: https://lists.apache.org/thread.html/r2721aba31a
                        │      │                  │       8562639c4b937150897e24f78f747cdbda8641c0f659fe@%3Cuse
                        │      │                  │       rs.kafka.apache.org%3E 
                        │      │                  ├ [11]: https://lists.apache.org/thread.html/r2f209d2713
                        │      │                  │       49bafd91537a558a279c08ebcff8fa3e547357d58833e6@%3Cdev
                        │      │                  │       .zookeeper.apache.org%3E 
                        │      │                  ├ [12]: https://lists.apache.org/thread.html/r33864a0fc1
                        │      │                  │       71c1c4bf680645ebb6d4f8057899ab294a43e1e4fe9d04@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [13]: https://lists.apache.org/thread.html/r393943de45
                        │      │                  │       2406f0f6f4b3def9f8d3c071f96323c1f6ed1a098f7fe4@%3Ctor
                        │      │                  │       que-dev.db.apache.org%3E 
                        │      │                  ├ [14]: https://lists.apache.org/thread.html/r3d1d00441c
                        │      │                  │       55144a4013adda74b051ae7864128ebcfb6ee9721a2eb3@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [15]: https://lists.apache.org/thread.html/r4285398e55
                        │      │                  │       85a0456d3d9db021a4fce6e6fcf3ec027dfa13a450ec98@%3Ciss
                        │      │                  │       ues.zookeeper.apache.org%3E 
                        │      │                  ├ [16]: https://lists.apache.org/thread.html/r4591617981
                        │      │                  │       1a32cbaa500f972de9098e6ee80ee81c7f134fce83e03a@%3Ciss
                        │      │                  │       ues.flink.apache.org%3E 
                        │      │                  ├ [17]: https://lists.apache.org/thread.html/r48bcd06049
                        │      │                  │       c1779ef709564544c3d8a32ae6ee5c3b7281a606ac4463@%3Cjir
                        │      │                  │       a.kafka.apache.org%3E 
                        │      │                  ├ [18]: https://lists.apache.org/thread.html/r48efc7cb5a
                        │      │                  │       eb4e1f67aaa06fb4b5479a5635d12f07d0b93fc2d08809@%3Ccom
                        │      │                  │       mits.zookeeper.apache.org%3E 
                        │      │                  ├ [19]: https://lists.apache.org/thread.html/r4d5dc9f352
                        │      │                  │       0071338d9ebc26f9f158a43ae28a91923d176b550a807b@%3Cdev
                        │      │                  │       .hive.apache.org%3E 
                        │      │                  ├ [20]: https://lists.apache.org/thread.html/r4db540cafc
                        │      │                  │       5d7232c62e076051ef661d37d345015b2e59b3f81a932f@%3Cdev
                        │      │                  │       .hive.apache.org%3E 
                        │      │                  ├ [21]: https://lists.apache.org/thread.html/r4ed1f49616
                        │      │                  │       a8603832d378cb9d13e7a8b9b27972bb46d946ccd8491f@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [22]: https://lists.apache.org/thread.html/r5a68258e5a
                        │      │                  │       b12532dc179edae3d6e87037fa3b50ab9d63a90c432507@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [23]: https://lists.apache.org/thread.html/r65578f3761
                        │      │                  │       a89bc164e8964acd5d913b9f8fd997967b195a89a97ca3@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [24]: https://lists.apache.org/thread.html/r7641ee788e
                        │      │                  │       1eb1be4bb206a7d15f8a64ec6ef23e5ec6132d5a567695@%3Cnot
                        │      │                  │       ifications.zookeeper.apache.org%3E 
                        │      │                  ├ [25]: https://lists.apache.org/thread.html/r7e5c10534e
                        │      │                  │       d06bf805473ac85e8412fe3908a8fa4cabf5027bf11220@%3Cdev
                        │      │                  │       .kafka.apache.org%3E 
                        │      │                  ├ [26]: https://lists.apache.org/thread.html/r7e739f2961
                        │      │                  │       753af95e2a3a637828fb88bfca68e5d6b0221d483a9ee5@%3Cnot
                        │      │                  │       ifications.zookeeper.apache.org%3E 
                        │      │                  ├ [27]: https://lists.apache.org/thread.html/r8c001b9a95
                        │      │                  │       c0bbec06f4457721edd94935a55932e64b82cc5582b846@%3Ciss
                        │      │                  │       ues.zookeeper.apache.org%3E 
                        │      │                  ├ [28]: https://lists.apache.org/thread.html/r8e96c34000
                        │      │                  │       4b7898cad3204ea51280ef6e4b553a684e1452bf1b18b1@%3Cjir
                        │      │                  │       a.kafka.apache.org%3E 
                        │      │                  ├ [29]: https://lists.apache.org/thread.html/r9776e71e3c
                        │      │                  │       67c5d13a91c1eba0dc025b48b802eb7561cc6956d6961c@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [30]: https://lists.apache.org/thread.html/r9a79175c39
                        │      │                  │       3d14d760a0ae3731b4a873230a16ef321aa9ca48a810cd@%3Ciss
                        │      │                  │       ues.zookeeper.apache.org%3E 
                        │      │                  ├ [31]: https://lists.apache.org/thread.html/ra051e07a0e
                        │      │                  │       ea4943fa104247e69596f094951f51512d42c924e86c75@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [32]: https://lists.apache.org/thread.html/ra632b329b2
                        │      │                  │       ae2324fabbad5da204c4ec2e171ff60348ec4ba698fd40@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [33]: https://lists.apache.org/thread.html/rbc45eb0f53
                        │      │                  │       fd6242af3e666c2189464f848a851d408289840cecc6e3@%3Ccom
                        │      │                  │       mits.zookeeper.apache.org%3E 
                        │      │                  ├ [34]: https://lists.apache.org/thread.html/rbc7642b980
                        │      │                  │       0249553f13457e46b813bea1aec99d2bc9106510e00ff3@%3Ctor
                        │      │                  │       que-dev.db.apache.org%3E 
                        │      │                  ├ [35]: https://lists.apache.org/thread.html/rc2dbc4633a
                        │      │                  │       6eea1fcbce6831876cfa17b73759a98c65326d1896cb1a@%3Ctor
                        │      │                  │       que-dev.db.apache.org%3E 
                        │      │                  ├ [36]: https://lists.apache.org/thread.html/rc6b81c0136
                        │      │                  │       18d1de1b5d6b8c1088aaf87b4bacc10c2371f15a566701@%3Cnot
                        │      │                  │       ifications.zookeeper.apache.org%3E 
                        │      │                  ├ [37]: https://lists.apache.org/thread.html/rd0e44e8ef7
                        │      │                  │       1eeaaa3cf3d1b8b41eb25894372e2995ec908ce7624d26@%3Ccom
                        │      │                  │       mits.pulsar.apache.org%3E 
                        │      │                  ├ [38]: https://lists.apache.org/thread.html/rd55f65c682
                        │      │                  │       2ff235eda435d31488cfbb9aa7055cdf47481ebee777cc@%3Ciss
                        │      │                  │       ues.zookeeper.apache.org%3E 
                        │      │                  ├ [39]: https://lists.apache.org/thread.html/rd5d5808881
                        │      │                  │       2cf8e677d99b07f73c654014c524c94e7fedbdee047604@%3Ctor
                        │      │                  │       que-dev.db.apache.org%3E 
                        │      │                  ├ [40]: https://lists.apache.org/thread.html/rd8e87c4d69
                        │      │                  │       df335d0ba7d815b63be8bd8a6352f429765c52eb07ddac@%3Ciss
                        │      │                  │       ues.zookeeper.apache.org%3E 
                        │      │                  ├ [41]: https://lists.apache.org/thread.html/re024d86dff
                        │      │                  │       a72ad800f2848d0c77ed93f0b78ee808350b477a6ed987@%3Cgit
                        │      │                  │       box.hive.apache.org%3E 
                        │      │                  ├ [42]: https://lists.apache.org/thread.html/rec34b1cccf
                        │      │                  │       907898e7cb36051ffac3ccf1ea89d0b261a2a3b3fb267f@%3Ccom
                        │      │                  │       mits.zookeeper.apache.org%3E 
                        │      │                  ├ [43]: https://lists.apache.org/thread.html/rf1c2a81a08
                        │      │                  │       034c688b8f15cf58a4cfab322d00002ca46d20133bee20@%3Cdev
                        │      │                  │       .kafka.apache.org%3E 
                        │      │                  ├ [44]: https://lists.apache.org/thread.html/rf9fa47ab66
                        │      │                  │       495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev
                        │      │                  │       .mina.apache.org%3E 
                        │      │                  ├ [45]: https://lists.debian.org/debian-lts-announce/202
                        │      │                  │       1/12/msg00017.html 
                        │      │                  ├ [46]: https://nvd.nist.gov/vuln/detail/CVE-2020-9488 
                        │      │                  ├ [47]: https://security.netapp.com/advisory/ntap-202005
                        │      │                  │       04-0003/ 
                        │      │                  ├ [48]: https://www.cve.org/CVERecord?id=CVE-2020-9488 
                        │      │                  ├ [49]: https://www.debian.org/security/2021/dsa-5020 
                        │      │                  ├ [50]: https://www.openwall.com/lists/oss-security/2020
                        │      │                  │       /04/25/1 
                        │      │                  ├ [51]: https://www.oracle.com/security-alerts/cpuApr202
                        │      │                  │       1.html 
                        │      │                  ├ [52]: https://www.oracle.com/security-alerts/cpuapr202
                        │      │                  │       2.html 
                        │      │                  ├ [53]: https://www.oracle.com/security-alerts/cpujan202
                        │      │                  │       1.html 
                        │      │                  ├ [54]: https://www.oracle.com/security-alerts/cpujul202
                        │      │                  │       0.html 
                        │      │                  ├ [55]: https://www.oracle.com/security-alerts/cpuoct202
                        │      │                  │       0.html 
                        │      │                  ╰ [56]: https://www.oracle.com/security-alerts/cpuoct202
                        │      │                          1.html 
                        │      ├ PublishedDate   : 2020-04-27T16:15:00Z 
                        │      ╰ LastModifiedDate: 2022-05-12T15:00:00Z 
                        ├ [10] ╭ VulnerabilityID : CVE-2023-34624 
                        │      ├ PkgName         : net.sourceforge.htmlcleaner:htmlcleaner 
                        │      ├ PkgPath         : usr/local/davmail/lib/htmlcleaner-2.21.jar 
                        │      ├ InstalledVersion: 2.21 
                        │      ├ Status          : affected 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-34624 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Maven 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Arevie
                        │      │                          wed+ecosystem%3Amaven 
                        │      ├ Title           : An issue was discovered htmlcleaner thru = 2.28 allows
                        │      │                   attackers to ca ... 
                        │      ├ Description     : An issue was discovered htmlcleaner thru = 2.28 allows
                        │      │                   attackers to cause a denial of service or other unspecified
                        │      │                   impacts via crafted object that uses cyclic
                        │      │                   dependencies. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-787 
                        │      ├ CVSS             ╭ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/
                        │      │                  │      │           I:N/A:H 
                        │      │                  │      ╰ V3Score : 7.5 
                        │      │                  ╰ nvd  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/
                        │      │                         │           I:N/A:H 
                        │      │                         ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://github.com/advisories/GHSA-jv4x-j47q-6qvp 
                        │      │                  ├ [1]: https://github.com/amplafi/htmlcleaner/issues/13 
                        │      │                  ├ [2]: https://lists.debian.org/debian-lts-announce/2023
                        │      │                  │      /08/msg00007.html 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2023-34624 
                        │      │                  ╰ [4]: https://www.debian.org/security/2023/dsa-5471 
                        │      ├ PublishedDate   : 2023-06-14T14:15:00Z 
                        │      ╰ LastModifiedDate: 2023-08-08T04:15:00Z 
                        ├ [11] ╭ VulnerabilityID : CVE-2020-13956 
                        │      ├ PkgName         : org.apache.httpcomponents:httpclient 
                        │      ├ PkgPath         : usr/local/davmail/lib/httpclient-4.5.6.jar 
                        │      ├ InstalledVersion: 4.5.6 
                        │      ├ FixedVersion    : 4.5.13 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                        │      │                  │         d9fd1d00a6086ecc983755bef 
                        │      │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                        │      │                            dd5b3d6b6f229dd57b6d13ffb 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-13956 
                        │      ├ DataSource       ╭ ID  : glad 
                        │      │                  ├ Name: GitLab Advisory Database Community 
                        │      │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                        │      ├ Title           : incorrect handling of malformed authority component in
                        │      │                   request URIs 
                        │      ├ Description     : Apache HttpClient versions prior to version 4.5.13 and
                        │      │                   5.0.3 can misinterpret malformed authority component in
                        │      │                   request URIs passed to the library as java.net.URI object
                        │      │                   and pick the wrong target host for request
                        │      │                   execution. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           N/I:L/A:N 
                        │      │                  │        ╰ V3Score : 5.3 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:N/C:N/I:P/A:N 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                  │        │           N/I:L/A:N 
                        │      │                  │        ├ V2Score : 5 
                        │      │                  │        ╰ V3Score : 5.3 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                        │      │                           │           N/I:L/A:N 
                        │      │                           ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-13956 
                        │      │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=1886587 
                        │      │                  ├ [2] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=C
                        │      │                  │       VE-2020-13956 
                        │      │                  ├ [3] : https://errata.almalinux.org/8/ALSA-2022-1861.html 
                        │      │                  ├ [4] : https://github.com/advisories/GHSA-7r82-7xv7-xcpj 
                        │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-13956.html 
                        │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2022-1861.html 
                        │      │                  ├ [7] : https://lists.apache.org/thread.html/r03bbc318c8
                        │      │                  │       1be21f5c8a9b85e34f2ecc741aa804a8e43b0ef2c37749@%3Ciss
                        │      │                  │       ues.maven.apache.org%3E 
                        │      │                  ├ [8] : https://lists.apache.org/thread.html/r043a75acde
                        │      │                  │       b52b15dd5e9524cdadef4202e6a5228644206acf9363f9@%3Cdev
                        │      │                  │       .hive.apache.org%3E 
                        │      │                  ├ [9] : https://lists.apache.org/thread.html/r06cf3ca5c8
                        │      │                  │       ceb94b39cd24a73d4e96153b485a7dac88444dd876accb@%3Ciss
                        │      │                  │       ues.drill.apache.org%3E 
                        │      │                  ├ [10]: https://lists.apache.org/thread.html/r0a75b8f0f7
                        │      │                  │       2f3e18442dc56d33f3827b905f2fe5b7ba48997436f5d1@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [11]: https://lists.apache.org/thread.html/r0bebe6f980
                        │      │                  │       8ac7bdf572873b4fa96a29c6398c90dab29f131f3ebffe@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [12]: https://lists.apache.org/thread.html/r12cb62751b
                        │      │                  │       35bdcda0ae2a08b67877d665a1f4d41eee0fa7367169e0@%3Cdev
                        │      │                  │       .ranger.apache.org%3E 
                        │      │                  ├ [13]: https://lists.apache.org/thread.html/r132e4c6a56
                        │      │                  │       0cfc519caa1aaee63bdd4036327610eadbd89f76dd5457@%3Cdev
                        │      │                  │       .creadur.apache.org%3E 
                        │      │                  ├ [14]: https://lists.apache.org/thread.html/r2835543ef0
                        │      │                  │       f91adcc47da72389b816e36936f584c7be584d2314fac3@%3Ciss
                        │      │                  │       ues.lucene.apache.org%3E 
                        │      │                  ├ [15]: https://lists.apache.org/thread.html/r2a03dc2102
                        │      │                  │       31d7e852ef73015f71792ac0fcaca6cccc024c522ef17d@%3Ccom
                        │      │                  │       mits.creadur.apache.org%3E 
                        │      │                  ├ [16]: https://lists.apache.org/thread.html/r2dc7930b43
                        │      │                  │       eadc78220d269b79e13ecd387e4bee52db67b2f47d4303@%3Cgit
                        │      │                  │       box.hive.apache.org%3E 
                        │      │                  ├ [17]: https://lists.apache.org/thread.html/r34178ab6ef
                        │      │                  │       106bc940665fd3f4ba5026fac3603b3fa2aefafa0b619d@%3Cdev
                        │      │                  │       .ranger.apache.org%3E 
                        │      │                  ├ [18]: https://lists.apache.org/thread.html/r34efec51cb
                        │      │                  │       817397ccf9f86e25a75676d435ba5f83ee7b2eabdad707@%3Ccom
                        │      │                  │       mits.creadur.apache.org%3E 
                        │      │                  ├ [19]: https://lists.apache.org/thread.html/r3cecd59fba
                        │      │                  │       74404cbf4eb430135e1080897fb376f111406a78bed13a@%3Ciss
                        │      │                  │       ues.lucene.apache.org%3E 
                        │      │                  ├ [20]: https://lists.apache.org/thread.html/r3f740e4c38
                        │      │                  │       bba1face49078aa5cbeeb558c27be601cc9712ad2dcd1e@%3Ccom
                        │      │                  │       mits.creadur.apache.org%3E 
                        │      │                  ├ [21]: https://lists.apache.org/thread.html/r4850b3fbae
                        │      │                  │       a02fde2886e461005e4af8d37c80a48b3ce2a6edca0e30@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [22]: https://lists.apache.org/thread.html/r549ac8c159
                        │      │                  │       bf0c568c19670bedeb8d7c0074beded951d34b1c1d0d05@%3Cdev
                        │      │                  │       .drill.apache.org%3E 
                        │      │                  ├ [23]: https://lists.apache.org/thread.html/r55b2a1d1e9
                        │      │                  │       b1ec9db792b93da8f0f99a4fd5a5310b02673359d9b4d1@%3Cdev
                        │      │                  │       .drill.apache.org%3E 
                        │      │                  ├ [24]: https://lists.apache.org/thread.html/r5b55f65c12
                        │      │                  │       3a7481104d663a915ec45a0d103e6aaa03f42ed1c07a89@%3Cdev
                        │      │                  │       .jackrabbit.apache.org%3E 
                        │      │                  ├ [25]: https://lists.apache.org/thread.html/r5de3d3808e
                        │      │                  │       7b5028df966e45115e006456c4e8931dc1e29036f17927@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [26]: https://lists.apache.org/thread.html/r5fec9c1d67
                        │      │                  │       f928179adf484b01e7becd7c0a6fdfe3a08f92ea743b90@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [27]: https://lists.apache.org/thread.html/r63296c45d5
                        │      │                  │       d84447babaf39bd1487329d8a80d8d563e67a4b6f3d8a7@%3Cdev
                        │      │                  │       .ranger.apache.org%3E 
                        │      │                  ├ [28]: https://lists.apache.org/thread.html/r69a94e2f30
                        │      │                  │       2d1b778bdfefe90fcb4b8c50b226438c3c8c1d0de85a19@%3Cdev
                        │      │                  │       .ranger.apache.org%3E 
                        │      │                  ├ [29]: https://lists.apache.org/thread.html/r6a3cda38d0
                        │      │                  │       50ebe13c1bc9a28d0a8ec38945095d07eca49046bcb89f@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [30]: https://lists.apache.org/thread.html/r6d672b4662
                        │      │                  │       2842e565e00f6ef6bef83eb55d8792aac2bee75bff9a2a@%3Ciss
                        │      │                  │       ues.lucene.apache.org%3E 
                        │      │                  ├ [31]: https://lists.apache.org/thread.html/r6dab7da30f
                        │      │                  │       8bf075f79ee189e33b45a197502e2676481bb8787fc0d7%40%3Cd
                        │      │                  │       ev.hc.apache.org%3E 
                        │      │                  ├ [32]: https://lists.apache.org/thread.html/r6eb2dae157
                        │      │                  │       dbc9af1f30d1f64e9c60d4ebef618f3dce4a0e32d6ea4d@%3Ccom
                        │      │                  │       mits.drill.apache.org%3E 
                        │      │                  ├ [33]: https://lists.apache.org/thread.html/r70c4299231
                        │      │                  │       00c5a4fae8e5bc71c8a2d39af3de4888f50a0ac3755e6f@%3Ccom
                        │      │                  │       mits.creadur.apache.org%3E 
                        │      │                  ├ [34]: https://lists.apache.org/thread.html/r87ddc09295
                        │      │                  │       c27f25471269ad0a79433a91224045988b88f0413a97ec@%3Ciss
                        │      │                  │       ues.bookkeeper.apache.org%3E 
                        │      │                  ├ [35]: https://lists.apache.org/thread.html/r8aa1e5c343
                        │      │                  │       b89aec5b69961471950e862f15246cb6392910161c389b@%3Ciss
                        │      │                  │       ues.maven.apache.org%3E 
                        │      │                  ├ [36]: https://lists.apache.org/thread.html/r9e52a6c72c
                        │      │                  │       8365000ecd035e48cc9fee5a677a150350d4420c46443d@%3Cdev
                        │      │                  │       .drill.apache.org%3E 
                        │      │                  ├ [37]: https://lists.apache.org/thread.html/ra539f20ef0
                        │      │                  │       fb0c27ee39945b5f56bf162e5c13d1c60f7344dab8de3b@%3Ciss
                        │      │                  │       ues.maven.apache.org%3E 
                        │      │                  ├ [38]: https://lists.apache.org/thread.html/ra8bc6b61c5
                        │      │                  │       df301a6fe5a716315528ecd17ccb8a7f907e24a47a1a5e@%3Ciss
                        │      │                  │       ues.lucene.apache.org%3E 
                        │      │                  ├ [39]: https://lists.apache.org/thread.html/rad62221341
                        │      │                  │       83046f3928f733bf680919e0c390739bfbfe6c90049673@%3Ciss
                        │      │                  │       ues.drill.apache.org%3E 
                        │      │                  ├ [40]: https://lists.apache.org/thread.html/rae14ae25ff
                        │      │                  │       4a60251e3ba2629c082c5ba3851dfd4d21218b99b56652@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [41]: https://lists.apache.org/thread.html/rb33212dab7
                        │      │                  │       beccaf1ffef9b88610047c644f644c7a0ebdc44d77e381@%3Ccom
                        │      │                  │       mits.turbine.apache.org%3E 
                        │      │                  ├ [42]: https://lists.apache.org/thread.html/rb4ba262d6f
                        │      │                  │       08ab9cf8b1ebbcd9b00b0368ffe90dad7ad7918b4b56fc@%3Cdev
                        │      │                  │       .drill.apache.org%3E 
                        │      │                  ├ [43]: https://lists.apache.org/thread.html/rb725052404
                        │      │                  │       fabffbe093c83b2c46f3f87e12c3193a82379afbc529f8@%3Csol
                        │      │                  │       r-user.lucene.apache.org%3E 
                        │      │                  ├ [44]: https://lists.apache.org/thread.html/rc0863892cc
                        │      │                  │       fd9fd0d0ae10091f24ee769fb39b8957fe4ebabfc11f17@%3Cdev
                        │      │                  │       .jackrabbit.apache.org%3E 
                        │      │                  ├ [45]: https://lists.apache.org/thread.html/rc3739e0ad4
                        │      │                  │       bcf1888c6925233bfc37dd71156bbc8416604833095c42@%3Cdev
                        │      │                  │       .drill.apache.org%3E 
                        │      │                  ├ [46]: https://lists.apache.org/thread.html/rc505fee574
                        │      │                  │       fe8d18f9b0c655a4d120b0ae21bb6a73b96003e1d9be35@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [47]: https://lists.apache.org/thread.html/rc5c6ccb86d
                        │      │                  │       2afe46bbd4b71573f0448dc1f87bbcd5a0d8c7f8f904b2@%3Ciss
                        │      │                  │       ues.lucene.apache.org%3E 
                        │      │                  ├ [48]: https://lists.apache.org/thread.html/rc990e2462e
                        │      │                  │       c32b09523deafb2c73606208599e196fa2d7f50bdbc587@%3Ciss
                        │      │                  │       ues.maven.apache.org%3E 
                        │      │                  ├ [49]: https://lists.apache.org/thread.html/rcced7ed323
                        │      │                  │       7c29cd19c1e9bf465d0038b8b2e967b99fc283db7ca553@%3Cdev
                        │      │                  │       .ranger.apache.org%3E 
                        │      │                  ├ [50]: https://lists.apache.org/thread.html/rcd9ad5dda6
                        │      │                  │       0c82ab0d0c9bd3e9cb1dc740804451fc20c7f451ef5cc4@%3Cgit
                        │      │                  │       box.hive.apache.org%3E 
                        │      │                  ├ [51]: https://lists.apache.org/thread.html/rd0e44e8ef7
                        │      │                  │       1eeaaa3cf3d1b8b41eb25894372e2995ec908ce7624d26@%3Ccom
                        │      │                  │       mits.pulsar.apache.org%3E 
                        │      │                  ├ [52]: https://lists.apache.org/thread.html/rd5ab56beb2
                        │      │                  │       ac6879f6ab427bc4e5f7691aed8362d17b713f61779858@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [53]: https://lists.apache.org/thread.html/re504acd4d6
                        │      │                  │       3b8df2a7353658f45c9a3137e5f80e41cf7de50058b2c1@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [54]: https://lists.apache.org/thread.html/rea3dbf633d
                        │      │                  │       de5008d38bf6600a3738b9216e733e03f9ff7becf79625@%3Ciss
                        │      │                  │       ues.drill.apache.org%3E 
                        │      │                  ├ [55]: https://lists.apache.org/thread.html/ree942561f4
                        │      │                  │       620313c75982a4e5f3b74fe6f7062b073210779648eec2@%3Ciss
                        │      │                  │       ues.lucene.apache.org%3E 
                        │      │                  ├ [56]: https://lists.apache.org/thread.html/reef569c241
                        │      │                  │       9705754a3acf42b5f19b2a158153cef0e448158bc54917@%3Cdev
                        │      │                  │       .drill.apache.org%3E 
                        │      │                  ├ [57]: https://lists.apache.org/thread.html/rf03228972e
                        │      │                  │       56cb4a03e6d9558188c2938078cf3ceb23a3fead87c9ca@%3Ciss
                        │      │                  │       ues.bookkeeper.apache.org%3E 
                        │      │                  ├ [58]: https://lists.apache.org/thread.html/rf43d17ed0d
                        │      │                  │       1fb4fb79036b582810ef60b18b1ef3add0d5dea825af1e@%3Ciss
                        │      │                  │       ues.lucene.apache.org%3E 
                        │      │                  ├ [59]: https://lists.apache.org/thread.html/rf4db88c22e
                        │      │                  │       1be9eb60c7dc623d0528642c045fb196a24774ac2fa3a3@%3Ciss
                        │      │                  │       ues.lucene.apache.org%3E 
                        │      │                  ├ [60]: https://lists.apache.org/thread.html/rf7ca60f78f
                        │      │                  │       05b772cc07d27e31bcd112f9910a05caf9095e38ee150f@%3Cdev
                        │      │                  │       .ranger.apache.org%3E 
                        │      │                  ├ [61]: https://lists.apache.org/thread.html/rfb35f6db9b
                        │      │                  │       a1f1e061b63769a4eff5abadcc254ebfefc280e5a0dcf1@%3Ccom
                        │      │                  │       mits.creadur.apache.org%3E 
                        │      │                  ├ [62]: https://lists.apache.org/thread.html/rfbedcb586a
                        │      │                  │       1e7dfce87ee03c720e583fc2ceeafa05f35c542cecc624@%3Ciss
                        │      │                  │       ues.solr.apache.org%3E 
                        │      │                  ├ [63]: https://lists.apache.org/thread.html/rfc00884c7b
                        │      │                  │       7ca878297bffe45fcb742c362b00b26ba37070706d44c3@%3Ciss
                        │      │                  │       ues.hive.apache.org%3E 
                        │      │                  ├ [64]: https://nvd.nist.gov/vuln/detail/CVE-2020-13956 
                        │      │                  ├ [65]: https://security.netapp.com/advisory/ntap-202202
                        │      │                  │       10-0002/ 
                        │      │                  ├ [66]: https://www.cve.org/CVERecord?id=CVE-2020-13956 
                        │      │                  ├ [67]: https://www.openwall.com/lists/oss-security/2020
                        │      │                  │       /10/08/4 
                        │      │                  ├ [68]: https://www.oracle.com//security-alerts/cpujul20
                        │      │                  │       21.html 
                        │      │                  ├ [69]: https://www.oracle.com/security-alerts/cpuApr202
                        │      │                  │       1.html 
                        │      │                  ├ [70]: https://www.oracle.com/security-alerts/cpuapr202
                        │      │                  │       2.html 
                        │      │                  ├ [71]: https://www.oracle.com/security-alerts/cpujan202
                        │      │                  │       2.html 
                        │      │                  ╰ [72]: https://www.oracle.com/security-alerts/cpuoct202
                        │      │                          1.html 
                        │      ├ PublishedDate   : 2020-12-02T17:15:00Z 
                        │      ╰ LastModifiedDate: 2022-05-12T14:47:00Z 
                        ╰ [12] ╭ VulnerabilityID : CVE-2023-1436 
                               ├ PkgName         : org.codehaus.jettison:jettison 
                               ├ PkgPath         : usr/local/davmail/lib/jettison-1.5.3.jar 
                               ├ InstalledVersion: 1.5.3 
                               ├ FixedVersion    : 1.5.4 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:e85880bab4142286c5858f9da2293065c5c14b2
                               │                  │         d9fd1d00a6086ecc983755bef 
                               │                  ╰ DiffID: sha256:fcffa16c9914a7bced14daedc492c7d32fafca8
                               │                            dd5b3d6b6f229dd57b6d13ffb 
                               ├ SeveritySource  : nvd 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-1436 
                               ├ DataSource       ╭ ID  : glad 
                               │                  ├ Name: GitLab Advisory Database Community 
                               │                  ╰ URL : https://gitlab.com/gitlab-org/advisories-community 
                               ├ Title           : Uncontrolled Recursion in JSONArray 
                               ├ Description     : An infinite recursion is triggered in Jettison when
                               │                   constructing a JSONArray from a Collection that contains a
                               │                   self-reference in one of its elements. This leads to a
                               │                   StackOverflowError exception being thrown. 
                               ├ Severity        : HIGH 
                               ├ CweIDs           ─ [0]: CWE-674 
                               ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                               │                  │        │           N/I:N/A:H 
                               │                  │        ╰ V3Score : 7.5 
                               │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                               │                  │        │           N/I:N/A:H 
                               │                  │        ╰ V3Score : 7.5 
                               │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:
                               │                           │           N/I:N/A:H 
                               │                           ╰ V3Score : 7.5 
                               ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-1436 
                               │                  ├ [1]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CV
                               │                  │      E-2023-1436 
                               │                  ├ [2]: https://github.com/advisories/GHSA-q6g2-g7f3-rr83 
                               │                  ├ [3]: https://github.com/jettison-json/jettison/issues/60 
                               │                  ├ [4]: https://github.com/jettison-json/jettison/pull/62 
                               │                  ├ [5]: https://github.com/jettison-json/jettison/release
                               │                  │      s/tag/jettison-1.5.4 
                               │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2023-1436 
                               │                  ├ [7]: https://research.jfrog.com/vulnerabilities/jettis
                               │                  │      on-json-array-dos-xray-427911/ 
                               │                  ├ [8]: https://ubuntu.com/security/notices/USN-6179-1 
                               │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2023-1436 
                               ├ PublishedDate   : 2023-03-22T06:15:00Z 
                               ╰ LastModifiedDate: 2023-03-29T19:07:00Z 
````

# Changelog

## [1.6.0](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.5.0...v1.6.0) (2026-08-31)


### Features

* allow presentation of invalid credentials to test error cases ([b1b452a](https://github.com/ba-itsys/eudi-wallet-simulator/commit/b1b452a72d9ee84ed5ebe1bc9cfefaebf7a17c05))

## [1.5.0](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.4.1...v1.5.0) (2026-08-27)


### Features

* show the sent dcql query in a collapsible debug pane on the consent ui ([18e20cf](https://github.com/ba-itsys/eudi-wallet-simulator/commit/18e20cf49a5805c08811b40aceaf94f33bae0604))
* support request_uri_method=post with encrypted request objects ([d92dc2c](https://github.com/ba-itsys/eudi-wallet-simulator/commit/d92dc2c644cb22f81026be121e88c35bae088257))

## [1.4.1](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.4.0...v1.4.1) (2026-08-24)


### Bug Fixes

* add baseurl+path to all url references (statuslist, registrar) ([f14072b](https://github.com/ba-itsys/eudi-wallet-simulator/commit/f14072bf6376e9538c7df144cf5be2187486fce0))

## [1.4.0](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.3.0...v1.4.0) (2026-08-24)


### Features

* allow insecure-tls ([c1f4641](https://github.com/ba-itsys/eudi-wallet-simulator/commit/c1f4641bb0a52c67282962670185f06959d42641))

## [1.3.0](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.2.3...v1.3.0) (2026-08-21)


### Features

* add proxy support for backend calls ([c2b0cd4](https://github.com/ba-itsys/eudi-wallet-simulator/commit/c2b0cd44736710098ebab42af9a115750dfefcf4))

## [1.2.3](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.2.2...v1.2.3) (2026-08-21)


### Bug Fixes

* allow empty claims on credential edit ([5c63e9e](https://github.com/ba-itsys/eudi-wallet-simulator/commit/5c63e9e96570d993f4fdb12e8dcc6176cee68478))

## [1.2.2](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.2.1...v1.2.2) (2026-08-20)


### Bug Fixes

* default pids match rulebooks closer ([7120300](https://github.com/ba-itsys/eudi-wallet-simulator/commit/7120300a57992d11aa6cb3309a240dc8c4760c7d))

## [1.2.1](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.2.0...v1.2.1) (2026-08-18)


### Bug Fixes

* carry the registration certificate as a compact jwt in verifier_info ([a198254](https://github.com/ba-itsys/eudi-wallet-simulator/commit/a198254ad7670667f5bda5892c5e42a71eabaa2a))
* keep every credential edited during a presentation flow ([8cc1a6c](https://github.com/ba-itsys/eudi-wallet-simulator/commit/8cc1a6c8495540a46f9dd7cb1cb635408719485d))


### Documentation

* cover trust scoping, structured claims and login timeouts in the example ([ec9de68](https://github.com/ba-itsys/eudi-wallet-simulator/commit/ec9de68374b36813e60d0a133efec7452589ba50))

## [1.2.0](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.1.0...v1.2.0) (2026-08-17)


### Features

* update the keycloak example to extension 0.9.1 with aki trusted authorities ([809b347](https://github.com/ba-itsys/eudi-wallet-simulator/commit/809b3472a214046228a9bc9a64e3e9f3e6fa7ad8))


### Bug Fixes

* keep the picker selection and the chosen alternative across the edit round trip ([1fcae06](https://github.com/ba-itsys/eudi-wallet-simulator/commit/1fcae0612c575b5778008cb2915f62269ae67c5e))

## [1.1.0](https://github.com/ba-itsys/eudi-wallet-simulator/compare/v1.0.0...v1.1.0) (2026-08-17)


### Features

* derive the pki from a configured seed for stateless deployments ([fe2150d](https://github.com/ba-itsys/eudi-wallet-simulator/commit/fe2150d0abe50a614e41a9e565ce0bbb4d0b3c52))
* update the keycloak example to extension 0.9.0 ([fdde421](https://github.com/ba-itsys/eudi-wallet-simulator/commit/fdde42171fb71226d01c4bda79979889d23e0fc9))

## 1.0.0 (2026-08-17)


### Features

* add ci workflow, readme and cancel flow coverage ([10eaf53](https://github.com/ba-itsys/eudi-wallet-simulator/commit/10eaf53046fac873ddc95dcd9a0d6fd082d367ec))
* add conformance validation with strict and debug modes and encrypted responses ([af1488e](https://github.com/ba-itsys/eudi-wallet-simulator/commit/af1488e8e51c43a00909ef7ec6c4f786a2a945e7))
* add edit-and-present during verification with per-credential binding keys ([867aed7](https://github.com/ba-itsys/eudi-wallet-simulator/commit/867aed77683c4c43b8f8a1ec6a3a06eb4e3f1681))
* add etsi trust lists, token status list and revocation api ([bef563e](https://github.com/ba-itsys/eudi-wallet-simulator/commit/bef563e8d1f30e506e6b56625dc1503640dcc80d))
* add keycloak example with haip realm, setup script and smoke test ([2c03abe](https://github.com/ba-itsys/eudi-wallet-simulator/commit/2c03abe82825cdd40bd70e5fffaffd8e4c2a7a7d))
* add non pid credential, credential set demo and ui polish ([74826ef](https://github.com/ba-itsys/eudi-wallet-simulator/commit/74826eff4b17bb1ac805456dda5a36b9c8977b7d))
* add oid4vp presentation flow with credential picker and direct_post ([3f16145](https://github.com/ba-itsys/eudi-wallet-simulator/commit/3f161456d212378142540c88ab5a670c6fa86462))
* add pki, credential store with yaml seed and sd-jwt vc issuance ([e79858e](https://github.com/ba-itsys/eudi-wallet-simulator/commit/e79858e521af102855836662118f34bf346fe1d3))
* add registrar with verifier_info validation, persistent pki and x509_hash-only client ids ([416f2b9](https://github.com/ba-itsys/eudi-wallet-simulator/commit/416f2b9b43c0a265c49253a4740edf188558824b))
* add spring boot skeleton with ui shell and health probes ([801c4a7](https://github.com/ba-itsys/eudi-wallet-simulator/commit/801c4a74d8a7aeb4da7198082569d72f6d97477a))
* add trusted authorities, claim and credential sets and spec error responses ([1cd5356](https://github.com/ba-itsys/eudi-wallet-simulator/commit/1cd535685981f5630d067d156a8e1be2947eb570))
* add vct inheritance with simplified urn child rule and per country test data ([7ad0c19](https://github.com/ba-itsys/eudi-wallet-simulator/commit/7ad0c1939970c9926da6de5d075db16404d83a9f))
* add wallet attestation and pop issuance endpoint ([a1bbb9c](https://github.com/ba-itsys/eudi-wallet-simulator/commit/a1bbb9c806961ea02f3a89a932959d2d50746218))
* add wallet overview with ad-hoc credential creation and revocation ui ([203dc7f](https://github.com/ba-itsys/eudi-wallet-simulator/commit/203dc7fe63585ace3ac9a2c3b12894560a78bb95))
* align default credentials with the eudi pid rulebook ([0e83076](https://github.com/ba-itsys/eudi-wallet-simulator/commit/0e83076f871aedf588408f048874ff81cd183c28))
* configurable always disclosed claims and user chosen claim and credential sets ([01cd960](https://github.com/ba-itsys/eudi-wallet-simulator/commit/01cd9601736e416c7ddc0cbc1adb3baca860727e))
* demo requests pid with optional ehic via credential sets and trusted authorities ([fb9160a](https://github.com/ba-itsys/eudi-wallet-simulator/commit/fb9160afd590d958812120e772a446797edbb479))
* edit nested claims as dot notation fields ([6d36f54](https://github.com/ba-itsys/eudi-wallet-simulator/commit/6d36f54d46b5ec976b2e474d96437cca0b820516))
* inherit id and status list slot when modifying a credential for a presentation ([2782c05](https://github.com/ba-itsys/eudi-wallet-simulator/commit/2782c059469facdc5f31c2be599d1cfca647da1f))
* issue credentials during a presentation for that presentation only ([d3cb2fe](https://github.com/ba-itsys/eudi-wallet-simulator/commit/d3cb2feff3f002fcffcef9061e435f35a0445624))
* registrar_dataset verifier_info format and user selectable credential set options ([17a58a4](https://github.com/ba-itsys/eudi-wallet-simulator/commit/17a58a42458937138c5ff1445bb8b3057da2b051))
* replace json claims editor with per-claim fields and stable automation ids ([7700d93](https://github.com/ba-itsys/eudi-wallet-simulator/commit/7700d9391668445488611d3287296886e68af7e7))
* support adding and removing claims in the edit form ([d1aa141](https://github.com/ba-itsys/eudi-wallet-simulator/commit/d1aa1414caee2fb1736c043541859a0b6b5785e6))
* switch alternatives and claim sets to dropdowns with dynamic rows ([6b6ca14](https://github.com/ba-itsys/eudi-wallet-simulator/commit/6b6ca14cb313cc2bb0e6256df6c828c9825a8305))


### Bug Fixes

* correct dcql claims semantics, jwe payload typing and add missing conformance checks ([71e1a7e](https://github.com/ba-itsys/eudi-wallet-simulator/commit/71e1a7eed506025af08cb5fe96ff27029bf1bee1))
* enable release-please workflow ([21d81a8](https://github.com/ba-itsys/eudi-wallet-simulator/commit/21d81a89c33efdce17dd9fe7937263928ca65893))
* revoke from the ui through the credentials status api ([cc0410a](https://github.com/ba-itsys/eudi-wallet-simulator/commit/cc0410a22f01fdefa584223e556be337a57b1cec))
* verifier_info/registration cert fixed according to EUDI ARF ([f744abb](https://github.com/ba-itsys/eudi-wallet-simulator/commit/f744abbe4c2b290d7d3fc2cc0e5d7d0db9ff86e6))


### Documentation

* document key material files and kubernetes secret setup ([1c50ee5](https://github.com/ba-itsys/eudi-wallet-simulator/commit/1c50ee59eb8002c80094538ca4d2909260d4ed01))
* explain the serialized verifier_info configuration value ([02f61f5](https://github.com/ba-itsys/eudi-wallet-simulator/commit/02f61f52306041c7941c16790b893172fd0e5940))
* explain why master realm ssl config needs kcadm instead of realm import ([94055e6](https://github.com/ba-itsys/eudi-wallet-simulator/commit/94055e6ff5f905f318ee540bbe75d75517e4afed))

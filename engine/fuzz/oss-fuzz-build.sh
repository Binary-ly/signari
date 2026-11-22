#!/bin/bash -eu
# Builds every native Go fuzz target in the engine for OSS-Fuzz (or ClusterFuzzLite),
# whose build image provides compile_native_go_fuzzer. One line per target, named
# <package>_<target>; TestEveryFuzzTargetIsBuiltForOSSFuzz (internal/docsync) fails
# when a target is missing here or a line names one that no longer exists.
# docs/fuzzing.md says how it is run and what to submit.
cd "$SRC/signari/engine"

compile_native_go_fuzzer signari.dev/engine/internal/authzen FuzzDecode authzen_decode
compile_native_go_fuzzer signari.dev/engine/internal/clientip FuzzClientIP clientip_client_ip
compile_native_go_fuzzer signari.dev/engine/internal/dpop FuzzVerify dpop_verify
compile_native_go_fuzzer signari.dev/engine/internal/jsonstrict FuzzNoDuplicateKeys jsonstrict_no_duplicate_keys
compile_native_go_fuzzer signari.dev/engine/internal/ldapd FuzzDecodeFilter ldapd_decode_filter
compile_native_go_fuzzer signari.dev/engine/internal/oauth FuzzValidateAuthz oauth_validate_authz
compile_native_go_fuzzer signari.dev/engine/internal/oauth FuzzVerifyPKCE oauth_verify_pkce
compile_native_go_fuzzer signari.dev/engine/internal/oid4vp FuzzParsePath oid4vp_parse_path
compile_native_go_fuzzer signari.dev/engine/internal/oid4vp FuzzReadDCAPIAnswer oid4vp_read_dcapi_answer
compile_native_go_fuzzer signari.dev/engine/internal/oid4vp FuzzVerifyMdoc oid4vp_verify_mdoc
compile_native_go_fuzzer signari.dev/engine/internal/oidfed FuzzParseStatement oidfed_parse_statement
compile_native_go_fuzzer signari.dev/engine/internal/proxyproto FuzzRead proxyproto_read
compile_native_go_fuzzer signari.dev/engine/internal/radius FuzzDecode radius_decode
compile_native_go_fuzzer signari.dev/engine/internal/radius FuzzDecodeEAP radius_decode_eap
compile_native_go_fuzzer signari.dev/engine/internal/rar FuzzParse rar_parse
compile_native_go_fuzzer signari.dev/engine/internal/saml FuzzUnmarshal saml_unmarshal
compile_native_go_fuzzer signari.dev/engine/internal/scim FuzzParseListFilter scim_parse_list_filter
compile_native_go_fuzzer signari.dev/engine/internal/scim FuzzParsePath scim_parse_path
compile_native_go_fuzzer signari.dev/engine/internal/sdjwt FuzzParse sdjwt_parse
compile_native_go_fuzzer signari.dev/engine/internal/tokens FuzzVerifyAccessToken tokens_verify_access_token
compile_native_go_fuzzer signari.dev/engine/internal/uma FuzzParseResourceDescription uma_parse_resource_description
compile_native_go_fuzzer signari.dev/engine/internal/uma FuzzParseScope uma_parse_scope

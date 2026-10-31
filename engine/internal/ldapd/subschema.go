package ldapd

import "net"

// subschemaDN is the one subschema entry, named by the root DSE, so a client
// that reads a directory's schema before using it finds the truth of this one.
const subschemaDN = "cn=Subschema"

// The definitions are OpenLDAP's, from its core.schema, cosine.schema and
// inetorgperson.schema, with one change: SINGLE-VALUE where schema.go says this
// directory holds one value. A client told an attribute is multi-valued here
// would send a second value and be refused.
var (
	subschemaAttributeTypes = []string{
		"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name SINGLE-VALUE )",
		"( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name SINGLE-VALUE )",
		"( 2.5.4.42 NAME ( 'givenName' 'gn' ) SUP name SINGLE-VALUE )",
		"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )",
		"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) EQUALITY caseIgnoreIA5Match " +
			"SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} SINGLE-VALUE )",
		"( 2.16.840.1.113730.3.1.241 NAME 'displayName' EQUALITY caseIgnoreMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} SINGLE-VALUE )",
		"( 1.2.840.113556.1.2.102 NAME 'memberOf' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION USAGE directoryOperation )",
		"( 2.5.4.49 NAME 'distinguishedName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 2.5.4.31 NAME 'member' SUP distinguishedName )",
		"( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' ) SUP name )",
	}
	subschemaObjectClasses = []string{
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY userPassword )",
		"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL )",
		"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL " +
			"MAY ( displayName $ givenName $ mail $ uid ) )",
		"( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) )",
		"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou )",
	}
	subschemaSyntaxes = []string{
		"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'Distinguished Name' )",
		"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
		"( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )",
	}
)

// writeSubschema answers a base-object search of the subschema entry. It says
// nothing of who is in the directory, so like the root DSE it needs no bind: a
// client may read it to decide how to bind.
func (s *Server) writeSubschema(c net.Conn, messageID int64, req *searchRequest) bool {
	e := &entry{DN: subschemaDN, Attrs: map[string][]string{
		"objectClass":    {"top", "subschema"},
		"cn":             {"Subschema"},
		"attributeTypes": subschemaAttributeTypes,
		"objectClasses":  subschemaObjectClasses,
		"ldapSyntaxes":   subschemaSyntaxes,
	}}
	if req.Filter.Matches(e) {
		// These are operational attributes, so a client asks for them by name or
		// with `+`, and it means every one.
		attrs := req.Attrs
		for _, a := range attrs {
			if a == "+" {
				attrs = nil
				break
			}
		}
		if !s.write(c, newMessage(messageID, newSearchEntry(e, attrs, req.TypesOnly))) {
			return false
		}
	}
	return s.write(c, newMessage(messageID, newResult(appSearchResultDone, resultSuccess, "", "")))
}

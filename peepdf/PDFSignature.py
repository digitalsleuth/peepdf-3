#    peepdf-3 is a tool to analyse and modify PDF files
#    https://github.com/digitalsleuth/peepdf-3
#    Original Author: Jose Miguel Esparza <jesparza AT eternal-todo.com>
#    Updated for Python 3 by Corey Forman (digitalsleuth - https://github.com/digitalsleuth/peepdf-3)
#    Copyright (C) 2011-2017 Jose Miguel Esparza
#
#    This file is part of peepdf-3.
#
#        peepdf-3 is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf-3 is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf-3. If not, see <http://www.gnu.org/licenses/>.

"""
Digital signature verification: was the signed byte range
altered since signing, and does it verify against the
embedded signer certificate.
"""

import hashlib
import os

from asn1crypto import cms, core, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

try:
    from peepdf.PDFUtils import getBytesFromFile
except ModuleNotFoundError:
    from PDFUtils import getBytesFromFile

SUPPORTED_SUBFILTERS = {
    "adbe.pkcs7.detached",
    "adbe.pkcs7.sha1",
    "adbe.x509.rsa_sha1",
    "ETSI.CAdES.detached",
}

_HASH_CLASSES = {
    "md5": hashes.MD5,
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def _dereference(pdfFile, element, version):
    if element is None or element == []:
        return None
    if element.getType() == "reference":
        # As of 'version', an object not redefined in that revision's body
        # still exists if an earlier revision defined it.
        return pdfFile.getObjectAtVersion(element.getId(), version)
    return element


def _catalogAtVersion(pdfFile, version):
    catalogId = pdfFile.getCatalogObjectId(version)
    if catalogId is None:
        return None
    return pdfFile.getObjectAtVersion(catalogId, version)


def _definingVersion(pdfFile, objectId, upToVersion):
    """
    The revision whose body defines the object as it stands at upToVersion.
    """
    for v in range(upToVersion, -1, -1):
        if objectId in pdfFile.body[v].objects:
            return v
    return None


def _fieldIsSignature(pdfFile, fieldObj, version, depth=0):
    """
    /FT is inheritable via /Parent, per the AcroForm field spec.
    """
    if fieldObj is None or depth > 10:
        return False
    ftElement = fieldObj.getElementByName("/FT")
    if ftElement is not None and ftElement != []:
        return ftElement.getValue() == "/Sig"
    parent = _dereference(pdfFile, fieldObj.getElementByName("/Parent"), version)
    return _fieldIsSignature(pdfFile, parent, version, depth + 1)


def _walkAcroFormFields(pdfFile, version):
    catalog = _catalogAtVersion(pdfFile, version)
    if catalog is None:
        return []
    acroForm = _dereference(pdfFile, catalog.getElementByName("/AcroForm"), version)
    if acroForm is None:
        return []
    fields = _dereference(pdfFile, acroForm.getElementByName("/Fields"), version)
    if fields is None:
        return []

    found = []
    for fieldRef in fields.getElements():
        fieldObj = _dereference(pdfFile, fieldRef, version)
        if not _fieldIsSignature(pdfFile, fieldObj, version):
            continue
        vElement = fieldObj.getElementByName("/V")
        sigDict = _dereference(pdfFile, vElement, version)
        if sigDict is None:
            continue  # unsigned signature field
        nameElement = fieldObj.getElementByName("/T")
        fieldName = (
            nameElement.getValue() if nameElement and nameElement != [] else None
        )
        # The signature dict must be indirect. /ByteRange needs a stable byte
        # offset, so /V is expected to be a reference.
        if vElement.getType() == "reference":
            sigId = vElement.getId()
        elif fieldRef.getType() == "reference":
            sigId = fieldRef.getId()
        else:
            sigId = None
        found.append((sigId, fieldName, sigDict))
    return found


def _walkPermsSignatures(pdfFile, version, skipIds):
    """
    /Perms held in the catalog
    /DocMDP (a certification signature)
    /UR3 and /UR (Adobe Reader Extensions usage rights)
    """
    catalog = _catalogAtVersion(pdfFile, version)
    if catalog is None:
        return []
    perms = _dereference(pdfFile, catalog.getElementByName("/Perms"), version)
    if perms is None or perms.getType() != "dictionary":
        return []
    catalogId = pdfFile.getCatalogObjectId(version)

    found = []
    for key in ("/DocMDP", "/UR3", "/UR"):
        element = perms.getElementByName(key)
        sigDict = _dereference(pdfFile, element, version)
        if sigDict is None or sigDict.getType() != "dictionary":
            continue
        if element.getType() == "reference":
            if element.getId() in skipIds:
                continue  # already found as a named form field
            sigId = element.getId()
        else:
            sigId = catalogId
        found.append((sigId, f"/Perms {key}", sigDict))
    return found


def findSignatureDictionaries(pdfFile, version):
    """
    Returns a list of (objectId, fieldName_or_None, sigDict) tuples
    """
    found = _walkAcroFormFields(pdfFile, version)
    seenIds = {objId for objId, _fieldName, _sigDict in found}
    for entry in _walkPermsSignatures(pdfFile, version, seenIds):
        found.append(entry)
        seenIds.add(entry[0])

    body = pdfFile.body[version]
    for objId in body.objects:
        if objId in seenIds:
            continue
        indirectObject = body.objects[objId]
        if indirectObject is None:
            continue
        obj = indirectObject.getObject()
        if obj is None or obj.getType() != "dictionary":
            continue
        byteRange = obj.getElementByName("/ByteRange")
        contents = obj.getElementByName("/Contents")
        if byteRange and byteRange != [] and contents and contents != []:
            found.append((objId, None, obj))
            seenIds.add(objId)
    return found


def _extractByteRange(sigDict):
    byteRangeElement = sigDict.getElementByName("/ByteRange")
    if byteRangeElement is None or byteRangeElement == []:
        return None
    values = [element.getRawValue() for element in byteRangeElement.getElements()]
    if len(values) != 4:
        return None
    return values


def _extractContentsBytes(sigDict):
    contentsElement = sigDict.getElementByName("/Contents")
    if contentsElement is None or contentsElement == []:
        return None
    return contentsElement.getValue().encode("latin-1")


def _signerCertificate(signedData, signerInfo):
    sid = signerInfo["sid"]
    if sid.name == "issuer_and_serial_number":
        issuer = sid.chosen["issuer"]
        serialNumber = sid.chosen["serial_number"].native
        for certChoice in signedData["certificates"]:
            cert = certChoice.chosen
            if cert.issuer == issuer and cert.serial_number == serialNumber:
                return cert
    else:  # subject_key_identifier
        ski = sid.chosen.native
        for certChoice in signedData["certificates"]:
            cert = certChoice.chosen
            if cert.key_identifier_value.native == ski:
                return cert
    if len(signedData["certificates"]) == 1:
        return signedData["certificates"][0].chosen
    return None


def _messageDigestAttribute(signedAttrs):
    for attribute in signedAttrs:
        if attribute["type"].native == "message_digest":
            return attribute["values"][0].native
    return None


def _signingTimeAttribute(signedAttrs):
    for attribute in signedAttrs:
        if attribute["type"].native == "signing_time":
            return attribute["values"][0].native
    return None


def _signedAttrsDer(signedAttrs):
    """
    The signature is computed over the DER encoding of signed_attrs as a
    plain SET OF (universal tag 17), not the [0] IMPLICIT encoding used to
    embed it in the SignerInfo.
    https://www.rfc-editor.org/info/rfc5652/#page-43
    https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/setof.html
    """
    retagged = signedAttrs.untag()
    retagged.class_ = 0
    retagged.tag = 17
    return retagged.dump()


def _certificateDetails(certificate):
    """
    Identity fields expected for the signer certificate.
    """
    der = certificate.dump()
    fingerprints = {}
    for name in ("md5", "sha1", "sha256"):
        digest = hashlib.new(name, der).hexdigest().upper()
        fingerprints[name] = ":".join(
            digest[i : i + 2] for i in range(0, len(digest), 2)
        )

    if certificate.serial_number < 0:
        serialHex = (
            certificate["tbs_certificate"]["serial_number"].contents.hex().upper()
        )
    else:
        serialHex = format(certificate.serial_number, "X")
        if len(serialHex) % 2:
            serialHex = "0" + serialHex

    publicKey = certificate.public_key
    publicKeyInfo = {
        "algorithm": publicKey.algorithm.upper(),
        "bits": publicKey.bit_size,
    }
    if publicKey.algorithm == "ec":
        publicKeyInfo["curve"] = publicKey.curve[1]

    return {
        "subject": certificate.subject.human_friendly,
        "issuer": certificate.issuer.human_friendly,
        "not_before": certificate.not_valid_before.isoformat(),
        "not_after": certificate.not_valid_after.isoformat(),
        "self_signed": certificate.subject == certificate.issuer,
        "version": {"v1": 1, "v2": 2, "v3": 3}.get(
            certificate["tbs_certificate"]["version"].native
        ),
        "serial_number": serialHex,
        "serial_number_decimal": str(certificate.serial_number),
        "public_key": publicKeyInfo,
        "signature_algorithm": _certificateSignatureAlgorithm(certificate),
        "fingerprints": fingerprints,
    }


def _embeddedChain(signedData, signerCertificate):
    """
    Every certificate embedded in the CMS blob, ordered leaf to root by
    following issuer links from the signer.
    """
    return _orderChain(
        [choice.chosen for choice in signedData["certificates"]], signerCertificate
    )


def _orderChain(certificates, signerCertificate):
    """
    Leaf-to-root ordering of a list of certificates, starting from the signer.
    """
    remaining = list(certificates)
    ordered = [signerCertificate]
    remaining = [cert for cert in remaining if cert.dump() != signerCertificate.dump()]
    current = signerCertificate
    while current.subject != current.issuer:
        issuer = next(
            (cert for cert in remaining if cert.subject == current.issuer), None
        )
        if issuer is None:
            break
        ordered.append(issuer)
        remaining.remove(issuer)
        current = issuer
    ordered.extend(remaining)

    chain = []
    for cert in ordered:
        entry = _certificateDetails(cert)
        entry["is_signer"] = cert is signerCertificate
        chain.append(entry)
    return chain


def _certificateSignatureAlgorithm(certificate):
    """
    How the issuer signed this certificate.
    """
    nativeName = certificate["signature_algorithm"]["algorithm"].native
    labels = {
        "rsassa_pkcs1v15": "RSA",
        "rsassa_pss": "RSASSA-PSS",
        "ecdsa": "ECDSA",
        "dsa": "DSA",
    }
    try:
        hashAlgo, signatureAlgo = certificate.hash_algo, certificate.signature_algo
    except Exception:
        return nativeName
    if hashAlgo and signatureAlgo in labels:
        return f"{hashAlgo.upper()}with{labels[signatureAlgo]}"
    return nativeName


def _verifySignatureBytes(
    publicKey, signatureBytes, signedBytes, digestAlgo, signatureAlgoNative
):
    hashClass = _HASH_CLASSES.get(digestAlgo)
    if hashClass is None:
        return f"error: unsupported digest algorithm '{digestAlgo}'"
    algorithm = hashClass()
    try:
        if "ecdsa" in signatureAlgoNative:
            publicKey.verify(signatureBytes, signedBytes, ec.ECDSA(algorithm))
        elif "pss" in signatureAlgoNative:
            publicKey.verify(
                signatureBytes,
                signedBytes,
                padding.PSS(
                    mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size
                ),
                algorithm,
            )
        elif "rsa" in signatureAlgoNative:
            publicKey.verify(signatureBytes, signedBytes, padding.PKCS1v15(), algorithm)
        else:
            return f"error: unsupported signature algorithm '{signatureAlgoNative}'"
    except InvalidSignature:
        return "invalid"
    except Exception as exc:  # malformed key/signature data, wrong padding, etc.
        return f"error: {exc}"
    return "valid"


def _transformNotes(pdfFile, version, sigDict):
    """
    Describes /Reference transform methods.
    DocMDP (certification) and UR3/UR (usage rights).
    These say which later changes are permitted,
    which is what makes "modified after signing" unremarkable for them.
    """
    reference = _dereference(pdfFile, sigDict.getElementByName("/Reference"), version)
    if reference is None or reference.getType() != "array":
        return []

    notes = []
    for entry in reference.getElements():
        entry = _dereference(pdfFile, entry, version)
        if entry is None or entry.getType() != "dictionary":
            continue
        methodElement = entry.getElementByName("/TransformMethod")
        if methodElement is None or methodElement == []:
            continue
        method = methodElement.getValue()
        params = _dereference(
            pdfFile, entry.getElementByName("/TransformParams"), version
        )
        if params is not None and params.getType() != "dictionary":
            params = None

        if method == "/DocMDP":
            level = 2  # the default when /P is absent
            levelElement = params.getElementByName("/P") if params is not None else None
            if levelElement is not None and levelElement != []:
                level = levelElement.getRawValue()
            meaning = {
                1: "no changes permitted",
                2: "form filling and signing permitted",
                3: "form filling, signing and annotations permitted",
            }.get(level, "unknown level")
            notes.append(f"Certification signature (DocMDP level {level}): {meaning}")
        elif method in ("/UR3", "/UR"):
            rights = []
            for key in ("/Document", "/Form", "/Annots", "/Signature", "/EF"):
                rightsElement = (
                    params.getElementByName(key) if params is not None else None
                )
                if (
                    rightsElement is not None
                    and rightsElement != []
                    and rightsElement.getType() == "array"
                ):
                    values = ", ".join(
                        e.getValue().lstrip("/") for e in rightsElement.getElements()
                    )
                    rights.append(f"{key.lstrip('/')}: {values}")
            text = "Usage-rights signature (Adobe Reader Extensions)"
            notes.append(f"{text} - {'; '.join(rights)}" if rights else text)
        elif method == "/FieldMDP":
            actionElement = (
                params.getElementByName("/Action") if params is not None else None
            )
            action = (
                actionElement.getValue().lstrip("/")
                if actionElement not in (None, [])
                else "unknown action"
            )
            fieldsElement = (
                params.getElementByName("/Fields") if params is not None else None
            )
            names = []
            if fieldsElement not in (None, []) and fieldsElement.getType() == "array":
                names = [e.getValue() for e in fieldsElement.getElements()]
            notes.append(
                f"Field lock (FieldMDP): {action}"
                + (f" ({', '.join(names)})" if names else "")
            )
        else:
            notes.append(f"Signature transform method: {method}")
    return notes


def _readSignedBytes(pdfFile, byteRange):
    offset1, length1, offset2, length2 = byteRange
    ret1 = getBytesFromFile(pdfFile.getPath(), offset1, length1)
    ret2 = getBytesFromFile(pdfFile.getPath(), offset2, length2)
    if ret1[0] == -1 or ret2[0] == -1:
        return None
    return ret1[1] + ret2[1]


def _certificateNotes(digestAlgo, certificate):
    """
    Informational only - none of these make the signature invalid.
    """
    notes = []
    if digestAlgo in ("md5", "sha1"):
        notes.append(f"{digestAlgo.upper()} is a weak digest algorithm")
    publicKey = certificate.public_key
    if publicKey.algorithm == "rsa" and publicKey.bit_size < 2048:
        notes.append(f"RSA key is only {publicKey.bit_size} bits")
    if certificate.serial_number < 0:
        notes.append("Certificate serial number is negative (not allowed by RFC 5280)")
    return notes


def _rsaSha1Certificates(pdfFile, version, sigDict):
    """
    /Cert holds one certificate string, or an array of them with the signer first.
    """
    certElement = _dereference(pdfFile, sigDict.getElementByName("/Cert"), version)
    if certElement is None:
        return []
    elements = (
        certElement.getElements() if certElement.getType() == "array" else [certElement]
    )
    certificates = []
    for element in elements:
        element = _dereference(pdfFile, element, version)
        certificates.append(x509.Certificate.load(element.getValue().encode("latin-1")))
    return certificates


def _verifyRsaSha1(pdfFile, version, sigDict, contentsBytes, byteRange, result):
    """
    adbe.x509.rsa_sha1: /Contents is a DER OCTET STRING holding a raw RSA
    PKCS1 v1.5 signature over the SHA-1 of the /ByteRange bytes.
    The signer certificate(s) are in /Cert, not inside the signature.
    """
    result["digest_algorithm"] = "sha1"
    result["signature_algorithm"] = "rsassa_pkcs1v15"
    dateElement = sigDict.getElementByName("/M")
    if dateElement is not None and dateElement != []:
        result["claimed_signing_time"] = dateElement.getValue()

    def fail(message):
        result["content_integrity"] = message
        result["signature_authenticity"] = message
        return result

    signedBytes = _readSignedBytes(pdfFile, byteRange)
    if signedBytes is None:
        return fail("error: could not read /ByteRange bytes from file")
    try:
        signatureBytes = core.OctetString.load(contentsBytes).native
    except Exception as exc:
        return fail(f"error: could not parse /Contents as a DER OCTET STRING ({exc})")
    try:
        certificates = _rsaSha1Certificates(pdfFile, version, sigDict)
    except Exception as exc:
        return fail(f"error: could not read /Cert ({exc})")
    if not certificates:
        return fail("error: no signer certificate in /Cert")

    certificate = certificates[0]
    try:
        publicKey = load_der_public_key(certificate.public_key.dump())
    except Exception as exc:
        return fail(f"error: could not load signer certificate ({exc})")

    outcome = _verifySignatureBytes(
        publicKey, signatureBytes, signedBytes, "sha1", "rsassa_pkcs1v15"
    )
    result["content_integrity"] = outcome
    result["signature_authenticity"] = outcome
    result["signer"] = {
        **_certificateDetails(certificate),
        "signing_time_within_validity": None,
    }
    result["certificate_chain"] = _orderChain(certificates, certificate)
    result["notes"] = _certificateNotes("sha1", certificate) + _transformNotes(
        pdfFile, version, sigDict
    )
    return result


def _newResult(objectId, fieldName):
    return {
        "object_id": objectId,
        "field_name": fieldName,
        "version": None,
        "filter": None,
        "sub_filter": None,
        "byte_range": None,
        "modified_after_signing": None,
        "content_integrity": None,
        "signature_authenticity": None,
        "signing_time": None,
        "digest_algorithm": None,
        "signature_algorithm": None,
        "signer": None,
        "certificate_chain": None,
        "claimed_signing_time": None,
        "notes": [],
        "unsupported_reason": None,
    }


def verifySignature(pdfFile, version, objectId, fieldName, sigDict):
    result = _newResult(objectId, fieldName)

    typeElement = sigDict.getElementByName("/Type")
    typeValue = typeElement.getValue() if typeElement and typeElement != [] else "/Sig"
    filterElement = sigDict.getElementByName("/Filter")
    result["filter"] = (
        filterElement.getValue() if filterElement and filterElement != [] else None
    )
    subFilterElement = sigDict.getElementByName("/SubFilter")
    subFilter = (
        subFilterElement.getValue()
        if subFilterElement and subFilterElement != []
        else None
    )
    result["sub_filter"] = subFilter

    if typeValue == "/DocTimeStamp":
        result["unsupported_reason"] = (
            "RFC 3161 document timestamps are not yet supported"
        )
        return result
    if subFilter is None or subFilter.lstrip("/") not in SUPPORTED_SUBFILTERS:
        result["unsupported_reason"] = f"unsupported /SubFilter: {subFilter}"
        return result

    byteRange = _extractByteRange(sigDict)
    if byteRange is None:
        result["unsupported_reason"] = "missing or malformed /ByteRange"
        return result
    result["byte_range"] = byteRange
    offset1, length1, offset2, length2 = byteRange

    try:
        fileSize = os.path.getsize(pdfFile.getPath())
        result["modified_after_signing"] = (offset2 + length2) != fileSize
    except OSError:
        result["modified_after_signing"] = None

    contentsBytes = _extractContentsBytes(sigDict)
    if contentsBytes is None:
        result["unsupported_reason"] = "missing /Contents"
        return result

    if subFilter.lstrip("/") == "adbe.x509.rsa_sha1":
        return _verifyRsaSha1(
            pdfFile, version, sigDict, contentsBytes, byteRange, result
        )

    try:
        info = cms.ContentInfo.load(contentsBytes)
        signedData = info["content"]
        signerInfo = signedData["signer_infos"][0]
    except Exception as exc:
        result["content_integrity"] = (
            f"error: could not parse /Contents as CMS SignedData ({exc})"
        )
        result["signature_authenticity"] = result["content_integrity"]
        return result

    digestAlgo = signerInfo["digest_algorithm"]["algorithm"].native
    signatureAlgoNative = signerInfo["signature_algorithm"]["algorithm"].native
    result["digest_algorithm"] = digestAlgo
    result["signature_algorithm"] = signatureAlgoNative

    signedBytes = _readSignedBytes(pdfFile, byteRange)
    if signedBytes is None:
        result["content_integrity"] = "error: could not read /ByteRange bytes from file"
        result["signature_authenticity"] = result["content_integrity"]
        return result

    signedAttrs = signerInfo["signed_attrs"]
    hasSignedAttrs = not isinstance(signedAttrs, core.Void) and len(signedAttrs) > 0

    signingTime = None
    if hasSignedAttrs:
        signingTime = _signingTimeAttribute(signedAttrs)
        result["signing_time"] = (
            signingTime.isoformat() if signingTime is not None else None
        )
        claimedDigest = _messageDigestAttribute(signedAttrs)
        hashClass = _HASH_CLASSES.get(digestAlgo)
        if hashClass is None or claimedDigest is None:
            result["content_integrity"] = (
                f"error: unsupported digest algorithm '{digestAlgo}'"
            )
        else:
            computedDigest = hashlib.new(digestAlgo, signedBytes).digest()
            result["content_integrity"] = (
                "valid" if computedDigest == claimedDigest else "invalid"
            )
        dataToVerify = _signedAttrsDer(signedAttrs)
    else:
        dataToVerify = signedBytes

    try:
        certificate = _signerCertificate(signedData, signerInfo)
        if certificate is None:
            result["signature_authenticity"] = (
                "error: signer certificate not found in /Contents"
            )
            return result
        publicKey = load_der_public_key(certificate.public_key.dump())
    except Exception as exc:
        result["signature_authenticity"] = (
            f"error: could not load signer certificate ({exc})"
        )
        return result

    signatureBytes = signerInfo["signature"].native
    result["signature_authenticity"] = _verifySignatureBytes(
        publicKey, signatureBytes, dataToVerify, digestAlgo, signatureAlgoNative
    )
    if not hasSignedAttrs:
        result["content_integrity"] = result["signature_authenticity"]

    notBefore = certificate.not_valid_before
    notAfter = certificate.not_valid_after
    signingTimeWithinValidity = None
    if signingTime is not None:
        signingTimeWithinValidity = notBefore <= signingTime <= notAfter

    result["signer"] = {
        **_certificateDetails(certificate),
        "signing_time_within_validity": signingTimeWithinValidity,
    }
    result["certificate_chain"] = _embeddedChain(signedData, certificate)
    result["notes"] = _certificateNotes(digestAlgo, certificate) + _transformNotes(
        pdfFile, version, sigDict
    )
    return result


def getSignatures(pdfFile, version=None):
    """
    Signatures as of 'version', or of every revision when it is None.
    A signature is reported once, with 'version' set to the revision that
    defines it, however many revisions can still see it.
    """
    versions = range(pdfFile.updates + 1) if version is None else [version]
    chosen = {}
    for v in versions:
        for objectId, fieldName, sigDict in findSignatureDictionaries(pdfFile, v):
            defined = _definingVersion(pdfFile, objectId, v)
            byteRange = _extractByteRange(sigDict)
            key = tuple(byteRange) if byteRange else ("object", objectId, defined)
            rank = (
                2
                if fieldName and not fieldName.startswith("/Perms")
                else 1 if fieldName else 0
            )
            if key not in chosen or rank > chosen[key][0]:
                chosen[key] = (rank, objectId, fieldName, sigDict, v, defined)

    results = []
    for _rank, objectId, fieldName, sigDict, foundAt, defined in sorted(
        chosen.values(), key=lambda entry: -1 if entry[5] is None else entry[5]
    ):
        try:
            result = verifySignature(pdfFile, foundAt, objectId, fieldName, sigDict)
        except Exception as exc:
            result = _newResult(objectId, fieldName)
            message = f"error: unexpected failure verifying this signature ({type(exc).__name__}: {exc})"
            result["content_integrity"] = message
            result["signature_authenticity"] = message
        result["version"] = defined
        results.append(result)
    return results

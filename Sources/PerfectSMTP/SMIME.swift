//
//  SMIME.swift
//  PerfectSMTP
//
//  Created by Jonathan Guthrie on 2019-01-29, Yonatan Mittlefehldt on 4/6/18.
//  Contributed from the Moonshot project.
//

import Foundation
import COpenSSL

extension Date {

	/// Trys to create a Date from a string using a specified format
	///
	/// - Parameters:
	///   - string: string that represents a date
	///   - format: format for the date
	/// - Returns: a date, if successful
	static func fromString(_ string: String, format: String) -> Date? {

		let formatter = DateFormatter()
		formatter.dateFormat = format

		return formatter.date(from: string)
	}

	/// Postgres compatible string for a date
	var postgresDate: String {
		let formatter = DateFormatter()
		formatter.dateFormat = "yyyy-MM-dd"

		return formatter.string(from: self)
	}

	/// Postgres compatible string for a timestamp
	var postgresTimestamp: String {
		return description
	}

}

public struct SMIME {

	/// Private certificate used for encrypting and decrypting the SMIME message data
	let cert: String

	public init(cert: String) {
		self.cert = cert
	}

	/// Decrypt a message using a private certificate
	///
	/// - Parameter msg: encrypted message to be decrypted
	/// - Returns: decrypted message, if successful
	public func decrypt(message msg: String) -> String {

		OPENSSL_add_all_algorithms_conf()

		let certificate = BIO_new(BIO_s_mem())
		let input = BIO_new(BIO_s_mem())
		let output = BIO_new(BIO_s_mem())

		_ = BIO_ctrl(input, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, nil)

		var ret = BIO_puts(certificate, cert)

		if ret <= 0 {
			print("DECRYPT: Could not put certificate into a BIO")
			return ""
		}

		let senderCert = PEM_read_bio_X509(certificate, nil, nil, nil)

		_ = BIO_ctrl(certificate, BIO_CTRL_RESET, 0, nil)
		ret = BIO_puts(certificate, cert)

		if ret <= 0 {
			print("DECRYPT: Could not put certificate into a BIO, after reset")
			return ""
		}

		let senderKey = PEM_read_bio_PrivateKey(certificate, nil, nil, nil)

		ret = BIO_puts(input, msg)

		if ret <= 0 {
			print("DECRYPT: Could not put encrypted message into a BIO")
			return ""
		}

		let cms = SMIME_read_CMS(input, nil)

		let buf = UnsafeMutablePointer<Int8>.allocate(capacity: 1024)

		ret = CMS_decrypt(cms, senderKey, senderCert, nil, output, 0)

		if ret == 0 {
			print("DECRYPT: Could not decrypt message using certificate")
			return ""
		}

		var out = ""

		while BIO_gets(output, buf, 1024) > 0 {
			out += String(cString: buf)
		}

		return out
	}

	/// Encrypt a message using the recipient's public certificate
	///
	/// - Parameters:
	///   - msg: message to encrypt
	///   - recipientCert: recipient's public certificate
	/// - Returns: an encrypted message, if successful
	public func encrypt(message msg: String, using recipientCert: String) -> String {

		OPENSSL_add_all_algorithms_conf()

		let certificate = BIO_new(BIO_s_mem())
		let input = BIO_new(BIO_s_mem())
		let output = BIO_new(BIO_s_mem())

		var ret = BIO_puts(certificate, recipientCert)

		if ret <= 0 {
			print("ENCRYPT: Could not put certificate into a BIO")
			return ""
		}

		var rcert = PEM_read_bio_X509(certificate, nil, nil, nil)

		ret = BIO_puts(input, msg)

		if ret <= 0 {
			print("ENCRYPT: Could not put message into a BIO")
			return ""
		}

		let flags = UInt32(CMS_BINARY | CMS_PARTIAL | CMS_KEY_PARAM)
		let cms = CMS_encrypt(nil, input, EVP_aes_192_cbc(), flags)

		if cms == nil {
			print("ENCRYPT: Could not create a CMS enveloped data structure")
			return ""
		}

		let ri = CMS_add1_recipient_cert(cms, rcert, flags)

		if ri == nil {
			print("ENCRYPT: Could not add recipient to a CMS enveloped data structure")
			return ""
		}

		let ctx = CMS_RecipientInfo_get0_pkey_ctx(ri)

		if ctx == nil {
			print("ENCRYPT: Could get the public key context from the recipient info")
			return ""
		}

		// EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
		ret = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, RSA_PKCS1_OAEP_PADDING, nil)

		if ret <= 0 {
			print("ENCRYPT: Could not set OAEP padding for the encryption key")
			return ""
		}

		let md = UnsafeMutableRawPointer(mutating: EVP_sha256())

		// EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256())
		ret = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_MD, 0, md)

		if ret <= 0 {
			print("ENCRYPT: Could not set the hash function to SHA256")
			return ""
		}

		var mgfFlags = EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER
		mgfFlags |= EVP_PKEY_OP_SIGNCTX | EVP_PKEY_OP_VERIFYCTX | EVP_PKEY_OP_TYPE_CRYPT

		// EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256())
		ret = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, mgfFlags, EVP_PKEY_CTRL_RSA_MGF1_MD, 0, md)

		if ret <= 0 {
			print("ENCRYPT: Could not set the mask generation function to SHA256")
			return ""
		}

		ret = CMS_final(cms, input, nil, flags)

		if ret == 0 {
			print("ENCRYPT: Could not finalize the CMS")
			return ""
		}

		rcert = nil

		ret = SMIME_write_CMS(output, cms, input, 0)

		if ret == 0 {
			print("ENCRYPT: Could not convert CMS structure into S/MIME format")
			return ""
		}

		let buf = UnsafeMutablePointer<Int8>.allocate(capacity: 1024)
		var out = ""

		while BIO_gets(output, buf, 1024) > 0 {
			out += String(cString: buf)
		}

		return out
	}

	/// Sign a message using a private certificate
	///
	/// - Parameter msg: message to be signed
	/// - Returns: the signed message, if successful
	public func sign(message msg: String) -> String {

		OPENSSL_add_all_algorithms_conf()

		let certificate = BIO_new(BIO_s_mem())
		let input = BIO_new(BIO_s_mem())
		let output = BIO_new(BIO_s_mem())

		var ret = BIO_puts(certificate, cert)

		if ret <= 0 {
			print("SIGN: Could not put certificate into a BIO")
			return ""
		}

		let senderCert = PEM_read_bio_X509(certificate, nil, nil, nil)

		_ = BIO_ctrl(certificate, BIO_CTRL_RESET, 0, nil)
		ret = BIO_puts(certificate, cert)

		if ret <= 0 {
			print("SIGN: Could not put certificate into a BIO, after reset")
			return ""
		}

		let senderKey = PEM_read_bio_PrivateKey(certificate, nil, nil, nil)

		ret = BIO_puts(input, msg)

		if ret <= 0 {
			print("SIGN: Could not put message into a BIO")
			return ""
		}

		let p7 = PKCS7_sign(senderCert, senderKey, nil, input, PKCS7_DETACHED)

		_ = BIO_ctrl(input, BIO_CTRL_RESET, 0, nil)
		ret = BIO_puts(input, msg)

		if ret <= 0 {
			print("SIGN: Could not put message into a BIO, after reset")
			return ""
		}

		ret = SMIME_write_PKCS7(output, p7, input, PKCS7_DETACHED)

		if ret == 0 {
			print("SIGN: Could not convert PKCS#7 structure into S/MIME format")
			return ""
		}

		let buf = UnsafeMutablePointer<Int8>.allocate(capacity: 1024)
		var out = ""

		while BIO_gets(output, buf, 1024) > 0 {
			out += String(cString: buf)
		}

		return out
	}

	/// Helper function to extract the email address from a signing certificate
	///
	/// - Parameter x509: the X509 signing certificate
	/// - Returns: the email address, if successful
	private static func extractEmail(from x509: UnsafeMutablePointer<X509>) -> String? {

		guard let altNames = X509_get_ext_d2i(x509, NID_subject_alt_name, nil, nil) else {
			return nil
		}

		let altNameStack = altNames.assumingMemoryBound(to: _STACK.self)

		defer {
			sk_free(altNameStack)
		}

		while let altName = sk_pop(altNameStack) {
			let name = altName.assumingMemoryBound(to: GENERAL_NAME.self)
			if name.pointee.type == GEN_EMAIL,
				let data = ASN1_STRING_data(name.pointee.d.uniformResourceIdentifier) {
				return String(cString: data)
			}
		}

		return nil
	}

	/// Extracts the validity dates from a signing certificate
	///
	/// - Parameter x509: the X509 signing certificate
	/// - Returns: a tuple of the from/to dates, if successful
	private static func extractDates(from x509: UnsafeMutablePointer<X509>) -> (from: Date, to: Date)? {

		let notBefore = String(cString: x509.pointee.cert_info.pointee.validity.pointee.notBefore.pointee.data)
		let notAfter = String(cString: x509.pointee.cert_info.pointee.validity.pointee.notAfter.pointee.data)

		var fromDate: Date?
		var toDate: Date?

		for format in ["yyMMddHHmmssZ", "yyyyMMddHHmmssZ"] {

			if fromDate == nil {
				fromDate = Date.fromString(notBefore, format: format)
			}

			if toDate == nil {
				toDate = Date.fromString(notAfter, format: format)
			}
		}

		guard let from = fromDate, let to = toDate else {
			return nil
		}

		return (from: from, to: to)
	}

	/// Helper function to extract the certificate info from an X509 structure
	///
	/// - Parameter x509: pointer to the X509 structure
	/// - Returns: certificate info, if successful
	private static func extractInfo(from x509: UnsafeMutablePointer<X509>) -> CertificateInfo? {

		guard let email = extractEmail(from: x509) else {
			return nil
		}

		guard let (from, to) = extractDates(from: x509) else {
			return nil
		}

		let output = BIO_new(BIO_s_mem())

		PEM_write_bio_X509(output, x509)

		let buf = UnsafeMutablePointer<Int8>.allocate(capacity: 1024)
		var certificate = ""

		while BIO_gets(output, buf, 1024) > 0 {
			certificate += String(cString: buf)
		}

		return CertificateInfo(email: email, certificate: certificate, validFrom: from, validTo: to)
	}

	/// Helper function to extract the certificate info from a PKCS7 structure
	///
	/// - Parameter p7: pointer to the PKCS7 structure
	/// - Returns: certificate info, if successful
	private static func extractInfo(from p7: UnsafeMutablePointer<PKCS7>?) -> CertificateInfo? {

		guard let signers = PKCS7_get0_signers(p7, nil, 0) else {
			return nil
		}

		let signerStack = UnsafeMutablePointer<_STACK>.allocate(capacity: 1)
		signerStack.pointee = signers.pointee.stack

		while let signer = sk_pop(signerStack) {
			let x509 = signer.assumingMemoryBound(to: X509.self)

			if let cert = extractInfo(from: x509) {
				return cert
			}
		}

		return nil
	}

	/// Extracts the certificate information from a public certificate in PEM format
	///
	/// - Parameter cert: PEM format certificate
	/// - Returns: certificate info, if successful
	public static func extractInfo(from cert: String) -> CertificateInfo? {

		OPENSSL_add_all_algorithms_conf()
		ERR_load_crypto_strings()

		let input = BIO_new(BIO_s_mem())

		_ = BIO_ctrl(input, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, nil)
		let ret = BIO_puts(input, cert)

		if ret <= 0 {
			print("EXTRACT INFO: Could not put message into a BIO")
			return nil
		}

		guard let x509 = PEM_read_bio_X509(input, nil, nil, nil) else {
			return nil
		}

		return extractInfo(from: x509)
	}

	/// Extracts the public certificate from a signature and the email address that is associated with it
	///
	/// - Parameter msg: email (S/MIME) message
	/// - Returns: certificate info, if successful
	public static func extractPublicCertificate(from msg: String) -> CertificateInfo? {

		OPENSSL_add_all_algorithms_conf()
		ERR_load_crypto_strings()

		let input = BIO_new(BIO_s_mem())

		_ = BIO_ctrl(input, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, nil)
		let ret = BIO_puts(input, msg)

		if ret <= 0 {
			print("EXTRACT CERT: Could not put message into a BIO")
			return nil
		}

		let p7 = SMIME_read_PKCS7(input, nil)

		return extractInfo(from: p7)
	}

	/// Extracts the MIME part of an email message
	///
	/// - Parameter msg: email (S/MIME) message
	/// - Returns: the MIME part or an empty string
	public static func extractMimeMessage(from msg: String) -> String {

		let lines = msg.components(separatedBy: "\n")
		var start = lines.count

		for (idx, line) in lines.enumerated() {
			if line.uppercased().hasPrefix("MIME-Version:".uppercased()) {
				start = idx
				break
			}
		}

		return lines[start..<lines.count].joined(separator: "\n")
	}

	/// Extracts the data out of the MIME part
	///
	/// - Parameter mime: MIME part of an email
	/// - Returns: the data part of the MIME
	public static func extractData(from mime: String) -> String {

		OPENSSL_add_all_algorithms_conf()
		ERR_load_crypto_strings()

		let input = BIO_new(BIO_s_mem())
		var output = BIO_new(BIO_s_mem())

		_ = BIO_ctrl(input, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, nil)
		let ret = BIO_puts(input, mime)

		if ret <= 0 {
			print("EXTRACT DATA: Could not put mime into a BIO")
			return ""
		}

		let p7 = SMIME_read_PKCS7(input, &output)

		if p7 == nil {
			print("EXTRACT DATA: Could not parse S/MIME message")
			return ""
		}

		let buf = UnsafeMutablePointer<Int8>.allocate(capacity: 1024)
		var data = ""

		while BIO_gets(output, buf, 1024) > 0 {
			data += String(cString: buf)
		}

		return data
	}
}

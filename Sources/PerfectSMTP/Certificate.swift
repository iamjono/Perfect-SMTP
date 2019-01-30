//
//  Certificate.swift
//  PerfectSMTP
//
//  Created by Jonathan Guthrie on 2019-01-29, Yonatan Mittlefehldt on 2018-06-12.
//  Contributed from the Moonshot Project.
//

import Foundation

public struct CertificateInfo {
	// Email address associated with the certificate
	public let email: String

	// Certificate
	public let certificate: String

	// Validity
	public let validFrom: Date
	public let validTo: Date

	public init(email: String,
				certificate: String,
				validFrom: Date,
				validTo: Date) {

		self.email = email
		self.certificate = certificate
		self.validFrom = validFrom
		self.validTo = validTo
	}
}

/// Structure to store a PUBLIC certificate
public struct Certificate {

	public let id: Int?

	// Info for the certificate
	public let info: CertificateInfo?

	public init() {
		self.id = nil
		self.info = nil
	}

	public init(id: Int?, info: CertificateInfo) {
		self.id = id
		self.info = info
	}

	public init(info: CertificateInfo) {
		self.id = nil
		self.info = info
	}

	/// Converts the certificate into a JSON representation
	///
	/// - Returns: JSON represenation of the important data for a message
	public func json() -> [String: Any] {
		var json: [String: Any] = ["email": info?.email,
								   "certificate": info?.certificate,
								   "validFrom": info?.validFrom.postgresDate,
								   "validTo": info?.validTo.postgresDate]

		if let id = id {
			json["id"] = id
		}

		return json
	}
}

import SwiftUI
import Combine
import PhotosUI
import Charts
import UniformTypeIdentifiers
import Security
import CoreText
import CryptoKit
import CoreImage.CIFilterBuiltins
import Vision

private struct LocalProfile: Codable, Identifiable {
    var id: UUID = UUID()
    var fullName: String
    var nickname: String
    var requirePasswordOnLaunch: Bool
    var passwordSalt: String?
    var passwordDigest: String?

    enum CodingKeys: String, CodingKey { case id, fullName, nickname, requirePasswordOnLaunch, passwordSalt, passwordDigest }

    init(id: UUID = UUID(), fullName: String, nickname: String, requirePasswordOnLaunch: Bool,
         passwordSalt: String? = nil, passwordDigest: String? = nil) {
        self.id = id
        self.fullName = fullName
        self.nickname = nickname
        self.requirePasswordOnLaunch = requirePasswordOnLaunch
        self.passwordSalt = passwordSalt
        self.passwordDigest = passwordDigest
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        fullName = try values.decode(String.self, forKey: .fullName)
        nickname = try values.decode(String.self, forKey: .nickname)
        requirePasswordOnLaunch = try values.decodeIfPresent(Bool.self, forKey: .requirePasswordOnLaunch) ?? false
        passwordSalt = try values.decodeIfPresent(String.self, forKey: .passwordSalt)
        passwordDigest = try values.decodeIfPresent(String.self, forKey: .passwordDigest)
    }
}

@MainActor
private final class LocalProfileStore: ObservableObject {
    @Published private(set) var profiles: [LocalProfile] = []
    @Published private(set) var activeProfileID: UUID?
    var profile: LocalProfile? { profiles.first { $0.id == activeProfileID } }
    private let service = "com.applevault.local-profile"

    private var directoryURL: URL {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AppleVault", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }
    private var profilesURL: URL { directoryURL.appendingPathComponent("profiles.json") }
    private var legacyProfileURL: URL { directoryURL.appendingPathComponent("profile.json") }

    init() {
        if let data = try? Data(contentsOf: profilesURL),
           let saved = try? JSONDecoder().decode(ProfileDirectory.self, from: data) {
            profiles = saved.profiles
            activeProfileID = saved.activeProfileID.flatMap { id in saved.profiles.contains(where: { $0.id == id }) ? id : nil }
                ?? saved.profiles.first?.id
        } else if let data = try? Data(contentsOf: legacyProfileURL),
                  let legacy = try? JSONDecoder().decode(LocalProfile.self, from: data) {
            profiles = [legacy]
            activeProfileID = legacy.id
            migrateLegacyPassword(to: legacy.id)
            persist()
        }
    }

    func save(fullName: String, nickname: String, requirePassword: Bool, newPassword: String? = nil) throws {
        guard let activeProfileID, let index = profiles.firstIndex(where: { $0.id == activeProfileID }) else {
            try addProfile(fullName: fullName, nickname: nickname, requirePassword: requirePassword, password: newPassword ?? "")
            return
        }
        var salt = profiles[index].passwordSalt
        var digest = profiles[index].passwordDigest
        if let password = newPassword, !password.isEmpty {
            let newSalt = UUID().uuidString
            salt = newSalt
            digest = Self.passwordDigest(password, salt: newSalt)
        }
        let updated = LocalProfile(id: activeProfileID,
                                   fullName: fullName.trimmingCharacters(in: .whitespacesAndNewlines),
                                   nickname: nickname.trimmingCharacters(in: .whitespacesAndNewlines),
                                   requirePasswordOnLaunch: requirePassword,
                                   passwordSalt: salt, passwordDigest: digest)
        if let password = newPassword, !password.isEmpty { try storePassword(password, for: activeProfileID) }
        profiles[index] = updated
        persist()
    }

    func verify(_ password: String) -> Bool {
        guard let activeProfileID else { return false }
        if let index = profiles.firstIndex(where: { $0.id == activeProfileID }),
           let salt = profiles[index].passwordSalt, let digest = profiles[index].passwordDigest {
            return Self.passwordDigest(password, salt: salt) == digest
        }
        var query = baseQuery(for: activeProfileID)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIAllow
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let saved = String(data: data, encoding: .utf8) else { return false }
        guard saved == password,
              let index = profiles.firstIndex(where: { $0.id == activeProfileID }) else { return false }
        let salt = UUID().uuidString
        profiles[index].passwordSalt = salt
        profiles[index].passwordDigest = Self.passwordDigest(password, salt: salt)
        persist()
        return true
    }

    func addProfile(fullName: String, nickname: String, requirePassword: Bool, password: String) throws {
        let salt = password.isEmpty ? nil : UUID().uuidString
        let newProfile = LocalProfile(fullName: fullName.trimmingCharacters(in: .whitespacesAndNewlines),
                                      nickname: nickname.trimmingCharacters(in: .whitespacesAndNewlines),
                                      requirePasswordOnLaunch: requirePassword,
                                      passwordSalt: salt,
                                      passwordDigest: salt.map { Self.passwordDigest(password, salt: $0) })
        if !password.isEmpty { try storePassword(password, for: newProfile.id) }
        profiles.append(newProfile)
        activeProfileID = newProfile.id
        persist()
    }

    func switchProfile(to id: UUID) {
        guard profiles.contains(where: { $0.id == id }) else { return }
        activeProfileID = id
        persist()
    }

    func reset() {
        profiles.forEach { SecItemDelete(baseQuery(for: $0.id) as CFDictionary) }
        SecItemDelete(legacyPasswordQuery as CFDictionary)
        try? FileManager.default.removeItem(at: directoryURL)
        profiles = []
        activeProfileID = nil
    }

    private func baseQuery(for id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: id.uuidString]
    }

    private static func passwordDigest(_ password: String, salt: String) -> String {
        SHA256.hash(data: Data((salt + password).utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private var legacyPasswordQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "profile-password"]
    }

    private func storePassword(_ password: String, for id: UUID) throws {
        let base = baseQuery(for: id)
        var query = base
        query[kSecValueData as String] = Data(password.utf8)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let update = [kSecValueData as String: Data(password.utf8)]
            let updateStatus = SecItemUpdate(base as CFDictionary, update as CFDictionary)
            guard updateStatus == errSecSuccess else { throw ProfileError.keychain(updateStatus) }
        } else if status != errSecSuccess {
            throw ProfileError.keychain(status)
        }
    }

    private func migrateLegacyPassword(to id: UUID) {
        var query = legacyPasswordQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data,
           let password = String(data: data, encoding: .utf8) {
            try? storePassword(password, for: id)
            SecItemDelete(legacyPasswordQuery as CFDictionary)
        }
    }

    private func persist() {
        let directory = ProfileDirectory(profiles: profiles, activeProfileID: activeProfileID)
        guard let data = try? JSONEncoder().encode(directory) else { return }
        try? data.write(to: profilesURL, options: .atomic)
    }

}

private enum ProfileError: LocalizedError {
    case keychain(OSStatus)
    var errorDescription: String? { "Impossible d’enregistrer le mot de passe dans le trousseau macOS (\(errorCode))." }
    private var errorCode: Int32 { if case .keychain(let status) = self { return status }; return -1 }
}

struct AppleDevice: Identifiable, Codable {
    var id = UUID()
    var model: String
    var identifier: String
    var aNumber: String
    var partNumber: String
    var storage: String
    var color: String
    var serial: String
    var ios: String
    var condition: String
    var repairsDone: String
    var repairsTodo: String
    var notes: String
    var jailbreak: String
    var shsh: String
    var batteryHealth: String
    var purchaseDate: String
    var purchasePrice: String
    var photoPath: String
    var appleImageURL: String
    var estimatedValue: String
    var repairHistory: [RepairEntry]
    var tags: [String]
    var isFavorite: Bool
    var maintenanceDate: Date?
    var warrantyEndDate: Date?
    var accessories: String
    var hasBox: Bool
    var hasCharger: Bool
    var hasInvoice: Bool
    var warningsIgnored: Bool
    var timeline: [DeviceTimelineEntry]
    var documents: [DeviceDocument]
    var releaseYear: String
    var purchaseLocation: String
    var seller: String
    var estimatedValueMin: String
    var estimatedValueMax: String
    var valueHistory: [DeviceValueSnapshot]
    var batteryHistory: [BatterySnapshot]
    var loanedTo: String
    var loanDueDate: Date?
    var privateNotes: String
    var createdAt: Date

    // Older inventory files do not contain jailbreak or SHSH fields.
    enum CodingKeys: String, CodingKey {
        case id, model, identifier, aNumber, partNumber, storage, color, serial, ios
        case condition, repairsDone, repairsTodo, notes, jailbreak, shsh
        case batteryHealth, purchaseDate, purchasePrice, photoPath, appleImageURL
        case estimatedValue, repairHistory, tags, isFavorite, maintenanceDate
        case warrantyEndDate, accessories, hasBox, hasCharger, hasInvoice, warningsIgnored, timeline, documents
        case releaseYear, purchaseLocation, seller, estimatedValueMin, estimatedValueMax, valueHistory
        case batteryHistory, loanedTo, loanDueDate, createdAt
    }

    init(model: String, identifier: String, aNumber: String, partNumber: String = "", storage: String,
         color: String, serial: String, ios: String, condition: String,
         repairsDone: String, repairsTodo: String, notes: String,
         jailbreak: String = "", shsh: String = "", batteryHealth: String = "",
         purchaseDate: String = "", purchasePrice: String = "", photoPath: String = "",
         appleImageURL: String = "", estimatedValue: String = "",
         repairHistory: [RepairEntry] = [], tags: [String] = [], isFavorite: Bool = false,
         maintenanceDate: Date? = nil, warrantyEndDate: Date? = nil, accessories: String = "",
         hasBox: Bool = false, hasCharger: Bool = false, hasInvoice: Bool = false,
         warningsIgnored: Bool = false, timeline: [DeviceTimelineEntry] = [], documents: [DeviceDocument] = [],
         releaseYear: String = "", purchaseLocation: String = "", seller: String = "",
         estimatedValueMin: String = "", estimatedValueMax: String = "",
         valueHistory: [DeviceValueSnapshot] = [], batteryHistory: [BatterySnapshot] = [],
         loanedTo: String = "", loanDueDate: Date? = nil, privateNotes: String = "", createdAt: Date = .now) {
        self.model = model
        self.identifier = identifier
        self.aNumber = aNumber
        self.partNumber = partNumber
        self.storage = storage
        self.color = color
        self.serial = serial
        self.ios = ios
        self.condition = condition
        self.repairsDone = repairsDone
        self.repairsTodo = repairsTodo
        self.notes = notes
        self.jailbreak = jailbreak
        self.shsh = shsh
        self.batteryHealth = batteryHealth
        self.purchaseDate = purchaseDate
        self.purchasePrice = purchasePrice
        self.photoPath = photoPath
        self.appleImageURL = appleImageURL
        self.estimatedValue = estimatedValue
        self.repairHistory = repairHistory
        self.tags = tags
        self.isFavorite = isFavorite
        self.maintenanceDate = maintenanceDate
        self.warrantyEndDate = warrantyEndDate
        self.accessories = accessories
        self.hasBox = hasBox
        self.hasCharger = hasCharger
        self.hasInvoice = hasInvoice
        self.warningsIgnored = warningsIgnored
        self.timeline = timeline
        self.documents = documents
        self.releaseYear = releaseYear; self.purchaseLocation = purchaseLocation; self.seller = seller
        self.estimatedValueMin = estimatedValueMin; self.estimatedValueMax = estimatedValueMax
        self.valueHistory = valueHistory; self.batteryHistory = batteryHistory
        self.loanedTo = loanedTo; self.loanDueDate = loanDueDate; self.privateNotes = privateNotes
        self.createdAt = createdAt
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        model = try values.decodeIfPresent(String.self, forKey: .model) ?? ""
        identifier = try values.decodeIfPresent(String.self, forKey: .identifier) ?? ""
        aNumber = try values.decodeIfPresent(String.self, forKey: .aNumber) ?? ""
        partNumber = try values.decodeIfPresent(String.self, forKey: .partNumber) ?? ""
        storage = try values.decodeIfPresent(String.self, forKey: .storage) ?? ""
        color = try values.decodeIfPresent(String.self, forKey: .color) ?? ""
        serial = try values.decodeIfPresent(String.self, forKey: .serial) ?? ""
        ios = try values.decodeIfPresent(String.self, forKey: .ios) ?? ""
        condition = try values.decodeIfPresent(String.self, forKey: .condition) ?? "Bon état"
        repairsDone = try values.decodeIfPresent(String.self, forKey: .repairsDone) ?? ""
        repairsTodo = try values.decodeIfPresent(String.self, forKey: .repairsTodo) ?? ""
        notes = try values.decodeIfPresent(String.self, forKey: .notes) ?? ""
        jailbreak = try values.decodeIfPresent(String.self, forKey: .jailbreak) ?? ""
        shsh = try values.decodeIfPresent(String.self, forKey: .shsh) ?? ""
        batteryHealth = try values.decodeIfPresent(String.self, forKey: .batteryHealth) ?? ""
        purchaseDate = try values.decodeIfPresent(String.self, forKey: .purchaseDate) ?? ""
        purchasePrice = try values.decodeIfPresent(String.self, forKey: .purchasePrice) ?? ""
        photoPath = try values.decodeIfPresent(String.self, forKey: .photoPath) ?? ""
        appleImageURL = try values.decodeIfPresent(String.self, forKey: .appleImageURL) ?? ""
        estimatedValue = try values.decodeIfPresent(String.self, forKey: .estimatedValue) ?? ""
        repairHistory = try values.decodeIfPresent([RepairEntry].self, forKey: .repairHistory) ?? []
        tags = try values.decodeIfPresent([String].self, forKey: .tags) ?? []
        isFavorite = try values.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        maintenanceDate = try values.decodeIfPresent(Date.self, forKey: .maintenanceDate)
        warrantyEndDate = try values.decodeIfPresent(Date.self, forKey: .warrantyEndDate)
        accessories = try values.decodeIfPresent(String.self, forKey: .accessories) ?? ""
        hasBox = try values.decodeIfPresent(Bool.self, forKey: .hasBox) ?? false
        hasCharger = try values.decodeIfPresent(Bool.self, forKey: .hasCharger) ?? false
        hasInvoice = try values.decodeIfPresent(Bool.self, forKey: .hasInvoice) ?? false
        warningsIgnored = try values.decodeIfPresent(Bool.self, forKey: .warningsIgnored) ?? false
        timeline = try values.decodeIfPresent([DeviceTimelineEntry].self, forKey: .timeline) ?? []
        documents = try values.decodeIfPresent([DeviceDocument].self, forKey: .documents) ?? []
        releaseYear = try values.decodeIfPresent(String.self, forKey: .releaseYear) ?? ""
        purchaseLocation = try values.decodeIfPresent(String.self, forKey: .purchaseLocation) ?? ""
        seller = try values.decodeIfPresent(String.self, forKey: .seller) ?? ""
        estimatedValueMin = try values.decodeIfPresent(String.self, forKey: .estimatedValueMin) ?? ""
        estimatedValueMax = try values.decodeIfPresent(String.self, forKey: .estimatedValueMax) ?? ""
        valueHistory = try values.decodeIfPresent([DeviceValueSnapshot].self, forKey: .valueHistory) ?? []
        batteryHistory = try values.decodeIfPresent([BatterySnapshot].self, forKey: .batteryHistory) ?? []
        loanedTo = try values.decodeIfPresent(String.self, forKey: .loanedTo) ?? ""
        loanDueDate = try values.decodeIfPresent(Date.self, forKey: .loanDueDate)
        privateNotes = PrivateNoteVault.read(for: id)
        createdAt = try values.decodeIfPresent(Date.self, forKey: .createdAt) ?? .now
    }
}

private enum PrivateNoteVault {
    private static let service = "com.applevault.private-device-notes"
    static func read(for id: UUID) -> String {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: id.uuidString,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return "" }
        query.removeAll()
        return String(data: data, encoding: .utf8) ?? ""
    }
    static func store(_ note: String, for id: UUID) {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: id.uuidString]
        if note.isEmpty { SecItemDelete(query as CFDictionary); return }
        let update: [String: Any] = [kSecValueData as String: Data(note.utf8),
                                     kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        if SecItemUpdate(query as CFDictionary, update as CFDictionary) == errSecItemNotFound {
            var insert = query; update.forEach { insert[$0.key] = $0.value }; SecItemAdd(insert as CFDictionary, nil)
        }
    }
    static func removeAll() {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service] as CFDictionary)
    }
    static func remove(for id: UUID) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                       kSecAttrService as String: service,
                       kSecAttrAccount as String: id.uuidString] as CFDictionary)
    }
}

struct DeviceValueSnapshot: Codable, Identifiable { var id = UUID(); var date = Date.now; var value: String }
struct BatterySnapshot: Codable, Identifiable { var id = UUID(); var date = Date.now; var health: String }

struct DeviceDocument: Identifiable, Codable {
    var id = UUID()
    var name: String
    var path: String
    var addedAt = Date.now
}

struct WishlistItem: Identifiable, Codable {
    var id = UUID()
    var name: String
    var budget: String
    var priority: String
    var notes: String
    var productURL: String = ""
    var observedPrice: String = ""
    var followupDate: Date? = nil
    enum CodingKeys: String, CodingKey { case id, name, budget, priority, notes, productURL, observedPrice, followupDate }
    init(id: UUID = UUID(), name: String, budget: String, priority: String, notes: String,
         productURL: String = "", observedPrice: String = "", followupDate: Date? = nil) {
        self.id = id; self.name = name; self.budget = budget; self.priority = priority; self.notes = notes
        self.productURL = productURL; self.observedPrice = observedPrice; self.followupDate = followupDate
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try values.decodeIfPresent(String.self, forKey: .name) ?? ""
        budget = try values.decodeIfPresent(String.self, forKey: .budget) ?? ""
        priority = try values.decodeIfPresent(String.self, forKey: .priority) ?? "Normale"
        notes = try values.decodeIfPresent(String.self, forKey: .notes) ?? ""
        productURL = try values.decodeIfPresent(String.self, forKey: .productURL) ?? ""
        observedPrice = try values.decodeIfPresent(String.self, forKey: .observedPrice) ?? ""
        followupDate = try values.decodeIfPresent(Date.self, forKey: .followupDate)
    }
}

struct RepairEntry: Identifiable, Codable {
    var id = UUID()
    var date: String
    var description: String
    var cost: String
    var parts: String = ""
    var repairer: String = ""
    enum CodingKeys: String, CodingKey { case id, date, description, cost, parts, repairer }
    init(id: UUID = UUID(), date: String, description: String, cost: String, parts: String = "", repairer: String = "") {
        self.id = id; self.date = date; self.description = description; self.cost = cost; self.parts = parts; self.repairer = repairer
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        date = try values.decodeIfPresent(String.self, forKey: .date) ?? ""
        description = try values.decodeIfPresent(String.self, forKey: .description) ?? ""
        cost = try values.decodeIfPresent(String.self, forKey: .cost) ?? ""
        parts = try values.decodeIfPresent(String.self, forKey: .parts) ?? ""
        repairer = try values.decodeIfPresent(String.self, forKey: .repairer) ?? ""
    }
}

struct DeviceTimelineEntry: Identifiable, Codable {
    var id = UUID()
    var date = Date.now
    var title: String
    var detail: String
}

private func parseTags(_ text: String) -> [String] {
    Array(Set(text.split(separator: ",").map {
        $0.trimmingCharacters(in: .whitespacesAndNewlines)
    }.filter { !$0.isEmpty })).sorted()
}

private func batteryPercent(from text: String) -> Double? {
    let normalized = text.replacingOccurrences(of: ",", with: ".")
        .filter { $0.isNumber || $0 == "." }
    return Double(normalized)
}

// Estimation locale, volontairement arrondie : elle donne un ordre de grandeur
// quand aucune valeur n'a été saisie, sans prétendre suivre les annonces du marché.
private func automaticEstimate(for device: AppleDevice) -> Double? {
    let model = device.model.lowercased()
    let base: Double
    if model.contains("iphone") {
        let generation: [(String, Double)] = [("18", 850), ("17", 650), ("16", 520), ("15", 400), ("14", 300), ("13", 220), ("12", 160), ("11", 120), ("x", 85), ("8", 55), ("7", 40), ("6", 30), ("5", 20)]
        guard let match = generation.first(where: { model.contains("iphone \($0.0)") || model.contains("iphone\($0.0)") }) else { return nil }
        base = match.1 * (model.contains("pro max") ? 1.35 : model.contains("pro") ? 1.2 : model.contains("plus") ? 1.1 : model.contains("mini") || model.contains("e") ? 0.85 : 1)
    } else if model.contains("ipad") {
        base = model.contains("pro") ? 600 : model.contains("air") ? 400 : model.contains("mini") ? 300 : 250
    } else if model.contains("watch") {
        base = model.contains("ultra") ? 500 : model.contains("series 10") || model.contains("series 11") ? 300 : 150
    } else if model.contains("macbook") || model.contains("imac") || model.contains("mac mini") {
        base = model.contains("pro") ? 900 : 600
    } else if model.contains("airpods") {
        base = model.contains("max") ? 300 : 100
    } else {
        return nil
    }

    let condition = device.condition.lowercased()
    let stateFactor: Double = condition.contains("comme neuf") ? 1 : condition.contains("bon") ? 0.82 : condition.contains("usé") ? 0.62 : condition.contains("abîmé") ? 0.4 : condition.contains("pièces") ? 0.2 : 0.7
    let storageText = device.storage.lowercased()
    let capacityFactor = storageText.contains("2 to") || storageText.contains("2tb") ? 1.2 : storageText.contains("1 to") || storageText.contains("1tb") ? 1.12 : storageText.contains("512") ? 1.06 : storageText.contains("256") ? 1.03 : 1
    let batteryFactor: Double = (batteryPercent(from: device.batteryHealth).map { $0 < 70 ? 0.8 : $0 < 80 ? 0.9 : 1 } ?? 1)
    let repairFactor = device.repairsTodo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? 1 : 0.75
    return ((base * stateFactor * capacityFactor * batteryFactor * repairFactor) / 10).rounded() * 10
}

private func collectionEstimate(for device: AppleDevice) -> Double? {
    let entered = device.estimatedValue.replacingOccurrences(of: ",", with: ".")
    if let manual = Double(entered.filter { $0.isNumber || $0 == "." }), manual > 0 { return manual }
    return automaticEstimate(for: device)
}

private func formatEuro(_ amount: Double) -> String {
    amount.formatted(.currency(code: "EUR").locale(Locale(identifier: "fr_FR")))
}

private struct ExportField: Identifiable {
    let id: String
    let title: String
}

private let exportFieldOptions: [ExportField] = [
    .init(id: "model", title: "Modèle"), .init(id: "identifier", title: "Identifiant"),
    .init(id: "aNumber", title: "Numéro A"), .init(id: "partNumber", title: "Référence commerciale"),
    .init(id: "storage", title: "Stockage"), .init(id: "color", title: "Couleur"),
    .init(id: "serial", title: "Numéro de série"), .init(id: "ios", title: "Version iOS / iPadOS"),
    .init(id: "condition", title: "État"), .init(id: "battery", title: "Batterie"),
    .init(id: "accessories", title: "Autres accessoires"), .init(id: "box", title: "Boîte"),
    .init(id: "charger", title: "Chargeur"), .init(id: "invoice", title: "Facture"),
    .init(id: "maintenance", title: "Prochain entretien"), .init(id: "warranty", title: "Fin de garantie"),
    .init(id: "repairsDone", title: "Réparations effectuées"), .init(id: "repairsTodo", title: "Réparations à prévoir"),
    .init(id: "repairHistory", title: "Historique des réparations"), .init(id: "estimatedValue", title: "Valeur estimée"),
    .init(id: "purchaseDate", title: "Date d’achat"), .init(id: "purchasePrice", title: "Prix d’achat"),
    .init(id: "notes", title: "Notes"), .init(id: "jailbreak", title: "Jailbreak"),
    .init(id: "shsh", title: "Blobs SHSH"), .init(id: "tags", title: "Étiquettes")
]

private func exportValue(_ key: String, from d: AppleDevice, hideSerial: Bool) -> String {
    switch key {
    case "model": d.model
    case "identifier": d.identifier
    case "aNumber": d.aNumber
    case "partNumber": d.partNumber
    case "storage": d.storage
    case "color": d.color
    case "serial": hideSerial ? maskedSerial(d.serial) : d.serial
    case "ios": d.ios
    case "condition": d.condition
    case "battery": d.batteryHealth.isEmpty ? "" : d.batteryHealth + "%"
    case "accessories": d.accessories
    case "box": d.hasBox ? "Oui" : "Non"
    case "charger": d.hasCharger ? "Oui" : "Non"
    case "invoice": d.hasInvoice ? "Oui" : "Non"
    case "maintenance": d.maintenanceDate?.formatted(date: .numeric, time: .omitted) ?? ""
    case "warranty": d.warrantyEndDate?.formatted(date: .numeric, time: .omitted) ?? ""
    case "repairsDone": d.repairsDone
    case "repairsTodo": d.repairsTodo
    case "repairHistory": d.repairHistory.map { "\($0.date) \($0.description) \($0.cost) €" }.joined(separator: " | ")
    case "estimatedValue": collectionEstimate(for: d).map(formatEuro) ?? ""
    case "purchaseDate": d.purchaseDate
    case "purchasePrice": d.purchasePrice
    case "notes": d.notes
    case "jailbreak": d.jailbreak
    case "shsh": d.shsh
    case "tags": d.tags.joined(separator: ", ")
    default: ""
    }
}

private func maskedSerial(_ serial: String) -> String {
    guard !serial.isEmpty else { return "" }
    guard serial.count > 4 else { return String(repeating: "•", count: serial.count) }
    return String(repeating: "•", count: serial.count - 4) + String(serial.suffix(4))
}

private struct ActivityEntry: Identifiable, Codable {
    var id = UUID()
    var date = Date.now
    var action: String
    var deviceName: String
}

private struct ActivityHistoryView: View {
    let entries: [ActivityEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Historique d’activité").font(.largeTitle.bold())
            Text("Les dernières actions effectuées sur ce profil.").foregroundStyle(.secondary)
            if entries.isEmpty {
                ContentUnavailableView("Aucune activité", systemImage: "clock.arrow.circlepath",
                    description: Text("Les ajouts et modifications apparaîtront ici."))
            } else {
                List(entries) { entry in
                    HStack(spacing: 14) {
                        Image(systemName: entry.action == "Réparation ajoutée" ? "wrench.and.screwdriver" : "square.stack.3d.up")
                            .foregroundStyle(.tint).frame(width: 24)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(entry.action).font(.headline)
                            Text(entry.deviceName).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(entry.date, format: .dateTime.day().month(.abbreviated).year().hour().minute())
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 5)
                }
                .listStyle(.inset)
            }
            Spacer(minLength: 0)
        }
        .padding(28)
        .navigationTitle("Historique")
    }
}

private struct DeviceShortcutView: View {
    let title: String
    let symbol: String
    let emptyMessage: String
    let devices: [AppleDevice]
    let detail: (AppleDevice) -> String
    let onSelect: (UUID) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(title, systemImage: symbol).font(.largeTitle.bold())
            if devices.isEmpty {
                ContentUnavailableView(title, systemImage: symbol, description: Text(emptyMessage))
            } else {
                List(devices) { device in
                    Button { onSelect(device.id) } label: {
                        HStack(spacing: 12) {
                            DeviceImage(device: device).frame(width: 44, height: 48)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(device.model).font(.headline)
                                Text(detail(device)).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                            }
                            Spacer()
                            Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                        }
                        .contentShape(Rectangle())
                        .padding(.vertical, 4)
                    }
                    .buttonStyle(.plain)
                }
                .listStyle(.inset)
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .navigationTitle(title)
    }
}

private struct DuplicateDevicesView: View {
    let devices: [AppleDevice]
    let onSelect: (UUID) -> Void
    private var groups: [[AppleDevice]] {
        Dictionary(grouping: devices.filter { !$0.serial.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) {
            $0.serial.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        }.values.filter { $0.count > 1 }.sorted { ($0.first?.model ?? "") < ($1.first?.model ?? "") }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Doublons possibles").font(.largeTitle.bold())
            Text("AppleVault compare les numéros de série. Vérifie les fiches avant d’en supprimer une.")
                .foregroundStyle(.secondary)
            if groups.isEmpty {
                ContentUnavailableView("Aucun doublon détecté", systemImage: "checkmark.circle",
                    description: Text("Aucun numéro de série identique dans cette collection."))
            } else {
                ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                    GroupBox("Même numéro de série : \(group[0].serial)") {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(group) { device in
                                Button { onSelect(device.id) } label: {
                                    HStack {
                                        Image(systemName: "iphone")
                                        Text(device.model.isEmpty ? "Appareil sans nom" : device.model)
                                        Spacer()
                                        Text([device.storage, device.color].filter { !$0.isEmpty }.joined(separator: " · "))
                                            .foregroundStyle(.secondary)
                                    }.contentShape(Rectangle())
                                }.buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
            Spacer()
        }.padding(28).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct WishlistView: View {
    @ObservedObject var inventory: Inventory
    @State private var name = ""
    @State private var budget = ""
    @State private var priority = "Normale"
    @State private var notes = ""
    @State private var productURL = ""
    @State private var observedPrice = ""
    @State private var followupDate = Date.now
    @State private var hasFollowupDate = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Liste de souhaits").font(.largeTitle.bold())
            Text("Garde une liste des appareils que tu aimerais ajouter à ta collection.")
                .foregroundStyle(.secondary)
            GroupBox("Ajouter un appareil souhaité") {
                VStack(alignment: .leading, spacing: 10) {
                    TextField("Nom de l’appareil", text: $name)
                    HStack {
                        TextField("Budget cible (€)", text: $budget)
                            .frame(maxWidth: 180)
                        Picker("Priorité", selection: $priority) {
                            ForEach(["Basse", "Normale", "Haute"], id: \.self) { Text($0) }
                        }.frame(maxWidth: 220)
                    }
                    TextField("Notes (état recherché, stockage, couleur…)", text: $notes)
                    TextField("Lien vers l’annonce ou la fiche", text: $productURL)
                    TextField("Prix repéré (€)", text: $observedPrice)
                    Toggle("Me rappeler de suivre cette annonce", isOn: $hasFollowupDate)
                    if hasFollowupDate { DatePicker("Date de suivi", selection: $followupDate, displayedComponents: .date) }
                    Button("Ajouter à ma liste", systemImage: "plus.circle.fill") {
                        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !trimmed.isEmpty else { return }
                        inventory.addWish(WishlistItem(name: trimmed, budget: budget, priority: priority, notes: notes,
                            productURL: productURL, observedPrice: observedPrice, followupDate: hasFollowupDate ? followupDate : nil))
                        name = ""; budget = ""; priority = "Normale"; notes = ""; productURL = ""; observedPrice = ""; hasFollowupDate = false
                    }.disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }.padding(.vertical, 4)
            }
            if inventory.wishlist.isEmpty {
                ContentUnavailableView("Ta liste est vide", systemImage: "star",
                    description: Text("Ajoute un modèle avec un budget ou une priorité pour le retrouver facilement."))
            } else {
                ForEach(inventory.wishlist) { item in
                    GroupBox {
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 5) {
                                Text(item.name).font(.headline)
                                Text([item.budget.isEmpty ? nil : "Budget : \(item.budget) €", "Priorité : \(item.priority)"]
                                    .compactMap { $0 }.joined(separator: " · "))
                                    .font(.caption).foregroundStyle(.secondary)
                                if !item.notes.isEmpty { Text(item.notes).font(.callout) }
                                if !item.observedPrice.isEmpty { Text("Prix repéré : \(item.observedPrice) €").font(.caption) }
                                if let date = item.followupDate { Text("Suivi le \(date.formatted(date: .abbreviated, time: .omitted))").font(.caption).foregroundStyle(.secondary) }
                                if let url = URL(string: item.productURL), !item.productURL.isEmpty { Link("Ouvrir l’annonce", destination: url) }
                            }
                            Spacer()
                            Button("Supprimer", systemImage: "trash", role: .destructive) { inventory.removeWish(item) }
                                .labelStyle(.iconOnly).help("Supprimer de la liste de souhaits")
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            Spacer(minLength: 0)
        }.padding(28).frame(maxWidth: 850, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct AppleCatalogItem: Identifiable {
    let model: String
    let productPage: String
    let imageURL: String?
    let aNumber: String?
    var id: String { model }

    init(model: String, productPage: String, imageURL: String?, aNumber: String? = nil) {
        self.model = model
        self.productPage = productPage
        self.imageURL = imageURL
        self.aNumber = aNumber
    }

    static let all: [AppleCatalogItem] = [
        .init(model: "iPhone Duo", productPage: "https://www.apple.com/iphone-duo/specs/", imageURL: "https://store.storeimages.cdn-apple.com/1/as-images.apple.com/is/iphone-compare-iphone-duo-202609?.v=M0dlUVBobHVpY1h1dmlaR3RZekpENmZPZm9YejBValJVbXlTNDNkM1pFVjE5VXk1QVF5NWxrMFlTNWNpV2huNVM0TjRWdzF2UjRGVEY0c3dBQVZ6VFFlcU5xMENJdDhjbzVtS3hXU1dQS3c&fmt=png-alpha&hei=512&wid=400"),
        .init(model: "iPhone 18 Pro Max", productPage: "https://www.apple.com/iphone-18-pro/specs/", imageURL: "https://store.storeimages.cdn-apple.com/1/as-images.apple.com/is/iphone-compare-iphone-18-pro-202609?.v=M0dlUVBobHVpY1h1dmlaR3RZekpEMEhRUmlKNkhhdE80VTZIL1ZUdjd2eUpxQWhXdDZiUERGcnlNZW9hNkhxRmJPbDJJWDFrVGJEYlIxTitTcHhVWldHUUw4RnF3MmwyMUVGYm13ODRTWXlINUhveGhFc1lXWld4RkQ2dkFBMi8&fmt=png-alpha&hei=512&wid=400", aNumber: "A3473 / A3718 / A3717"),
        .init(model: "iPhone 18 Pro", productPage: "https://www.apple.com/iphone-18-pro/specs/", imageURL: "https://store.storeimages.cdn-apple.com/1/as-images.apple.com/is/iphone-compare-iphone-18-pro-202609?.v=M0dlUVBobHVpY1h1dmlaR3RZekpEMEhRUmlKNkhhdE80VTZIL1ZUdjd2eUpxQWhXdDZiUERGcnlNZW9hNkhxRmJPbDJJWDFrVGJEYlIxTitTcHhVWldHUUw4RnF3MmwyMUVGYm13ODRTWXlINUhveGhFc1lXWld4RkQ2dkFBMi8&fmt=png-alpha&hei=512&wid=400", aNumber: "A3472 / A3713 / A3715 / A3714"),
        .init(model: "iPhone Air", productPage: "https://www.apple.com/iphone-air/specs/", imageURL: "https://store.storeimages.cdn-apple.com/1/as-images.apple.com/is/iphone-compare-iphone-air-202609?.v=M0dlUVBobHVpY1h1dmlaR3RZekpEMC9lSXF0eXpIalRkVVR5QXkvMTY3bDE5VXk1QVF5NWxrMFlTNWNpV2huNVM0TjRWdzF2UjRGVEY0c3dBQVZ6VFY3NC9UKzZjWlgwWjRhTEZ0Rlk0ZFk&fmt=png-alpha&hei=512&wid=400"),
        .init(model: "iPhone 17 Pro Max", productPage: "https://www.apple.com/iphone-17-pro/specs/", imageURL: nil, aNumber: "A3257 / A3525 / A3527 / A3526"),
        .init(model: "iPhone 17 Pro", productPage: "https://www.apple.com/iphone-17-pro/specs/", imageURL: nil, aNumber: "A3256 / A3522 / A3524 / A3523"),
        .init(model: "iPhone 17", productPage: "https://www.apple.com/iphone-17/specs/", imageURL: "https://store.storeimages.cdn-apple.com/1/as-images.apple.com/is/iphone-compare-iphone-17-202609?.v=M0dlUVBobHVpY1h1dmlaR3RZekpEL1l5N1hFTy9RTVZvRXBQbUJ5QTZYMUxxZU5scXpES1hnUm96ckN1R2pZN215d1FhSDJ0bkR0ZGZtUjZJNmFveGJIT1NwVjArc3diTWlTKzkwUStjL0U&fmt=png-alpha&hei=512&wid=400", aNumber: "A3258 / A3519 / A3521 / A3520"),
        .init(model: "iPhone 17e", productPage: "https://www.apple.com/iphone-17e/specs/", imageURL: "https://store.storeimages.cdn-apple.com/1/as-images.apple.com/is/iphone-compare-iphone-17e-202609?.v=M0dlUVBobHVpY1h1dmlaR3RZekpEeVVieTZWd1FNWlkrMERhdjh2VWpuVjE5VXk1QVF5NWxrMFlTNWNpV2huNVM0TjRWdzF2UjRGVEY0c3dBQVZ6VFpFNTBaaXJZQTgyQTZVTHN4dGxYRXM&fmt=png-alpha&hei=512&wid=400", aNumber: "A3575 / A3635 / A3634"),
        .init(model: "iPhone 16 Pro Max", productPage: "https://support.apple.com/en-us/121032", imageURL: nil, aNumber: "A3084 / A3295 / A3297 / A3296"),
        .init(model: "iPhone 16 Pro", productPage: "https://support.apple.com/en-us/121031", imageURL: nil, aNumber: "A3083 / A3292 / A3294 / A3293"),
        .init(model: "iPhone 16 Plus", productPage: "https://support.apple.com/en-us/121030", imageURL: nil, aNumber: "A3082 / A3289 / A3291 / A3290"),
        .init(model: "iPhone 16", productPage: "https://support.apple.com/en-us/121029", imageURL: nil, aNumber: "A3081 / A3286 / A3288 / A3287"),
        .init(model: "iPhone 16e", productPage: "https://www.apple.com/iphone-16e/specs/", imageURL: nil, aNumber: "A3212 / A3408 / A3410 / A3409"),
        .init(model: "iPhone 15 Pro Max", productPage: "https://support.apple.com/en-us/111828", imageURL: nil, aNumber: "A2849 / A3105 / A3108 / A3106"),
        .init(model: "iPhone 15 Pro", productPage: "https://support.apple.com/en-us/111829", imageURL: nil, aNumber: "A2848 / A3101 / A3104 / A3102"),
        .init(model: "iPhone 15 Plus", productPage: "https://support.apple.com/en-us/111830", imageURL: nil, aNumber: "A2847 / A3093 / A3096 / A3094"),
        .init(model: "iPhone 15", productPage: "https://support.apple.com/en-us/111831", imageURL: nil, aNumber: "A2846 / A3089 / A3092 / A3090"),
        .init(model: "iPhone 14 Pro / Pro Max", productPage: "https://support.apple.com/en-us/111849", imageURL: nil),
        .init(model: "iPhone 14 / 14 Plus", productPage: "https://support.apple.com/en-us/111850", imageURL: nil),
        .init(model: "iPhone 13 (toutes versions)", productPage: "https://support.apple.com/en-us/111872", imageURL: nil),
        .init(model: "iPhone 12 (toutes versions)", productPage: "https://support.apple.com/en-us/111876", imageURL: nil),
        .init(model: "iPhone 11 (toutes versions)", productPage: "https://support.apple.com/en-us/111865", imageURL: nil),
        .init(model: "iPhone X / XS / XR", productPage: "https://support.apple.com/en-us/111864", imageURL: nil),
        .init(model: "iPhone 8 / 8 Plus", productPage: "https://support.apple.com/en-us/111976", imageURL: nil),
        .init(model: "iPhone 7 / 7 Plus", productPage: "https://support.apple.com/en-us/111958", imageURL: nil),
        .init(model: "iPhone 6 / 6s / SE", productPage: "https://support.apple.com/en-us/111954", imageURL: nil),
        .init(model: "iPhone 5 / 5s / 5c", productPage: "https://support.apple.com/en-us/111935", imageURL: nil),
        .init(model: "iPad", productPage: "https://www.apple.com/ipad/compare/", imageURL: nil),
        .init(model: "iPad mini", productPage: "https://www.apple.com/ipad/compare/", imageURL: nil),
        .init(model: "iPad Air", productPage: "https://www.apple.com/ipad/compare/", imageURL: nil),
        .init(model: "iPad Pro", productPage: "https://www.apple.com/ipad/compare/", imageURL: nil),
        .init(model: "MacBook / iMac / Mac mini", productPage: "https://www.apple.com/mac/compare/", imageURL: nil),
        .init(model: "Apple Watch", productPage: "https://www.apple.com/watch/compare/", imageURL: nil),
        .init(model: "AirPods / Apple TV / autre", productPage: "https://www.apple.com/airpods/compare/", imageURL: nil)
    ]
}

@MainActor
final class Inventory: ObservableObject {
    @Published var devices: [AppleDevice] = [] {
        didSet { save() }
    }
    @Published fileprivate var activities: [ActivityEntry] = []
    @Published var wishlist: [WishlistItem] = [] { didSet { saveWishlist() } }

    private var activeProfileID: UUID?
    private let migrationKey = "AppleVault.collectionsMigrated"
    private var rootDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AppleVault", isDirectory: true)
    }
    private var legacyFile: URL { rootDirectory.appendingPathComponent("devices.json") }
    private var wishlistFile: URL {
        rootDirectory.appendingPathComponent("Collections", isDirectory: true)
            .appendingPathComponent("\(activeProfileID?.uuidString ?? "default")-wishlist.json")
    }
    private var collectionSavingEnabled: Bool {
        UserDefaults.standard.object(forKey: "appleVault.collectionSavingEnabled") == nil ||
            UserDefaults.standard.bool(forKey: "appleVault.collectionSavingEnabled")
    }
    private var automaticBackupsEnabled: Bool {
        UserDefaults.standard.object(forKey: "appleVault.automaticBackupsEnabled") == nil ||
            UserDefaults.standard.bool(forKey: "appleVault.automaticBackupsEnabled")
    }
    private var backupDirectory: URL {
        guard let activeProfileID else { return rootDirectory.appendingPathComponent("Backups", isDirectory: true) }
        return rootDirectory.appendingPathComponent("Backups", isDirectory: true)
            .appendingPathComponent(activeProfileID.uuidString, isDirectory: true)
    }
    var recentBackupFiles: [URL] {
        ((try? FileManager.default.contentsOfDirectory(at: backupDirectory,
            includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles])) ?? [])
            .filter { $0.pathExtension == "json" }
            .sorted {
                let first = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                let second = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                return first > second
            }
    }
    var automaticBackupCount: Int { recentBackupFiles.count }

    func revealAutomaticBackups() {
        try? FileManager.default.createDirectory(at: backupDirectory, withIntermediateDirectories: true)
        NSWorkspace.shared.open(backupDirectory)
    }

    init() {
        if let data = try? Data(contentsOf: legacyFile),
           let decoded = try? JSONDecoder().decode([AppleDevice].self, from: data) {
            devices = decoded
        }
    }

    func activate(profileID: UUID) {
        guard activeProfileID != profileID else { return }
        activeProfileID = profileID
        let collections = rootDirectory.appendingPathComponent("Collections", isDirectory: true)
        try? FileManager.default.createDirectory(at: collections, withIntermediateDirectories: true)
        let destination = collections.appendingPathComponent("\(profileID.uuidString).json")
        let activityFile = collections.appendingPathComponent("\(profileID.uuidString)-history.json")
        if let data = try? Data(contentsOf: wishlistFile),
           let saved = try? JSONDecoder().decode([WishlistItem].self, from: data) {
            wishlist = saved
        } else {
            wishlist = []
        }
        if let data = try? Data(contentsOf: activityFile),
           let saved = try? JSONDecoder().decode([ActivityEntry].self, from: data) {
            activities = saved
        } else {
            activities = []
        }

        if let data = try? Data(contentsOf: destination),
           let decoded = try? JSONDecoder().decode([AppleDevice].self, from: data) {
            devices = decoded
        } else if !UserDefaults.standard.bool(forKey: migrationKey) {
            if let data = try? Data(contentsOf: legacyFile),
               let decoded = try? JSONDecoder().decode([AppleDevice].self, from: data) {
                devices = decoded
            } else {
                devices = []
            }
            UserDefaults.standard.set(true, forKey: migrationKey)
            save()
        } else {
            devices = []
        }
    }

    func save() {
        guard collectionSavingEnabled, let activeProfileID else { return }
        let collections = rootDirectory.appendingPathComponent("Collections", isDirectory: true)
        try? FileManager.default.createDirectory(at: collections, withIntermediateDirectories: true)
        guard let data = try? JSONEncoder().encode(devices) else { return }
        let file = collections.appendingPathComponent("\(activeProfileID.uuidString).json")
        try? data.write(to: file, options: .atomic)
        if automaticBackupsEnabled { createAutomaticBackup(with: data) }
    }

    func record(_ action: String, deviceName: String) {
        activities.insert(ActivityEntry(action: action, deviceName: deviceName), at: 0)
        activities = Array(activities.prefix(500))
        guard collectionSavingEnabled, let activeProfileID,
              let data = try? JSONEncoder().encode(activities) else { return }
        let collections = rootDirectory.appendingPathComponent("Collections", isDirectory: true)
        try? FileManager.default.createDirectory(at: collections, withIntermediateDirectories: true)
        let file = collections.appendingPathComponent("\(activeProfileID.uuidString)-history.json")
        try? data.write(to: file, options: .atomic)
    }

    func addWish(_ item: WishlistItem) { wishlist.append(item) }

    func removeWish(_ item: WishlistItem) { wishlist.removeAll { $0.id == item.id } }

    func attachDocument(from source: URL, to deviceID: UUID) throws {
        guard let activeProfileID, let index = devices.firstIndex(where: { $0.id == deviceID }) else { return }
        let access = source.startAccessingSecurityScopedResource()
        defer { if access { source.stopAccessingSecurityScopedResource() } }
        let folder = rootDirectory.appendingPathComponent("Documents", isDirectory: true)
            .appendingPathComponent(activeProfileID.uuidString, isDirectory: true)
            .appendingPathComponent(deviceID.uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let destination = folder.appendingPathComponent(source.lastPathComponent)
        if FileManager.default.fileExists(atPath: destination.path) {
            let uniqueName = "\(UUID().uuidString.prefix(8))-\(source.lastPathComponent)"
            try FileManager.default.copyItem(at: source, to: folder.appendingPathComponent(uniqueName))
            devices[index].documents.append(DeviceDocument(name: source.lastPathComponent, path: folder.appendingPathComponent(uniqueName).path))
        } else {
            try FileManager.default.copyItem(at: source, to: destination)
            devices[index].documents.append(DeviceDocument(name: source.lastPathComponent, path: destination.path))
        }
    }

    private func saveWishlist() {
        guard collectionSavingEnabled, activeProfileID != nil,
              let data = try? JSONEncoder().encode(wishlist) else { return }
        try? FileManager.default.createDirectory(at: wishlistFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: wishlistFile, options: .atomic)
    }

    func createBackupBeforeRestore() {
        guard collectionSavingEnabled, automaticBackupsEnabled,
              let data = try? JSONEncoder().encode(devices) else { return }
        createAutomaticBackup(with: data, force: true)
    }

    private func createAutomaticBackup(with data: Data, force: Bool = false) {
        do {
            try FileManager.default.createDirectory(at: backupDirectory, withIntermediateDirectories: true)
            let frequency = UserDefaults.standard.string(forKey: "appleVault.backupFrequency") ?? "eachSave"
            let interval: TimeInterval = frequency == "weekly" ? 7 * 86_400 : frequency == "daily" ? 86_400 : 0
            if !force, interval > 0, let latest = recentBackupFiles.first,
               let date = try? latest.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate,
               Date.now.timeIntervalSince(date) < interval { return }
            let timestamp = Date.now.formatted(.iso8601.year().month().day().time(includingFractionalSeconds: true))
                .replacingOccurrences(of: ":", with: "-")
            let destination = backupDirectory.appendingPathComponent("AppleVault-\(timestamp).json")
            try data.write(to: destination, options: .atomic)
            let backups = try FileManager.default.contentsOfDirectory(at: backupDirectory,
                includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles])
                .filter { $0.pathExtension == "json" }
                .sorted { first, second in
                    let firstDate = (try? first.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                    let secondDate = (try? second.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                    return firstDate > secondDate
                }
            let retention = UserDefaults.standard.object(forKey: "appleVault.backupRetention") == nil
                ? 20 : min(100, max(1, UserDefaults.standard.integer(forKey: "appleVault.backupRetention")))
            for oldBackup in backups.dropFirst(retention) { try? FileManager.default.removeItem(at: oldBackup) }
        } catch {
            // A backup failure must never block the primary collection save.
        }
    }

    func resetAll() {
        devices = []
        activeProfileID = nil
        UserDefaults.standard.removeObject(forKey: migrationKey)
        try? FileManager.default.removeItem(at: rootDirectory)
    }
}

private struct ProfileSetupView: View {
    @ObservedObject var store: LocalProfileStore
    let onComplete: () -> Void
    var isAdditional = false
    @State private var fullName = ""
    @State private var nickname = ""
    @State private var password = ""
    @State private var confirmation = ""
    @State private var requirePassword = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "person.crop.circle.badge.checkmark").font(.system(size: 46)).foregroundStyle(.tint)
            Text("Créer mon profil local").font(.largeTitle.bold())
            Text("Tes informations restent sur ce Mac. Le mot de passe est protégé par le trousseau macOS.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary).frame(maxWidth: 420)
            Form {
                TextField("Nom complet", text: $fullName)
                TextField("Pseudo", text: $nickname)
                SecureField("Mot de passe (8 caractères minimum)", text: $password)
                SecureField("Confirmer le mot de passe", text: $confirmation)
                Toggle("Exiger le mot de passe à l’ouverture", isOn: $requirePassword)
            }.formStyle(.grouped).frame(width: 440)
            if let error { Text(error).foregroundStyle(.red).font(.callout) }
            Button("Créer le profil") { createProfile() }
                .buttonStyle(.borderedProminent).disabled(fullName.trimmingCharacters(in: .whitespaces).isEmpty || nickname.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(36).frame(minWidth: 620, minHeight: 560)
    }

    private func createProfile() {
        guard password.count >= 8 else { error = "Choisis un mot de passe d’au moins 8 caractères."; return }
        guard password == confirmation else { error = "Les deux mots de passe ne correspondent pas."; return }
        do {
            if isAdditional {
                try store.addProfile(fullName: fullName, nickname: nickname, requirePassword: requirePassword, password: password)
            } else {
                try store.save(fullName: fullName, nickname: nickname, requirePassword: requirePassword, newPassword: password)
            }
            onComplete()
        }
        catch { self.error = error.localizedDescription }
    }
}

private struct ProfileUnlockView: View {
    let profile: LocalProfile
    let profiles: [LocalProfile]
    let verify: (String) -> Bool
    let onSelectProfile: (UUID) -> Void
    let onUnlock: () -> Void
    let onDeveloperAccess: () -> Void
    @State private var password = ""
    @State private var error: String?
    @State private var showPassword = false
    private var passwordPrompt: String {
        #if DEBUG
        "Mot de passe ou code développeur"
        #else
        "Mot de passe"
        #endif
    }

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.circle.fill").font(.system(size: 54)).foregroundStyle(.tint)
            Text("AppleVault est verrouillé").font(.largeTitle.bold())
            Text("Choisis un profil, puis saisis son mot de passe pour continuer.").foregroundStyle(.secondary)
            HStack(spacing: 14) {
                Text(String(profile.nickname.prefix(1)).uppercased())
                    .font(.system(size: 25, weight: .bold, design: .rounded)).foregroundStyle(.white)
                    .frame(width: 58, height: 58).background(LinearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing), in: Circle())
                VStack(alignment: .leading, spacing: 3) {
                    Text(profile.nickname).font(.headline)
                    Text(profile.fullName).font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(12).frame(maxWidth: 320, alignment: .leading)
            .background(.quaternary.opacity(0.55), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            Picker("Profil", selection: Binding(get: { profile.id }, set: onSelectProfile)) {
                ForEach(profiles) { item in
                    Text("\(item.nickname) — \(item.fullName)").tag(item.id)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .frame(width: 300)
            HStack(spacing: 8) {
                Group {
                    if showPassword { TextField(passwordPrompt, text: $password) }
                    else { SecureField(passwordPrompt, text: $password) }
                }
                .textFieldStyle(.roundedBorder).frame(width: 250).onSubmit(unlock)
                Button { showPassword.toggle() } label: {
                    Image(systemName: showPassword ? "eye.slash" : "eye")
                }.buttonStyle(.borderless).help(showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe")
            }
            TimelineView(.periodic(from: .now, by: 30)) { timeline in
                VStack(spacing: 2) {
                    Text(timeline.date, format: .dateTime.hour().minute()).font(.system(size: 28, weight: .light, design: .rounded)).monospacedDigit()
                    Text(timeline.date, format: .dateTime.weekday(.wide).day().month(.wide).year()).font(.caption).foregroundStyle(.secondary)
                }
            }
            Text("\(profiles.count) profil\(profiles.count > 1 ? "s" : "") \(profiles.count > 1 ? "locaux" : "local")")
                .font(.caption2).foregroundStyle(.tertiary)
            #if DEBUG
            Text("Le mode développeur affiche des diagnostics sans ouvrir la collection.")
                .font(.caption).foregroundStyle(.secondary)
            #endif
            if let error { Text(error).foregroundStyle(.red) }
            Button("Déverrouiller", action: unlock).buttonStyle(.borderedProminent)
        }
        .padding(40).frame(minWidth: 560, minHeight: 590)
        .onChange(of: profile.id) { _, _ in password = ""; error = nil }
    }

    private func unlock() {
#if DEBUG
        if password == "3343" { onDeveloperAccess(); password = ""; return }
#endif
        if verify(password) { onUnlock() }
        else { error = "Mot de passe incorrect."; password = "" }
    }
}

private struct DeveloperModeView: View {
    let nickname: String
    let deviceCount: Int
    let backupsEnabled: Bool
    let savingEnabled: Bool
    let profileID: UUID?
    let backupFiles: [URL]
    let weatherCity: String
    let weatherSourceURL: String
    let updateServerURL: String
    let onExit: () -> Void
    @State private var status = "Prêt"
    @State private var backupReport = ""
    @State private var logs = DeveloperDiagnosticLog.read()
    @State private var isBusy = false
    private var appVersion: String { Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Inconnue" }
    private var buildNumber: String { Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "Inconnu" }
    private var memory: String { ByteCountFormatter.string(fromByteCount: Int64(ProcessInfo.processInfo.physicalMemory), countStyle: .memory) }
    private var architecture: String {
        #if arch(arm64)
        "Apple Silicon (arm64)"
        #elseif arch(x86_64)
        "Intel (x86_64)"
        #else
        "Inconnue"
        #endif
    }

    private var supportDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AppleVault", isDirectory: true)
    }
    private var collectionURL: URL? {
        profileID.map { supportDirectory.appendingPathComponent("Collections", isDirectory: true).appendingPathComponent("\($0.uuidString).json") }
    }
    private var diagnostics: String {
        ["AppleVault \(appVersion) (\(buildNumber))", "macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)",
         "Architecture: \(architecture)", "Profil: \(nickname)", "Appareils: \(deviceCount)",
         "Enregistrement local: \(savingEnabled ? "activé" : "désactivé")",
         "Sauvegardes auto: \(backupsEnabled && savingEnabled ? "activées" : "désactivées")",
         "Sauvegardes JSON: \(backupFiles.count)"].joined(separator: "\n")
    }

    var body: some View {
        ScrollView {
          VStack(alignment: .leading, spacing: 20) {
            HStack {
                Image(systemName: "hammer.fill").font(.largeTitle).foregroundStyle(.orange)
                VStack(alignment: .leading) {
                    Text("Mode développeur").font(.largeTitle.bold())
                    Text("Diagnostics locaux — collection verrouillée").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Quitter et reverrouiller", systemImage: "lock.fill", action: onExit)
            }
            GroupBox("AppleVault") {
                Grid(alignment: .leading, horizontalSpacing: 32, verticalSpacing: 10) {
                    diagnostic("Version", appVersion)
                    diagnostic("Build", buildNumber)
                    diagnostic("Profil actif", nickname)
                    diagnostic("Appareils", "\(deviceCount)")
                    diagnostic("Enregistrement local", savingEnabled ? "Activé" : "Désactivé")
                    diagnostic("Sauvegardes automatiques", backupsEnabled && savingEnabled ? "Activées" : "Désactivées")
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 8)
            }
            GroupBox("Mac") {
                Grid(alignment: .leading, horizontalSpacing: 32, verticalSpacing: 10) {
                    diagnostic("Système", ProcessInfo.processInfo.operatingSystemVersionString)
                    diagnostic("Architecture", architecture)
                    diagnostic("Processeurs logiques", "\(ProcessInfo.processInfo.processorCount)")
                    diagnostic("Mémoire", memory)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 8)
            }
            GroupBox("Outils développeur") {
                VStack(alignment: .leading, spacing: 12) {
                    Button("Copier les diagnostics", systemImage: "doc.on.doc") {
                        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(diagnostics, forType: .string)
                        setStatus("Diagnostics copiés dans le presse-papiers.")
                    }
                    Button("Vérifier les sauvegardes JSON", systemImage: "checkmark.icloud") { verifyBackups() }
                    if !backupReport.isEmpty { Text(backupReport).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                    Button("Ouvrir le dossier AppleVault", systemImage: "folder") {
                        try? FileManager.default.createDirectory(at: supportDirectory, withIntermediateDirectories: true)
                        NSWorkspace.shared.open(supportDirectory); setStatus("Dossier AppleVault ouvert dans le Finder.")
                    }
                    Button("Effacer le cache temporaire", systemImage: "sparkles") { clearCache() }
                    Button("Tester la source météo", systemImage: "cloud.sun") { Task { await testWeather() } }
                    Button("Tester le serveur de mises à jour", systemImage: "arrow.clockwise") { Task { await testUpdateServer() } }
                    Divider()
                    Button("Contrôler le fichier de collection", systemImage: "doc.text.magnifyingglass") { inspectCollectionFile() }
                    Button("Rechercher les anomalies de la collection", systemImage: "exclamationmark.magnifyingglass") { inspectCollectionData() }
                    Button("Vérifier les photos et documents liés", systemImage: "paperclip") { inspectAttachments() }
                    Button("Afficher le fichier de collection dans le Finder", systemImage: "doc.viewfinder") { revealCollectionFile() }
                    Button("Ouvrir le dossier des sauvegardes", systemImage: "externaldrive") { openBackups() }
                    Button("Calculer l’espace utilisé par AppleVault", systemImage: "internaldrive") { calculateStorage() }
                    Button("Inspecter le cache temporaire", systemImage: "externaldrive.badge.timemachine") { inspectCache() }
                    Button("Ouvrir le cache dans le Finder", systemImage: "folder.badge.gearshape") { openCache() }
                    Button("Copier le journal développeur", systemImage: "list.clipboard") { copyLogs() }
                    Button("Exporter un rapport technique…", systemImage: "square.and.arrow.up") { exportTechnicalReport() }
                    Button("Vérifier l’espace disque libre du Mac", systemImage: "internaldrive.fill") { inspectDiskSpace() }
                    Button("Tester l’accès à Internet", systemImage: "network") { Task { await testInternet() } }
                    Text("État : \(status)").font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
            }
            GroupBox("Fichiers locaux") {
                VStack(alignment: .leading, spacing: 8) {
                    fileRow("Collection active", collectionURL)
                    if let profileID {
                        fileRow("Liste de souhaits", supportDirectory.appendingPathComponent("Collections/\(profileID.uuidString)-wishlist.json"))
                        fileRow("Historique d’activité", supportDirectory.appendingPathComponent("Collections/\(profileID.uuidString)-history.json"))
                    }
                    fileRow("Dossier des sauvegardes", profileID.map { supportDirectory.appendingPathComponent("Backups/\($0.uuidString)") })
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
            }
            GroupBox("Journal développeur récent") {
                VStack(alignment: .leading, spacing: 8) {
                    Text(logs.isEmpty ? "Aucun événement enregistré pour le moment." : logs)
                        .font(.system(.caption, design: .monospaced)).textSelection(.enabled).lineLimit(12)
                    Button("Actualiser", systemImage: "arrow.clockwise") { logs = DeveloperDiagnosticLog.read() }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
            }
            Text("Le nettoyage ne touche qu’au cache. Les collections, photos et sauvegardes restent intactes.")
                .font(.caption).foregroundStyle(.secondary)
            Spacer(minLength: 20)
          }.padding(32).frame(maxWidth: 850, alignment: .topLeading)
        }
    }

    private func diagnostic(_ title: String, _ value: String) -> some View {
        GridRow {
            Text(title).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }

    private func fileRow(_ title: String, _ url: URL?) -> some View {
        HStack {
            Text(title).foregroundStyle(.secondary); Spacer()
            if let url, let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey, .isDirectoryKey]),
               values.isDirectory == true {
                let count = (try? FileManager.default.contentsOfDirectory(atPath: url.path).count) ?? 0
                Text("Dossier · \(count) élément(s)").font(.caption.monospacedDigit())
            } else if let url, let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
                      values.isRegularFile == true {
                Text("\(ByteCountFormatter.string(fromByteCount: Int64(values.fileSize ?? 0), countStyle: .file)) · \(values.contentModificationDate?.formatted(date: .numeric, time: .shortened) ?? "")")
                    .font(.caption.monospacedDigit())
            } else { Text("Absent").font(.caption).foregroundStyle(.tertiary) }
        }
    }

    private func setStatus(_ value: String) { status = value; DeveloperDiagnosticLog.write(value); logs = DeveloperDiagnosticLog.read() }

    private func verifyBackups() {
        let good = backupFiles.filter { (try? JSONDecoder().decode([AppleDevice].self, from: Data(contentsOf: $0))) != nil }
        let bad = backupFiles.count - good.count
        backupReport = "\(good.count) sauvegarde(s) lisible(s), \(bad) illisible(s)."
        setStatus(backupReport)
    }

    private func inspectCollectionFile() {
        guard let collectionURL else { setStatus("Aucun profil actif à contrôler."); return }
        guard let data = try? Data(contentsOf: collectionURL) else { setStatus("Le fichier de collection est absent ou illisible."); return }
        do {
            let saved = try JSONDecoder().decode([AppleDevice].self, from: data)
            setStatus("Fichier JSON valide : \(saved.count) appareil(s), \(ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file)).")
        } catch { setStatus("Le JSON de la collection ne peut pas être décodé : \(error.localizedDescription)") }
    }

    private func inspectCollectionData() {
        guard let path = collectionURL,
              let data = try? Data(contentsOf: path),
              let saved = try? JSONDecoder().decode([AppleDevice].self, from: data) else {
            setStatus("Impossible d’analyser les données enregistrées de la collection."); return
        }
        let repeatedIDs = saved.count - Set(saved.map(\.id)).count
        let serials = saved.map { $0.serial.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }.filter { !$0.isEmpty }
        let repeatedSerials = serials.count - Set(serials).count
        let unnamed = saved.filter { $0.model.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.count
        setStatus("Analyse terminée : \(repeatedIDs) identifiant(s) répété(s), \(repeatedSerials) numéro(s) de série répété(s), \(unnamed) modèle(s) sans nom.")
    }

    private func inspectAttachments() {
        guard let path = collectionURL,
              let data = try? Data(contentsOf: path),
              let saved = try? JSONDecoder().decode([AppleDevice].self, from: data) else {
            setStatus("Impossible de lire la collection pour vérifier ses pièces jointes."); return
        }
        let photos = saved.filter { !$0.photoPath.isEmpty }
        let missingPhotos = photos.filter { !FileManager.default.fileExists(atPath: $0.photoPath) }.count
        let documents = saved.flatMap(\.documents)
        let missingDocuments = documents.filter { !FileManager.default.fileExists(atPath: $0.path) }.count
        setStatus("Pièces jointes : \(photos.count - missingPhotos)/\(photos.count) photo(s) et \(documents.count - missingDocuments)/\(documents.count) document(s) présents.")
    }

    private func revealCollectionFile() {
        guard let collectionURL, FileManager.default.fileExists(atPath: collectionURL.path) else { setStatus("Le fichier de collection active est introuvable."); return }
        NSWorkspace.shared.activateFileViewerSelecting([collectionURL]); setStatus("Fichier de collection affiché dans le Finder.")
    }

    private func openBackups() {
        guard let profileID else { setStatus("Aucun profil actif."); return }
        let folder = supportDirectory.appendingPathComponent("Backups/\(profileID.uuidString)", isDirectory: true)
        do { try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true); NSWorkspace.shared.open(folder); setStatus("Dossier des sauvegardes ouvert dans le Finder.") }
        catch { setStatus("Impossible d’ouvrir le dossier des sauvegardes.") }
    }

    private func calculateStorage() {
        setStatus("Données AppleVault : \(ByteCountFormatter.string(fromByteCount: directorySize(supportDirectory), countStyle: .file)).")
    }

    private func inspectCache() {
        let cache = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("AppleVault", isDirectory: true)
        let count = ((try? FileManager.default.subpathsOfDirectory(atPath: cache.path)) ?? []).count
        setStatus("Cache : \(count) élément(s), \(ByteCountFormatter.string(fromByteCount: directorySize(cache), countStyle: .file)).")
    }

    private func openCache() {
        let cache = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("AppleVault", isDirectory: true)
        do { try FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true); NSWorkspace.shared.open(cache); setStatus("Dossier du cache ouvert dans le Finder.") }
        catch { setStatus("Impossible d’ouvrir le dossier du cache.") }
    }

    private func copyLogs() {
        guard !logs.isEmpty else { setStatus("Le journal développeur est vide."); return }
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(logs, forType: .string); setStatus("Journal développeur copié dans le presse-papiers.")
    }

    private func exportTechnicalReport() {
        let report = diagnostics + "\n\nVille météo : \(weatherCity)\nSource météo : \(weatherSourceURL)\nServeur de mises à jour : \(updateServerURL.isEmpty ? "non configuré" : updateServerURL)\n\nJournal récent :\n\(logs.isEmpty ? "Aucun événement." : logs)"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("AppleVault-Rapport-technique-\(Int(Date.now.timeIntervalSince1970)).txt")
        do { try report.write(to: url, atomically: true, encoding: .utf8); NSWorkspace.shared.activateFileViewerSelecting([url]); setStatus("Rapport technique créé dans le dossier temporaire et affiché dans le Finder.") }
        catch { setStatus("Impossible de créer le rapport technique.") }
    }

    private func directorySize(_ url: URL) -> Int64 {
        guard let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.fileSizeKey], options: [.skipsHiddenFiles]) else { return 0 }
        var total: Int64 = 0
        for case let fileURL as URL in enumerator {
            total += Int64((try? fileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        }
        return total
    }

    private func inspectDiskSpace() {
        do {
            let values = try FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory())
            let free = (values[.systemFreeSize] as? NSNumber)?.int64Value ?? 0
            setStatus("Espace libre sur le disque de démarrage : \(ByteCountFormatter.string(fromByteCount: free, countStyle: .file)).")
        } catch { setStatus("Impossible de lire l’espace disque disponible.") }
    }

    private func testInternet() async {
        guard !isBusy else { return }; isBusy = true; defer { isBusy = false }
        do {
            let url = URL(string: "https://www.apple.com")!
            let (_, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, (200..<400).contains(http.statusCode) else { throw URLError(.badServerResponse) }
            setStatus("Accès Internet fonctionnel (site Apple, HTTP \(http.statusCode)).")
        } catch { setStatus("Connexion Internet indisponible ou bloquée.") }
    }

    private func clearCache() {
        let cache = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("AppleVault", isDirectory: true)
        do {
            try FileManager.default.removeItem(at: cache)
            setStatus("Cache temporaire effacé.")
        } catch CocoaError.fileNoSuchFile { setStatus("Aucun cache à effacer.") }
        catch { setStatus("Le cache n’a pas pu être effacé.") }
    }

    private func testWeather() async {
        guard !isBusy else { return }; isBusy = true; defer { isBusy = false }
        do {
            var geocoding = URLComponents(string: "https://geocoding-api.open-meteo.com/v1/search")!
            geocoding.queryItems = [URLQueryItem(name: "name", value: weatherCity), URLQueryItem(name: "count", value: "1"),
                                    URLQueryItem(name: "language", value: "fr"), URLQueryItem(name: "format", value: "json")]
            let (geoData, geoResponse) = try await URLSession.shared.data(from: geocoding.url!)
            guard (geoResponse as? HTTPURLResponse)?.statusCode == 200,
                  let location = (try JSONDecoder().decode(GeoSearchResponse.self, from: geoData).results ?? []).first else {
                throw URLError(.cannotFindHost)
            }
            let root = weatherSourceURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            guard var components = URLComponents(string: "\(root)/v1/forecast") else { throw URLError(.badURL) }
            components.queryItems = [URLQueryItem(name: "latitude", value: String(location.latitude)),
                                     URLQueryItem(name: "longitude", value: String(location.longitude)),
                                     URLQueryItem(name: "current", value: "temperature_2m")]
            guard let url = components.url else { throw URLError(.badURL) }
            let (_, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw URLError(.badServerResponse) }
            setStatus("Source météo joignable pour \(location.name) (HTTP 200).")
        } catch { setStatus("Échec du test météo. Vérifie la source configurée. Aucun changement n’a été effectué.") }
    }

    private func testUpdateServer() async {
        guard !isBusy else { return }; isBusy = true; defer { isBusy = false }
        guard let url = URL(string: updateServerURL), url.scheme?.lowercased() == "https" else {
            setStatus("Adresse HTTPS du serveur de mises à jour absente ou invalide."); return
        }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  let manifest = try? JSONDecoder().decode(UpdateManifest.self, from: data) else { throw URLError(.badServerResponse) }
            setStatus("Serveur joignable. Version annoncée : \(manifest.version).")
        } catch { setStatus("Échec du test du serveur de mises à jour.") }
    }
}

private enum DeveloperDiagnosticLog {
    private static var url: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AppleVault", isDirectory: true).appendingPathComponent("developer.log")
    }
    static func write(_ message: String) {
        let line = "\(Date.now.formatted(date: .numeric, time: .standard)) — \(message)\n"
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile(); handle.write(Data(line.utf8)); try? handle.close()
        } else { try? Data(line.utf8).write(to: url, options: .atomic) }
    }
    static func read() -> String {
        guard let data = try? Data(contentsOf: url), let value = String(data: data, encoding: .utf8) else { return "" }
        return value.split(separator: "\n").suffix(30).joined(separator: "\n")
    }
}

private struct ProfileEditorView: View {
    @ObservedObject var store: LocalProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var fullName: String
    @State private var nickname: String
    @State private var requirePasswordOnLaunch: Bool
    @State private var newPassword = ""
    @State private var confirmation = ""
    @State private var error: String?

    init(store: LocalProfileStore) {
        self.store = store
        let profile = store.profile ?? LocalProfile(fullName: "", nickname: "", requirePasswordOnLaunch: false)
        _fullName = State(initialValue: profile.fullName)
        _nickname = State(initialValue: profile.nickname)
        _requirePasswordOnLaunch = State(initialValue: profile.requirePasswordOnLaunch)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Mon profil").font(.title.bold())
            Form {
                TextField("Nom complet", text: $fullName)
                TextField("Pseudo", text: $nickname)
                Toggle("Exiger le mot de passe à l’ouverture", isOn: $requirePasswordOnLaunch)
                SecureField("Nouveau mot de passe (laisser vide pour conserver)", text: $newPassword)
                SecureField("Confirmer le nouveau mot de passe", text: $confirmation)
            }.formStyle(.grouped)
            Text("Profil stocké uniquement sur ce Mac. Le mot de passe est conservé dans le trousseau macOS.")
                .font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).font(.callout).foregroundStyle(.red) }
            HStack {
                Button("Verrouiller maintenant") { dismiss(); NotificationCenter.default.post(name: .appleVaultLock, object: nil) }
                Spacer()
                Button("Annuler") { dismiss() }
                Button("Enregistrer") { save() }.buttonStyle(.borderedProminent)
            }
        }.padding(24).frame(width: 520, height: 460)
    }

    private func save() {
        if !newPassword.isEmpty {
            guard newPassword.count >= 8 else { error = "Le mot de passe doit contenir au moins 8 caractères."; return }
            guard newPassword == confirmation else { error = "Les deux mots de passe ne correspondent pas."; return }
        }
        do {
            try store.save(fullName: fullName, nickname: nickname, requirePassword: requirePasswordOnLaunch,
                           newPassword: newPassword.isEmpty ? nil : newPassword)
            dismiss()
        } catch { self.error = error.localizedDescription }
    }
}

private extension Notification.Name { static let appleVaultLock = Notification.Name("AppleVaultLock") }

private struct SettingsView: View {
    @Binding var appearance: String
    @Binding var language: String
    @Binding var weatherCity: String
    @Binding var weatherSourceURL: String
    @Binding var updateServerURL: String
    @Binding var automaticUpdateChecks: Bool
    @ObservedObject var updateChecker: UpdateChecker
    @ObservedObject var profileStore: LocalProfileStore
    let automaticBackupCount: Int
    let backupFiles: [URL]
    let showBackupFolder: () -> Void
    let restoreBackup: (URL) -> Void
    let resetApp: () -> Void
    let addProfile: () -> Void
    @Binding var backupFrequency: String
    @Binding var backupRetention: Int
    @Binding var automaticBackupsEnabled: Bool
    @Binding var collectionSavingEnabled: Bool
    @Binding var alertLowBattery: Bool
    @Binding var alertWarranty: Bool
    @Binding var alertIncomplete: Bool
    @Binding var hideSerialNumbers: Bool
    @Binding var homeCardOrder: String
    @Binding var exportFieldsPreference: String
    @State private var showResetConfirmation = false
    @State private var backupToRestore: URL?

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.5.2"
    }

    private var processorName: String {
        #if arch(arm64)
        "Apple Silicon"
        #elseif arch(x86_64)
        "Intel"
        #else
        "Inconnu"
        #endif
    }

    private var memoryDescription: String {
        ByteCountFormatter.string(fromByteCount: Int64(ProcessInfo.processInfo.physicalMemory), countStyle: .memory)
    }

    private var dataSettingsSection: some View {
            Section("Données") {
                Label(
                    collectionSavingEnabled && automaticBackupsEnabled
                        ? "Sauvegardes automatiques activées"
                        : "Sauvegardes automatiques désactivées",
                    systemImage: collectionSavingEnabled && automaticBackupsEnabled
                        ? "checkmark.icloud.fill"
                        : "xmark.icloud.fill"
                )
                .foregroundColor(collectionSavingEnabled && automaticBackupsEnabled ? .green : .red)
                Text("L’équipe de Loop décline toute responsabilité en cas de perte de données.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle("Enregistrer la collection sur ce Mac", isOn: $collectionSavingEnabled)
                Text(collectionSavingEnabled
                     ? "Les modifications de la collection et l’historique sont enregistrés localement."
                     : "Les nouveaux changements ne seront pas conservés après fermeture. Les fichiers déjà enregistrés restent sur le Mac.")
                    .font(.caption).foregroundColor(collectionSavingEnabled ? .secondary : .orange)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle("Créer des sauvegardes automatiques", isOn: $automaticBackupsEnabled)
                    .disabled(!collectionSavingEnabled)
                Text("Cette option contrôle les copies de sauvegarde. L’enregistrement normal de la collection est réglé séparément ci-dessus.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Picker("Fréquence des sauvegardes", selection: $backupFrequency) {
                    Text("À chaque enregistrement").tag("eachSave")
                    Text("Une fois par jour").tag("daily")
                    Text("Une fois par semaine").tag("weekly")
                }
                .disabled(!collectionSavingEnabled || !automaticBackupsEnabled)
                Stepper("Copies à conserver : \(backupRetention)", value: $backupRetention, in: 1...100)
                    .disabled(!collectionSavingEnabled || !automaticBackupsEnabled)
                Text("\(automaticBackupCount) sauvegarde(s) locale(s) conservée(s) pour ce profil.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Afficher le dossier des sauvegardes…", systemImage: "folder") {
                    showBackupFolder()
                }
                if !backupFiles.isEmpty {
                    Text("Restaurer une ancienne sauvegarde").font(.subheadline.weight(.semibold))
                    ForEach(backupFiles, id: \.path) { file in
                        HStack {
                            Text(file.lastPathComponent).font(.caption).lineLimit(1)
                            Spacer()
                            Button("Restaurer") { backupToRestore = file }
                                .buttonStyle(.bordered)
                        }
                    }
                }
                Button("Réinitialiser AppleVault…", systemImage: "trash", role: .destructive) {
                    showResetConfirmation = true
                }
                Text("Supprime toutes les collections, les photos enregistrées et les profils de ce Mac.")
                    .font(.caption).foregroundStyle(.secondary)
            }
    }

    private var updateSettingsSection: some View {
    Section("Mises à jour") {
                LabeledContent("Version actuelle", value: appVersion)
                TextField("Adresse du serveur de mises à jour", text: $updateServerURL)
                    .textContentType(.URL)
                Text("Le serveur doit renvoyer un JSON avec version et, facultativement, downloadURL. Exemple : {\"version\":\"1.5.3\",\"downloadURL\":\"https://exemple.fr\"}")
                    .font(.caption).foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Toggle("Vérifier automatiquement au démarrage", isOn: $automaticUpdateChecks)
                Text("La vérification automatique ne fonctionne que si un serveur est configuré. AppleVault ne télécharge ni n’installe les mises à jour automatiquement.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button(updateChecker.isChecking ? "Vérification en cours…" : "Rechercher les mises à jour", systemImage: "arrow.clockwise") {
                    updateChecker.check(urlString: updateServerURL, currentVersion: appVersion)
                }
                .disabled(updateChecker.isChecking)
                if let updateCheckResult = updateChecker.result {
                    switch updateCheckResult {
                    case .upToDate:
                        Label("AppleVault est déjà à jour.", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    case .updateAvailable(let version, let downloadURL):
                        VStack(alignment: .leading, spacing: 7) {
                            Label("La version \(version) est disponible. Rends-toi sur le site depuis lequel tu as téléchargé AppleVault et suis les étapes indiquées.", systemImage: "arrow.down.circle.fill")
                                .foregroundStyle(.primary)
                                .fixedSize(horizontal: false, vertical: true)
                            if let downloadURL {
                                Link("Ouvrir la page de téléchargement", destination: downloadURL)
                            }
                        }
                    case .error(let message):
                        Label(message, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            Label("Réglages", systemImage: "gearshape.fill").font(.largeTitle.bold())
            Form {
                Section("Apparence") {
                    Picker("Thème", selection: $appearance) {
                        Text("Suivre le système").tag("system")
                        Text("Clair").tag("light")
                        Text("Sombre").tag("dark")
                    }
                    .pickerStyle(.segmented)
                }
                Section("Langue") {
                    Picker("Langue de l’application", selection: $language) {
                        Text("Français").tag("fr")
                    }
                    .pickerStyle(.menu)
                    Text("D’autres langues pourront être ajoutées plus tard.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                updateSettingsSection
                Section("Accueil") {
                    TextField("Ville pour la météo et l’horloge", text: $weatherCity)
                        .help("La météo et l’heure locale de cette ville apparaîtront sur l’accueil.")
                    TextField("Adresse de la source météo", text: $weatherSourceURL)
                        .textContentType(.URL)
                    Text("Utilise un serveur compatible avec l’API Open-Meteo. La recherche du nom de ville continue d’utiliser le géocodage Open-Meteo.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Rétablir Open-Meteo") { weatherSourceURL = "https://api.open-meteo.com" }
                    Text("Choisis les cartes affichées et change leur ordre avec les flèches.")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(["devices", "value", "alerts", "favorites", "repairs"], id: \.self) { key in
                        HStack {
                            Toggle(homeCardTitle(key), isOn: Binding(
                                get: { homeCardIDs.contains(key) },
                                set: { setHomeCard(key, enabled: $0) }
                            ))
                            Button { moveHomeCard(key, offset: -1) } label: { Image(systemName: "arrow.up") }
                                .disabled(!homeCardIDs.contains(key) || homeCardIDs.first == key)
                                .help("Déplacer vers le haut")
                            Button { moveHomeCard(key, offset: 1) } label: { Image(systemName: "arrow.down") }
                                .disabled(!homeCardIDs.contains(key) || homeCardIDs.last == key)
                                .help("Déplacer vers le bas")
                        }
                    }
                }
                Section("Alertes") {
                    Toggle("Signaler les batteries sous 80%", isOn: $alertLowBattery)
                    Toggle("Signaler les garanties qui expirent", isOn: $alertWarranty)
                    Toggle("Signaler les fiches incomplètes", isOn: $alertIncomplete)
                    Text("Les alertes ignorées individuellement restent masquées pour chaque appareil.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Confidentialité et exports") {
                    Toggle("Masquer les numéros de série dans l’app et les exports", isOn: $hideSerialNumbers)
                    Text("Le numéro complet reste masqué dans les fiches et les exports.")
                        .font(.caption).foregroundStyle(.secondary)
                    DisclosureGroup("Champs à inclure dans les exports PDF et CSV") {
                        ForEach(exportFieldOptions) { field in
                            Toggle(field.title, isOn: Binding(
                                get: { exportFieldIDs.contains(field.id) },
                                set: { setExportField(field.id, enabled: $0) }
                            ))
                        }
                    }
                    Text("Les sauvegardes JSON complètes gardent tous les champs pour permettre une restauration fidèle.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Sources météo") {
                    Text("Par défaut, les prévisions viennent d’Open-Meteo et les libellés sont traduits en français. Les conditions affichées sont basées sur des modèles météo. La recherche de ville utilise toujours le géocodage Open-Meteo.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Link("Open-Meteo — site et documentation", destination: URL(string: "https://open-meteo.com/")!)
                    Link("Licence des données Open-Meteo : CC BY 4.0", destination: URL(string: "https://creativecommons.org/licenses/by/4.0/")!)
                    Text("Si tu configures une autre source compatible, vérifie sa licence et ses règles d’attribution.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Informations système") {
                    LabeledContent("macOS", value: ProcessInfo.processInfo.operatingSystemVersionString)
                    LabeledContent("Processeur", value: processorName)
                    LabeledContent("Cœurs disponibles", value: "\(ProcessInfo.processInfo.activeProcessorCount)")
                    LabeledContent("Mémoire", value: memoryDescription)
                }
                Section("Profils") {
                    ForEach(profileStore.profiles) { profile in
                        Button {
                            profileStore.switchProfile(to: profile.id)
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(profile.nickname).foregroundStyle(.primary)
                                    Text(profile.fullName).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if profile.id == profileStore.activeProfileID {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.tint)
                                }
                            }
                        }
                        .buttonStyle(.plain)
                    }
                    Button("Ajouter un profil…", systemImage: "person.badge.plus", action: addProfile)
                }
                Section("Contact et suggestions") {
                    Text("Une idée de fonction ou une remarque ? Écris à Loop pour proposer une amélioration d’AppleVault.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Link(destination: URL(string: "mailto:loop7936@gmail.com?subject=Suggestion%20AppleVault")!) {
                        Label("Contacter Loop", systemImage: "envelope.fill")
                    }
                    Text("loop7936@gmail.com").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                dataSettingsSection
            }
            .formStyle(.grouped)
            Spacer(minLength: 0)
        }
        .padding(28)
        .frame(maxWidth: 720, maxHeight: .infinity, alignment: .topLeading)
        .alert("Réinitialiser AppleVault ?", isPresented: $showResetConfirmation) {
            Button("Annuler", role: .cancel) { }
            Button("Tout supprimer", role: .destructive, action: resetApp)
        } message: {
            Text("Cette action supprimera définitivement tous les profils, toutes les collections et les photos enregistrées. Pense à créer une sauvegarde JSON avant si tu veux garder tes appareils.")
        }
        .confirmationDialog("Restaurer cette sauvegarde ?", isPresented: Binding(
            get: { backupToRestore != nil }, set: { if !$0 { backupToRestore = nil } }
        ), titleVisibility: .visible) {
            Button("Restaurer la sauvegarde", role: .destructive) {
                if let backupToRestore { restoreBackup(backupToRestore) }
                backupToRestore = nil
            }
            Button("Annuler", role: .cancel) { backupToRestore = nil }
        } message: {
            Text("La collection actuelle de ce profil sera remplacée par la sauvegarde choisie.")
        }
    }

    private var homeCardIDs: [String] { homeCardOrder.split(separator: ",").map(String.init) }
    private var exportFieldIDs: Set<String> { Set(exportFieldsPreference.split(separator: ",").map(String.init)) }

    private func homeCardTitle(_ key: String) -> String {
        ["devices": "Nombre d’appareils", "value": "Valeur estimée", "alerts": "Alertes",
         "favorites": "Favoris", "repairs": "Réparations à prévoir"][key] ?? key
    }

    private func setHomeCard(_ key: String, enabled: Bool) {
        var keys = homeCardIDs
        if enabled && !keys.contains(key) { keys.append(key) }
        if !enabled, keys.count > 1 { keys.removeAll { $0 == key } }
        homeCardOrder = keys.joined(separator: ",")
    }

    private func moveHomeCard(_ key: String, offset: Int) {
        var keys = homeCardIDs
        guard let index = keys.firstIndex(of: key) else { return }
        let destination = index + offset
        guard keys.indices.contains(destination) else { return }
        keys.swapAt(index, destination)
        homeCardOrder = keys.joined(separator: ",")
    }

    private func setExportField(_ key: String, enabled: Bool) {
        var keys = exportFieldIDs
        if enabled { keys.insert(key) } else if keys.count > 1 { keys.remove(key) }
        exportFieldsPreference = exportFieldOptions.map(\.id).filter(keys.contains).joined(separator: ",")
    }


}

@MainActor
private final class UpdateChecker: ObservableObject {
    @Published var result: UpdateCheckResult?
    @Published private(set) var isChecking = false
    private var didAutomaticCheck = false

    func checkAutomaticallyIfConfigured(enabled: Bool, urlString: String, currentVersion: String) {
        guard enabled, !didAutomaticCheck,
              !urlString.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        didAutomaticCheck = true
        check(urlString: urlString, currentVersion: currentVersion)
    }

    func check(urlString: String, currentVersion: String) {
        let address = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: address), url.scheme?.lowercased() == "https", url.host != nil else {
            result = .error("Renseigne une adresse HTTPS valide pour le serveur de mises à jour.")
            return
        }
        guard !isChecking else { return }
        isChecking = true
        result = nil
        Task {
            defer { isChecking = false }
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                    throw URLError(.badServerResponse)
                }
                let manifest = try JSONDecoder().decode(UpdateManifest.self, from: data)
                guard let latest = Self.parsedVersion(manifest.version) else {
                    result = .error("Le serveur a renvoyé un numéro de version invalide.")
                    return
                }
                let current = Self.parsedVersion(currentVersion) ?? [0]
                let componentCount = max(latest.count, current.count)
                let normalizedLatest = latest + Array(repeating: 0, count: componentCount - latest.count)
                let normalizedCurrent = current + Array(repeating: 0, count: componentCount - current.count)
                if !normalizedCurrent.lexicographicallyPrecedes(normalizedLatest) {
                    result = .upToDate
                } else {
                    let candidate = manifest.downloadURL.flatMap(URL.init(string:))
                    let downloadLink = candidate?.scheme?.lowercased() == "https" ? candidate : nil
                    result = .updateAvailable(manifest.version, downloadLink)
                }
            } catch {
                DeveloperDiagnosticLog.write("Échec de vérification du serveur de mises à jour.")
                result = .error("Impossible de contacter le serveur de mises à jour ou de lire sa réponse.")
            }
        }
    }

    private static func parsedVersion(_ value: String) -> [Int]? {
        let parts = value.split(separator: ".").compactMap { Int($0) }
        guard !parts.isEmpty, parts.count == value.split(separator: ".").count else { return nil }
        return parts
    }
}

private struct UpdateManifest: Decodable {
    let version: String
    let downloadURL: String?
}

private enum UpdateCheckResult {
    case upToDate
    case updateAvailable(String, URL?)
    case error(String)
}

private struct ProfileDirectory: Codable {
    var profiles: [LocalProfile]
    var activeProfileID: UUID?
}

private struct CollectionFilterPreset: Codable, Identifiable {
    var id = UUID()
    var name: String
    var family: String
    var condition: String
    var tag: String
}

private struct CompletionSettingsView: View {
    @AppStorage("appleVault.requiredFields") private var requiredFieldsData = "identifier,aNumber,storage,color,serial,ios,batteryHealth"
    private let fields = ["identifier": "Identifiant Apple", "aNumber": "Numéro A", "storage": "Stockage",
                          "color": "Couleur", "serial": "Numéro de série", "ios": "Version iOS/iPadOS",
                          "batteryHealth": "Santé de la batterie", "releaseYear": "Année de sortie"]
    @State private var selected = Set<String>()
    var body: some View {
        Form {
            Section("Champs requis pour les fiches à compléter") {
                ForEach(fields.keys.sorted(), id: \.self) { key in
                    Toggle(fields[key] ?? key, isOn: Binding(get: { selected.contains(key) }, set: { enabled in
                        if enabled { selected.insert(key) } else { selected.remove(key) }
                        requiredFieldsData = selected.sorted().joined(separator: ",")
                    }))
                }
            }
        }.formStyle(.grouped).padding(24).frame(maxWidth: 560, maxHeight: .infinity, alignment: .top)
            .navigationTitle("Champs requis")
            .onAppear { selected = Set(requiredFieldsData.split(separator: ",").map(String.init)) }
    }
}

struct ContentView: View {
    @StateObject private var profileStore = LocalProfileStore()
    @State private var showProfileEditor = false
    @State private var showAddProfile = false
    @State private var isManuallyLocked = false
    @State private var isDeveloperModeActive = false
    @AppStorage("appleVault.appearance") private var appearance = "system"
    @AppStorage("appleVault.language") private var language = "fr"
    @AppStorage("appleVault.weatherCity") private var weatherCity = "Paris"
    @AppStorage("appleVault.weatherSourceURL") private var weatherSourceURL = "https://api.open-meteo.com"
    @AppStorage("appleVault.updateServerURL") private var updateServerURL = ""
    @AppStorage("appleVault.automaticUpdateChecks") private var automaticUpdateChecks = true
    @StateObject private var updateChecker = UpdateChecker()
    @AppStorage("appleVault.backupFrequency") private var backupFrequency = "eachSave"
    @AppStorage("appleVault.backupRetention") private var backupRetention = 20
    @AppStorage("appleVault.automaticBackupsEnabled") private var automaticBackupsEnabled = true
    @AppStorage("appleVault.collectionSavingEnabled") private var collectionSavingEnabled = true
    @AppStorage("appleVault.alertLowBattery") private var alertLowBattery = true
    @AppStorage("appleVault.alertWarranty") private var alertWarranty = true
    @AppStorage("appleVault.alertIncomplete") private var alertIncomplete = true
    @AppStorage("appleVault.hideSerialNumbers") private var hideSerialNumbers = false
    @AppStorage("appleVault.homeCardOrder") private var homeCardOrder = "devices,value,alerts"
    @AppStorage("appleVault.exportFields") private var exportFieldsPreference = "model,identifier,aNumber,partNumber,storage,color,serial,ios,condition,battery,accessories,box,charger,invoice,maintenance,warranty,repairsDone,repairsTodo,repairHistory,estimatedValue,purchaseDate,purchasePrice,notes,jailbreak,shsh,tags"
    @AppStorage("appleVault.collectionSort") private var collectionSort = "name"
    @AppStorage("appleVault.savedFilters") private var savedFiltersData = ""
    @AppStorage("appleVault.requiredFields") private var requiredFieldsData = "identifier,aNumber,storage,color,serial,ios,batteryHealth"
    @StateObject private var inventory = Inventory()
    @State private var search = ""
    @State private var showAdd = false
    @State private var editingDevice: AppleDevice?
    @State private var exportFile: URL?
    @State private var showExport = false
    @State private var showImport = false
    @State private var showCSVImport = false
    @State private var showCSVPreview = false
    @State private var showCSVError = false
    @State private var csvErrorMessage = ""
    @State private var csvImportDevices: [AppleDevice] = []
    @State private var showInventoryMode = false
    @State private var galleryWindowController: GalleryWindowController?
    @State private var selectedID: UUID?
    @State private var familyFilter = "Tous"
    @State private var conditionFilter = "Tous"
    @State private var showComparison = false
    @State private var showSettings = false
    @State private var showFeatures = false
    @State private var showActivityHistory = false
    @State private var showFavorites = false
    @State private var showRepairQueue = false
    @State private var showIncompleteDevices = false
    @State private var showMaintenance = false
    @State private var showWishlist = false
    @State private var showDuplicates = false
    @State private var showDocumentImporter = false
    @State private var showBarcodeImporter = false
    @State private var scanMessage = ""
    @State private var showScanMessage = false
    @State private var showLoanedDevices = false
    @State private var showCompletionSettings = false
    @State private var tagFilter = "Tous"
    @State private var showHome = true

    private func missingFields(for device: AppleDevice) -> [String] {
        let labels = ["identifier": (device.identifier, "identifiant"), "aNumber": (device.aNumber, "numéro A"),
                      "storage": (device.storage, "stockage"), "color": (device.color, "couleur"),
                      "serial": (device.serial, "numéro de série"), "ios": (device.ios, "version iOS/iPadOS"),
                      "batteryHealth": (device.batteryHealth, "batterie"), "releaseYear": (device.releaseYear, "année de sortie")]
        let required = Set(requiredFieldsData.split(separator: ",").map(String.init))
        return required.compactMap { key in
            guard let (value, label) = labels[key], value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            return label
        }.sorted()
    }

    private var incompleteDevices: [AppleDevice] {
        guard alertIncomplete else { return [] }
        return inventory.devices.filter { !$0.warningsIgnored && !missingFields(for: $0).isEmpty }
    }

    private var duplicateGroupCount: Int {
        let serials = inventory.devices.map { $0.serial.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() }
            .filter { !$0.isEmpty }
        return Dictionary(grouping: serials, by: { $0 }).values.filter { $0.count > 1 }.count
    }

    private var maintenanceDevices: [AppleDevice] {
        let today = Calendar.current.startOfDay(for: .now)
        let cutoff = Calendar.current.date(byAdding: .day, value: 30, to: today) ?? today
        return inventory.devices.filter { device in
            guard !device.warningsIgnored else { return false }
            let reminderIsDueSoon = device.maintenanceDate.map { Calendar.current.startOfDay(for: $0) <= cutoff } ?? false
            let batteryNeedsAttention = alertLowBattery && (batteryPercent(from: device.batteryHealth).map { $0 < 80 } ?? false)
            let warrantyDueSoon = alertWarranty && (device.warrantyEndDate.map { Calendar.current.startOfDay(for: $0) <= cutoff } ?? false)
            let loanReturnDue = device.loanDueDate.map { Calendar.current.startOfDay(for: $0) <= cutoff } ?? false
            return reminderIsDueSoon || batteryNeedsAttention || warrantyDueSoon || loanReturnDue
        }.sorted { first, second in
            (first.maintenanceDate ?? .distantFuture) < (second.maintenanceDate ?? .distantFuture)
        }
    }

    private func maintenanceDetails(for device: AppleDevice) -> String {
        var details: [String] = []
        if let date = device.maintenanceDate {
            let today = Calendar.current.startOfDay(for: .now)
            let dueDate = Calendar.current.startOfDay(for: date)
            details.append(dueDate < today ? "En retard depuis le \(date.formatted(date: .abbreviated, time: .omitted))" : "Entretien le \(date.formatted(date: .abbreviated, time: .omitted))")
        }
        if alertLowBattery, let battery = batteryPercent(from: device.batteryHealth), battery < 80 {
            details.append("Batterie à surveiller : \(Int(battery.rounded()))%")
        }
        if alertWarranty, let warranty = device.warrantyEndDate {
            details.append(warranty < .now ? "Garantie expirée le \(warranty.formatted(date: .abbreviated, time: .omitted))" : "Fin de garantie : \(warranty.formatted(date: .abbreviated, time: .omitted))")
        }
        if let returnDate = device.loanDueDate { details.append("Retour de prêt prévu le \(returnDate.formatted(date: .abbreviated, time: .omitted))") }
        return details.joined(separator: " · ")
    }

    private var filtered: [AppleDevice] {
        let matches = inventory.devices.filter { device in
            let matchesSearch = search.isEmpty || "\(device.model) \(device.identifier) \(device.aNumber) \(device.partNumber) \(device.ios) \(device.serial) \(device.tags.joined(separator: " "))"
                .localizedCaseInsensitiveContains(search)
            let model = device.model.lowercased()
            let family = model.contains("iphone") ? "iPhone" : model.contains("ipad") ? "iPad" :
                (model.contains("mac") || model.contains("imac")) ? "Mac" :
                model.contains("watch") ? "Watch" : model.contains("airpods") ? "AirPods" : "Autre"
            return matchesSearch && (familyFilter == "Tous" || family == familyFilter) &&
                (conditionFilter == "Tous" || device.condition == conditionFilter) &&
                (tagFilter == "Tous" || device.tags.contains(tagFilter))
        }
        switch collectionSort {
        case "year": return matches.sorted { ($0.releaseYear.isEmpty ? "0" : $0.releaseYear) < ($1.releaseYear.isEmpty ? "0" : $1.releaseYear) }
        case "condition": return matches.sorted { $0.condition < $1.condition }
        case "value": return matches.sorted { (collectionEstimate(for: $0) ?? 0) > (collectionEstimate(for: $1) ?? 0) }
        case "valueAsc": return matches.sorted { (collectionEstimate(for: $0) ?? .greatestFiniteMagnitude) < (collectionEstimate(for: $1) ?? .greatestFiniteMagnitude) }
        case "storage": return matches.sorted { (sortStorageGB($0.storage) ?? 0) > (sortStorageGB($1.storage) ?? 0) }
        case "battery": return matches.sorted { (sortNumber($0.batteryHealth) ?? -1) > (sortNumber($1.batteryHealth) ?? -1) }
        case "ios": return matches.sorted { $0.ios.localizedStandardCompare($1.ios) == .orderedAscending }
        case "favorite": return matches.sorted { $0.isFavorite && !$1.isFavorite }
        case "added": return matches.sorted { $0.createdAt > $1.createdAt }
        default: return matches.sorted { $0.model.localizedStandardCompare($1.model) == .orderedAscending }
        }
    }

    private func deviceFamily(_ device: AppleDevice) -> String {
        let model = device.model.lowercased()
        if model.contains("iphone") { return "iPhone" }
        if model.contains("ipad") { return "iPad" }
        if model.contains("mac") || model.contains("imac") { return "Mac" }
        if model.contains("watch") { return "Watch" }
        if model.contains("airpods") { return "AirPods" }
        return "Autre"
    }

    private func setFamilyFilter(_ family: String) {
        familyFilter = family
        selectedID = nil
    }

    private func sortNumber(_ text: String) -> Double? {
        let separators = text.indices.filter { text[$0] == "," || text[$0] == "." }
        let decimalSeparator = separators.last
        var normalized = ""
        for index in text.indices {
            let character = text[index]
            if character.isNumber { normalized.append(character) }
            else if index == decimalSeparator { normalized.append(".") }
        }
        return Double(normalized)
    }

    private func sortStorageGB(_ text: String) -> Double? {
        guard let amount = sortNumber(text) else { return nil }
        let normalized = text.lowercased()
        return amount * (normalized.contains("tb") || normalized.contains("to") ? 1024 : 1)
    }

    private var savedFilterPresets: [CollectionFilterPreset] {
        guard let data = savedFiltersData.data(using: .utf8) else { return [] }
        return (try? JSONDecoder().decode([CollectionFilterPreset].self, from: data)) ?? []
    }

    private func saveCurrentFilter() {
        let panel = NSAlert()
        panel.messageText = "Enregistrer ce filtre"
        let field = NSTextField(string: "Mon filtre")
        field.frame = NSRect(x: 0, y: 0, width: 240, height: 24)
        panel.accessoryView = field
        panel.addButton(withTitle: "Enregistrer"); panel.addButton(withTitle: "Annuler")
        guard panel.runModal() == .alertFirstButtonReturn else { return }
        var presets = savedFilterPresets
        presets.append(CollectionFilterPreset(name: field.stringValue, family: familyFilter, condition: conditionFilter, tag: tagFilter))
        if let data = try? JSONEncoder().encode(presets) { savedFiltersData = String(decoding: data, as: UTF8.self) }
    }

    private func scanImage(_ url: URL) {
        do {
            let request = VNDetectBarcodesRequest()
            try VNImageRequestHandler(url: url).perform([request])
            guard let value = request.results?.first?.payloadStringValue, !value.isEmpty else {
                scanMessage = "Aucun code-barres lisible dans cette image."; showScanMessage = true; return
            }
            if let device = inventory.devices.first(where: { $0.serial.caseInsensitiveCompare(value) == .orderedSame || $0.identifier.caseInsensitiveCompare(value) == .orderedSame || $0.partNumber.caseInsensitiveCompare(value) == .orderedSame }) {
                selectedID = device.id
                scanMessage = "Fiche trouvée : \(device.model)."
            } else { scanMessage = "Code lu : \(value). Aucune fiche ne correspond encore." }
        } catch { scanMessage = "Impossible de lire cette image." }
        showScanMessage = true
    }

    var body: some View {
        Group {
            if let profile = profileStore.profile {
                if isManuallyLocked {
                    ProfileUnlockView(profile: profile, profiles: profileStore.profiles, verify: profileStore.verify,
                        onSelectProfile: { id in
                            profileStore.switchProfile(to: id)
                            inventory.activate(profileID: id)
                            isManuallyLocked = profileStore.profile?.requirePasswordOnLaunch == true
                        },
                        onUnlock: { isDeveloperModeActive = false; isManuallyLocked = false },
                        onDeveloperAccess: { isDeveloperModeActive = true; isManuallyLocked = false })
                } else if isDeveloperModeActive {
                    DeveloperModeView(nickname: profile.nickname, deviceCount: inventory.devices.count,
                        backupsEnabled: automaticBackupsEnabled, savingEnabled: collectionSavingEnabled,
                        profileID: profileStore.activeProfileID, backupFiles: inventory.recentBackupFiles,
                        weatherCity: weatherCity, weatherSourceURL: weatherSourceURL, updateServerURL: updateServerURL,
                        onExit: { isDeveloperModeActive = false; isManuallyLocked = true })
                } else {
                    mainAppView
                }
            } else {
                ProfileSetupView(store: profileStore) { }
            }
        }
        .sheet(isPresented: $showProfileEditor) { ProfileEditorView(store: profileStore) }
        .sheet(isPresented: $showAddProfile) {
            ProfileSetupView(store: profileStore, onComplete: { showAddProfile = false }, isAdditional: true)
        }
        .onReceive(NotificationCenter.default.publisher(for: .appleVaultLock)) { _ in
            isDeveloperModeActive = false
            isManuallyLocked = true
        }
        .onChange(of: selectedID) { _, newID in
            if newID != nil { showFeatures = false }
        }
        .onChange(of: profileStore.activeProfileID) { _, newID in
            guard let newID else { return }
            inventory.activate(profileID: newID)
            selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
            showComparison = false
            showActivityHistory = false
            showFavorites = false
            showRepairQueue = false
            showIncompleteDevices = false
            showMaintenance = false
            tagFilter = "Tous"
            familyFilter = "Tous"
            conditionFilter = "Tous"
            search = ""
            isManuallyLocked = profileStore.profile?.requirePasswordOnLaunch == true
        }
        .task {
            if let id = profileStore.activeProfileID {
                inventory.activate(profileID: id)
                isManuallyLocked = profileStore.profile?.requirePasswordOnLaunch == true
            }
            updateChecker.checkAutomaticallyIfConfigured(
                enabled: automaticUpdateChecks, urlString: updateServerURL,
                currentVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.5.2"
            )
        }
        .onChange(of: automaticUpdateChecks) { _, enabled in
            if enabled {
                updateChecker.checkAutomaticallyIfConfigured(
                    enabled: true, urlString: updateServerURL,
                    currentVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.5.2"
                )
            }
        }
        .onChange(of: collectionSavingEnabled) { _, enabled in
            if enabled { inventory.save() }
        }
        .preferredColorScheme(appearance == "light" ? .light : appearance == "dark" ? .dark : nil)
    }

    private var mainAppView: some View {
        NavigationSplitView {
            List(selection: $selectedID) {
                Section("Vue d’ensemble") {
                    Button {
                        showFeatures = false
                        showHome = true
                        showSettings = false
                        showActivityHistory = false
                        showFavorites = false
                        showRepairQueue = false
                        showIncompleteDevices = false
                        showMaintenance = false
                        showComparison = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                    } label: {
                        Label("Accueil", systemImage: "house.fill")
                    }
                    .buttonStyle(.plain)
                    Button {
                        showFeatures = true
                        showHome = false
                        showSettings = false
                        showActivityHistory = false
                        showFavorites = false
                        showRepairQueue = false
                        showIncompleteDevices = false
                        showMaintenance = false
                        showComparison = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                    } label: {
                        Label("Fonctionnalités", systemImage: "square.grid.2x2.fill")
                    }
                    .buttonStyle(.plain)
                    Button {
                        showFeatures = false
                        showHome = false
                        showComparison = false
                        showComparison = false
                        showSettings = false
                        showActivityHistory = false
                        showFavorites = false
                        showRepairQueue = false
                        showIncompleteDevices = false
                        showMaintenance = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                    } label: {
                        Label("Tableau de bord", systemImage: "chart.bar.xaxis")
                    }
                    .buttonStyle(.plain)
                    Button {
                        showFeatures = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showSettings = false
                        showActivityHistory = false
                        showComparison = false
                        showFavorites = false
                        showRepairQueue = false
                        showIncompleteDevices = false
                        showMaintenance = true
                    } label: {
                        Label("Entretiens & alertes (\(maintenanceDevices.count))", systemImage: "calendar.badge.clock")
                    }
                    .buttonStyle(.plain)
                    Button {
                        showFeatures = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showSettings = false
                        showActivityHistory = false
                        showComparison = false
                        showFavorites = false
                        showRepairQueue = false
                        showIncompleteDevices = true
                        showMaintenance = false
                    } label: {
                        Label("Fiches à compléter (\(incompleteDevices.count))", systemImage: "checklist")
                    }
                    .buttonStyle(.plain)
                    Button {
                        showFeatures = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showSettings = false
                        showActivityHistory = false
                        showComparison = false
                        showRepairQueue = false
                        showIncompleteDevices = false
                        showMaintenance = false
                        showFavorites = true
                    } label: {
                        Label("Mes favoris (\(inventory.devices.filter(\.isFavorite).count))", systemImage: "heart.fill")
                    }
                    .buttonStyle(.plain)
                    Button {
                        showFeatures = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showSettings = false
                        showActivityHistory = false
                        showComparison = false
                        showFavorites = false
                        showIncompleteDevices = false
                        showMaintenance = false
                        showRepairQueue = true
                    } label: {
                        Label("Réparations à prévoir (\(inventory.devices.filter { !$0.repairsTodo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.count))", systemImage: "wrench.and.screwdriver.fill")
                    }
                    .buttonStyle(.plain)
                    Button {
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showSettings = false
                        showActivityHistory = false
                        showFavorites = false
                        showRepairQueue = false
                        showIncompleteDevices = false
                        showMaintenance = false
                        showComparison = true
                    } label: {
                        Label("Comparer deux appareils", systemImage: "rectangle.split.2x1")
                    }
                    .buttonStyle(.plain)
                    Button {
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showHome = false; showFeatures = false; showSettings = false
                        showActivityHistory = false; showFavorites = false; showRepairQueue = false
                        showIncompleteDevices = false; showMaintenance = false; showComparison = false
                        showDuplicates = true; showWishlist = false
                    } label: {
                        Label("Doublons possibles (\(duplicateGroupCount))", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.plain)
                    Button {
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showHome = false; showFeatures = false; showSettings = false
                        showActivityHistory = false; showFavorites = false; showRepairQueue = false
                        showIncompleteDevices = false; showMaintenance = false; showComparison = false
                        showDuplicates = false; showWishlist = true
                    } label: {
                        Label("Liste de souhaits (\(inventory.wishlist.count))", systemImage: "star")
                    }
                    .buttonStyle(.plain)
                    Button {
                        selectedID = nil; showHome = false; showWishlist = false; showDuplicates = false
                        showFeatures = false; showSettings = false; showActivityHistory = false
                        showFavorites = false; showRepairQueue = false; showIncompleteDevices = false
                        showMaintenance = false; showComparison = false; showCompletionSettings = true
                    } label: { Label("Champs requis des fiches", systemImage: "checklist.checked") }
                    .buttonStyle(.plain)
                    Button {
                        selectedID = nil; showHome = false; showWishlist = false; showDuplicates = false
                        showFeatures = false; showSettings = false; showActivityHistory = false
                        showFavorites = false; showRepairQueue = false; showIncompleteDevices = false
                        showMaintenance = false; showComparison = false; showCompletionSettings = false
                        showLoanedDevices = true
                    } label: {
                        Label("Appareils prêtés (\(inventory.devices.filter { !$0.loanedTo.isEmpty }.count))", systemImage: "person.2")
                    }.buttonStyle(.plain)
                    Button {
                        showFeatures = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showComparison = false
                        showActivityHistory = false
                        showFavorites = false
                        showRepairQueue = false
                        showIncompleteDevices = false
                        showMaintenance = false
                        showSettings = true
                    } label: {
                        Label("Réglages", systemImage: "gearshape")
                    }
                    .buttonStyle(.plain)
                    Button {
                        showFeatures = false
                        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                        showComparison = false
                        showSettings = false
                        showFavorites = false
                        showRepairQueue = false
                        showIncompleteDevices = false
                        showMaintenance = false
                        showActivityHistory = true
                    } label: {
                        Label("Historique d’activité", systemImage: "clock.arrow.circlepath")
                    }
                    .buttonStyle(.plain)
                    Button {
                        showProfileEditor = true
                    } label: {
                        Label("Profil local", systemImage: "person.crop.circle")
                    }
                    .buttonStyle(.plain)
                }
                Section {
                    Label("Ma collection", systemImage: "square.stack.3d.up.fill")
                        .font(.headline)
                    Text("\(inventory.devices.count) appareil(s)")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Familles") {
                    ForEach(["Tous", "iPhone", "iPad", "Mac", "Watch", "AirPods", "Autre"], id: \.self) { family in
                        let count = family == "Tous" ? inventory.devices.count : inventory.devices.filter { deviceFamily($0) == family }.count
                        if family == "Tous" || count > 0 {
                            Button { setFamilyFilter(family) } label: {
                                HStack {
                                    Label(family == "Tous" ? "Toute la collection" : family,
                                          systemImage: family == "Tous" ? "square.stack.3d.up" : familyIcon(family))
                                    Spacer()
                                    Text("\(count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                    if familyFilter == family { Image(systemName: "checkmark").font(.caption.bold()).foregroundStyle(.tint) }
                                }
                            }.buttonStyle(.plain)
                        }
                    }
                }
                Section("Appareils") {
                    ForEach(filtered) { device in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(device.model.isEmpty ? "Appareil sans nom" : device.model)
                                .font(.headline)
                            Text([device.storage, device.ios.isEmpty ? "" : "iOS \(device.ios)"]
                                .filter { !$0.isEmpty }.joined(separator: " · "))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 3)
                        .tag(device.id)
                        .contextMenu {
                            Button("Supprimer", systemImage: "trash", role: .destructive) {
                                inventory.record("Appareil supprimé", deviceName: device.model)
                                PrivateNoteVault.remove(for: device.id)
                                inventory.devices.removeAll { $0.id == device.id }
                                if selectedID == device.id { selectedID = nil }
                            }
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("AppleVault")
            .toolbar {
                ToolbarItem {
                    Button { showProfileEditor = true } label: { Label("Profil", systemImage: "person.crop.circle") }
                        .help("Modifier le profil local")
                }
                ToolbarItem {
                    Menu {
                        Picker("Famille", selection: $familyFilter) {
                            ForEach(["Tous", "iPhone", "iPad", "Mac", "Watch", "AirPods", "Autre"], id: \.self) { Text($0) }
                        }
                        Picker("État", selection: $conditionFilter) {
                            ForEach(["Tous", "Comme neuf", "Bon état", "Usé", "Abîmé", "Pour pièces"], id: \.self) { Text($0) }
                        }
                        Picker("Étiquette", selection: $tagFilter) {
                            Text("Toutes").tag("Tous")
                            ForEach(Array(Set(inventory.devices.flatMap(\.tags))).sorted(), id: \.self) { Text($0).tag($0) }
                        }
                        Picker("Trier par", selection: $collectionSort) {
                            Text("Nom").tag("name")
                            Text("Année de sortie").tag("year")
                            Text("État").tag("condition")
                            Text("Valeur estimée").tag("value")
                            Text("Valeur estimée · croissante").tag("valueAsc")
                            Text("Capacité de stockage").tag("storage")
                            Text("Santé de la batterie").tag("battery")
                            Text("Version iOS / iPadOS").tag("ios")
                            Text("Favoris en premier").tag("favorite")
                            Text("Ajout récent").tag("added")
                        }
                        Divider()
                        Button("Enregistrer les filtres actuels…", systemImage: "bookmark") { saveCurrentFilter() }
                        ForEach(savedFilterPresets) { preset in
                            Button(preset.name) {
                                familyFilter = preset.family; conditionFilter = preset.condition; tagFilter = preset.tag
                            }
                        }
                        Button("Effacer les filtres") { familyFilter = "Tous"; conditionFilter = "Tous"; tagFilter = "Tous" }
                    } label: {
                        Label("Filtres", systemImage: familyFilter == "Tous" && conditionFilter == "Tous" && tagFilter == "Tous" ? "line.3.horizontal.decrease" : "line.3.horizontal.decrease.circle.fill")
                    }
                }
                ToolbarItem {
                    Button { showAdd = true } label: {
                        Label("Ajouter un appareil", systemImage: "plus")
                    }
                    .help("Ajouter un appareil à la collection")
                }
            }
        } detail: {
            if showFeatures {
                FeaturesView()
            } else if showSettings {
                SettingsView(appearance: $appearance, language: $language, weatherCity: $weatherCity,
                             weatherSourceURL: $weatherSourceURL, updateServerURL: $updateServerURL,
                             automaticUpdateChecks: $automaticUpdateChecks, updateChecker: updateChecker,
                             profileStore: profileStore,
                             automaticBackupCount: inventory.automaticBackupCount,
                             backupFiles: inventory.recentBackupFiles,
                             showBackupFolder: inventory.revealAutomaticBackups,
                             restoreBackup: restoreBackup,
                             resetApp: resetApp, addProfile: { showAddProfile = true },
                             backupFrequency: $backupFrequency, backupRetention: $backupRetention,
                             automaticBackupsEnabled: $automaticBackupsEnabled,
                             collectionSavingEnabled: $collectionSavingEnabled,
                             alertLowBattery: $alertLowBattery, alertWarranty: $alertWarranty,
                             alertIncomplete: $alertIncomplete, hideSerialNumbers: $hideSerialNumbers,
                             homeCardOrder: $homeCardOrder, exportFieldsPreference: $exportFieldsPreference)
            } else if showActivityHistory {
                ActivityHistoryView(entries: inventory.activities)
            } else if showFavorites {
                DeviceShortcutView(title: "Mes favoris", symbol: "heart.fill",
                    emptyMessage: "Clique sur le cœur d’une fiche pour l’ajouter ici.",
                    devices: inventory.devices.filter(\.isFavorite),
                    detail: { [$0.storage, $0.condition].filter { !$0.isEmpty }.joined(separator: " · ") },
                    onSelect: { selectedID = $0 })
            } else if showRepairQueue {
                DeviceShortcutView(title: "Réparations à prévoir", symbol: "wrench.and.screwdriver.fill",
                    emptyMessage: "Ajoute les interventions à prévoir dans les fiches de tes appareils.",
                    devices: inventory.devices.filter { !$0.repairsTodo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty },
                    detail: { $0.repairsTodo },
                    onSelect: { selectedID = $0 })
            } else if showIncompleteDevices {
                DeviceShortcutView(title: "Fiches à compléter", symbol: "checklist",
                    emptyMessage: "Toutes les fiches contiennent déjà les informations principales.",
                    devices: incompleteDevices,
                    detail: { "À renseigner : \(missingFields(for: $0).joined(separator: ", "))" },
                    onSelect: { selectedID = $0 })
            } else if showMaintenance {
                DeviceShortcutView(title: "Entretiens & alertes", symbol: "calendar.badge.clock",
                    emptyMessage: "Aucun entretien prévu dans les 30 jours et aucune batterie sous 80%.",
                    devices: maintenanceDevices,
                    detail: { maintenanceDetails(for: $0) },
                    onSelect: { selectedID = $0 })
            } else if showDuplicates {
                DuplicateDevicesView(devices: inventory.devices, onSelect: { selectedID = $0; showDuplicates = false })
            } else if showWishlist {
                WishlistView(inventory: inventory)
            } else if showCompletionSettings {
                CompletionSettingsView()
            } else if showLoanedDevices {
                DeviceShortcutView(title: "Appareils prêtés", symbol: "person.2",
                    emptyMessage: "Aucun appareil n’est actuellement marqué comme prêté.",
                    devices: inventory.devices.filter { !$0.loanedTo.isEmpty },
                    detail: { device in "À \(device.loanedTo)" + (device.loanDueDate.map { " · retour prévu le \($0.formatted(date: .abbreviated, time: .omitted))" } ?? "") },
                    onSelect: { selectedID = $0 })
            } else if showComparison {
                ComparisonView(devices: inventory.devices)
            } else if let id = selectedID, let device = inventory.devices.first(where: { $0.id == id }) {
                DeviceDetailView(device: device, hideSerialNumbers: hideSerialNumbers,
                                 privateNotesRequirePassword: profileStore.profile?.requirePasswordOnLaunch ?? false,
                                 verifyPassword: profileStore.verify,
                                 onEdit: { editingDevice = device }, onToggleFavorite: {
                    guard let index = inventory.devices.firstIndex(where: { $0.id == device.id }) else { return }
                    inventory.devices[index].isFavorite.toggle()
                    inventory.record(inventory.devices[index].isFavorite ? "Ajouté aux favoris" : "Retiré des favoris",
                                    deviceName: inventory.devices[index].model)
                }, onToggleWarningsIgnored: {
                    guard let index = inventory.devices.firstIndex(where: { $0.id == device.id }) else { return }
                    inventory.devices[index].warningsIgnored.toggle()
                    let ignored = inventory.devices[index].warningsIgnored
                    inventory.devices[index].timeline.append(.init(title: ignored ? "Avertissements ignorés" : "Avertissements réactivés",
                                                                     detail: ignored ? "Masqué des listes d’alertes" : "Réactivé dans les listes d’alertes"))
                }, onAddDocument: { showDocumentImporter = true })
            } else if showHome {
                HomeView(devices: inventory.devices,
                         version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.5.2",
                         homeCardOrder: homeCardOrder, weatherCity: weatherCity,
                         weatherSourceURL: weatherSourceURL,
                         alertLowBattery: alertLowBattery,
                         alertWarranty: alertWarranty, alertIncomplete: alertIncomplete,
                         incompleteCount: incompleteDevices.count,
                         onOpenFeatures: {
                             showFeatures = true
                             showHome = false
                             showSettings = false
                             showActivityHistory = false
                             showFavorites = false
                             showRepairQueue = false
                             showIncompleteDevices = false
                             showMaintenance = false
                             showComparison = false
                             selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                         },
                         onOpenCollection: {
                             showHome = false
                             showSettings = false
                             showActivityHistory = false
                             showFavorites = false
                             showRepairQueue = false
                             showIncompleteDevices = false
                             showMaintenance = false
                             showComparison = false
                             selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
                         },
                         onAddDevice: { showAdd = true })
            } else {
                DashboardView(devices: inventory.devices) { deviceID in
                    selectedID = deviceID
                }
            }
        }
        .searchable(text: $search, prompt: "Rechercher dans la collection")
        .onChange(of: selectedID) { _, newValue in
            if newValue != nil {
                showHome = false
                showComparison = false
                showSettings = false
                showActivityHistory = false
                showFavorites = false
                showRepairQueue = false
                showIncompleteDevices = false
                showMaintenance = false
                showDuplicates = false
                showWishlist = false
                showLoanedDevices = false
                showCompletionSettings = false
            }
        }
        .sheet(isPresented: $showAdd) {
            AddDeviceView(profileID: profileStore.activeProfileID, knownDevices: inventory.devices) { device in
                inventory.devices.append(device)
                inventory.record("Appareil ajouté", deviceName: device.model)
                selectedID = device.id
            }
        }
        .sheet(item: $editingDevice) { device in
                EditDeviceView(device: device, profileID: profileStore.activeProfileID, hideSerialNumbers: hideSerialNumbers) { updated in
                if let index = inventory.devices.firstIndex(where: { $0.id == updated.id }) {
                        var tracked = updated
                        var events: [DeviceTimelineEntry] = []
                        if device.condition != updated.condition { events.append(.init(title: "État modifié", detail: "\(device.condition) → \(updated.condition)")) }
                        if device.batteryHealth != updated.batteryHealth { events.append(.init(title: "Batterie mise à jour", detail: "\(device.batteryHealth.isEmpty ? "—" : device.batteryHealth + "%") → \(updated.batteryHealth.isEmpty ? "—" : updated.batteryHealth + "%")")) }
                        if device.repairsTodo != updated.repairsTodo { events.append(.init(title: "Réparations à prévoir modifiées", detail: updated.repairsTodo.isEmpty ? "Aucune intervention à prévoir" : updated.repairsTodo)) }
                        if device.repairHistory.count < updated.repairHistory.count, let repair = updated.repairHistory.last { events.append(.init(title: "Réparation enregistrée", detail: repair.description)) }
                        if device.accessories != updated.accessories || device.hasBox != updated.hasBox || device.hasCharger != updated.hasCharger || device.hasInvoice != updated.hasInvoice { events.append(.init(title: "Accessoires mis à jour", detail: updated.accessories)) }
                        if device.warrantyEndDate != updated.warrantyEndDate { events.append(.init(title: "Garantie mise à jour", detail: updated.warrantyEndDate?.formatted(date: .abbreviated, time: .omitted) ?? "Fin de garantie supprimée")) }
                        if events.isEmpty { events.append(.init(title: "Fiche modifiée", detail: "Informations de l’appareil mises à jour")) }
                        tracked.timeline.append(contentsOf: events)
                        inventory.devices[index] = tracked
                }
                let addedRepair = updated.repairHistory.count > device.repairHistory.count
                inventory.record(addedRepair ? "Réparation ajoutée" : "Fiche modifiée", deviceName: updated.model)
            }
        }
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Menu {
                    Button("Mon profil…", systemImage: "person.crop.circle") { showProfileEditor = true }
                    Button("Verrouiller AppleVault", systemImage: "lock") { isManuallyLocked = true }
                    Divider()
                    Button("Mode inventaire…", systemImage: "checklist.checked") { showInventoryMode = true }
                        .disabled(inventory.devices.isEmpty)
                    Button("Afficher la collection en plein écran", systemImage: "arrow.up.left.and.arrow.down.right") { openCollectionGallery() }
                        .disabled(inventory.devices.isEmpty)
                    Divider()
                    Button("Exporter en CSV…", systemImage: "tablecells") { exportCSV() }
                        .disabled(inventory.devices.isEmpty)
                    Button("Exporter en PDF…", systemImage: "doc.richtext") { exportCollectionPDF() }
                        .disabled(inventory.devices.isEmpty)
                    Button("Créer une sauvegarde JSON…", systemImage: "externaldrive") { exportJSON() }
                        .disabled(inventory.devices.isEmpty)
                    Button("Importer une collection CSV…", systemImage: "tablecells.badge.ellipsis") { showCSVImport = true }
                    Button("Scanner un code depuis une image…", systemImage: "barcode.viewfinder") { showBarcodeImporter = true }
                    Divider()
                    Button("Restaurer depuis un fichier JSON…", systemImage: "arrow.down.doc") { showImport = true }
                } label: {
                    Label("Sauvegarde", systemImage: "square.and.arrow.up")
                }
            }
        }
        .sheet(isPresented: $showExport) {
            if let file = exportFile { ShareSheetView(fileURL: file) }
        }
        .sheet(isPresented: $showCSVPreview) {
            CSVImportPreviewView(devices: csvImportDevices, existingDevices: inventory.devices) { ignoreDuplicates in
                importCSVDevices(ignoreExistingSerials: ignoreDuplicates)
            }
        }
        .sheet(isPresented: $showInventoryMode) {
            InventoryModeView(devices: inventory.devices.sorted { $0.model.localizedStandardCompare($1.model) == .orderedAscending })
        }
        .fileImporter(isPresented: $showImport, allowedContentTypes: [.json], allowsMultipleSelection: false) { result in
            guard case .success(let urls) = result, let url = urls.first else { return }
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url),
                  let restored = try? JSONDecoder().decode([AppleDevice].self, from: data) else { return }
            var merged = inventory.devices
            for device in restored {
                if let index = merged.firstIndex(where: { $0.id == device.id }) { merged[index] = device }
                else { merged.append(device) }
            }
            inventory.devices = merged
            inventory.record("Sauvegarde restaurée", deviceName: "\(restored.count) appareil(s)")
            selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
            showComparison = false
        }
        .fileImporter(isPresented: $showCSVImport, allowedContentTypes: [.commaSeparatedText, .plainText], allowsMultipleSelection: false) { result in
            guard case .success(let urls) = result, let url = urls.first else { return }
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            do {
                let parsed = try parseCollectionCSV(Data(contentsOf: url))
                guard !parsed.isEmpty else { throw CSVImportError.noDevices }
                csvImportDevices = parsed
                showCSVPreview = true
            } catch {
                csvErrorMessage = error.localizedDescription
                showCSVError = true
            }
        }
        .fileImporter(isPresented: $showDocumentImporter, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            guard case .success(let urls) = result, let deviceID = selectedID else { return }
            for url in urls { try? inventory.attachDocument(from: url, to: deviceID) }
            inventory.record("Document ajouté", deviceName: inventory.devices.first(where: { $0.id == deviceID })?.model ?? "Appareil")
        }
        .fileImporter(isPresented: $showBarcodeImporter, allowedContentTypes: [.image], allowsMultipleSelection: false) { result in
            guard case .success(let urls) = result, let url = urls.first else { return }
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            scanImage(url)
        }
        .alert("Scanner", isPresented: $showScanMessage) {
            Button("OK", role: .cancel) { }
        } message: { Text(scanMessage) }
        .alert("Importation CSV", isPresented: $showCSVError) {
            Button("OK", role: .cancel) { }
        } message: { Text(csvErrorMessage) }
        .frame(minWidth: 850, minHeight: 600)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            Text("Créé par ChatGPT et Loop")
                .font(.caption2).foregroundStyle(.tertiary)
                .frame(maxWidth: .infinity).padding(.vertical, 4)
                .background(.bar)
        }
    }

    private func familyIcon(_ family: String) -> String {
        switch family {
        case "iPhone": "iphone"
        case "iPad": "ipad"
        case "Mac": "laptopcomputer"
        case "Watch": "applewatch"
        case "AirPods": "airpodspro"
        default: "square.grid.2x2"
        }
    }

    private func restoreBackup(_ url: URL) {
        guard let data = try? Data(contentsOf: url),
              let restored = try? JSONDecoder().decode([AppleDevice].self, from: data) else { return }
        inventory.createBackupBeforeRestore()
        inventory.devices = restored
        inventory.record("Sauvegarde restaurée", deviceName: "\(restored.count) appareil(s)")
        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
        showComparison = false
    }

    private func resetApp() {
        PrivateNoteVault.removeAll()
        inventory.resetAll()
        profileStore.reset()
        appearance = "system"
        language = "fr"
        isManuallyLocked = false
        selectedID = nil
                        showLoanedDevices = false
                        showCompletionSettings = false
                        showDuplicates = false
                        showWishlist = false
        showSettings = false
        showComparison = false
    }

    private var chosenExportFields: [ExportField] {
        let selected = Set(exportFieldsPreference.split(separator: ",").map(String.init))
        let fields = exportFieldOptions.filter { selected.contains($0.id) }
        return fields.isEmpty ? exportFieldOptions : fields
    }

    private func exportCSV() {
        func cell(_ value: String) -> String { "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\"" }
        let fields = chosenExportFields
        let header = fields.map { cell($0.title) }.joined(separator: ";")
        let rows = inventory.devices.map { device in
            fields.map { cell(exportValue($0.id, from: device, hideSerial: hideSerialNumbers)) }.joined(separator: ";")
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("AppleVault-collection.csv")
        try? ([header] + rows).joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        exportFile = url
        showExport = true
    }

    private func importCSVDevices(ignoreExistingSerials: Bool) {
        var merged = inventory.devices
        var knownSerials = Set(merged.map { $0.serial.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() }.filter { !$0.isEmpty })
        var added = 0
        var skipped = 0
        for device in csvImportDevices {
            let serial = device.serial.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            if ignoreExistingSerials, !serial.isEmpty, knownSerials.contains(serial) { skipped += 1; continue }
            merged.append(device)
            added += 1
            if !serial.isEmpty { knownSerials.insert(serial) }
        }
        inventory.devices = merged
        inventory.record("Import CSV", deviceName: "\(added) appareil(s) ajouté(s), \(skipped) doublon(s) ignoré(s)")
        csvImportDevices = []
        showCSVPreview = false
        selectedID = nil
        showHome = false
        showFeatures = false
        showSettings = false
        showComparison = false
    }

    private func openCollectionGallery() {
        let controller = GalleryWindowController(devices: inventory.devices)
        galleryWindowController = controller
        controller.showGallery()
    }

    private func exportCollectionPDF() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.pdf]
        panel.nameFieldStringValue = "AppleVault-Collection.pdf"
        panel.title = "Exporter la collection en PDF"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let page = CGRect(x: 0, y: 0, width: 595, height: 842)
        var mediaBox = page
        guard let consumer = CGDataConsumer(url: url as CFURL),
              let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil) else { return }
        let fields = chosenExportFields
        let content = inventory.devices.map { device in
            ([device.model] + fields.map { "\($0.title) : \(exportValue($0.id, from: device, hideSerial: hideSerialNumbers).isEmpty ? "—" : exportValue($0.id, from: device, hideSerial: hideSerialNumbers))" } + ["\n"]).joined(separator: "\n")
        }.joined(separator: "\n")
        let text = NSAttributedString(string: "APPLEVAULT — MA COLLECTION\nExport du \(Date.now.formatted(date: .long, time: .shortened))\n\n\(content)", attributes: [
            .font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.black
        ])
        let framesetter = CTFramesetterCreateWithAttributedString(text as CFAttributedString)
        var start = 0
        while start < text.length {
            context.beginPDFPage(nil)
            let path = CGPath(rect: page.insetBy(dx: 42, dy: 42), transform: nil)
            let frame = CTFramesetterCreateFrame(framesetter, CFRange(location: start, length: 0), path, nil)
            CTFrameDraw(frame, context)
            let visible = CTFrameGetVisibleStringRange(frame)
            context.endPDFPage()
            guard visible.length > 0 else { break }
            start += visible.length
        }
        context.closePDF()
    }

    private func exportJSON() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(inventory.devices) else { return }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("AppleVault-sauvegarde.json")
        guard (try? data.write(to: url, options: .atomic)) != nil else { return }
        exportFile = url
        showExport = true
    }
}

private struct HomeView: View {
    let devices: [AppleDevice]
    let version: String
    let homeCardOrder: String
    let weatherCity: String
    let weatherSourceURL: String
    let alertLowBattery: Bool
    let alertWarranty: Bool
    let alertIncomplete: Bool
    let incompleteCount: Int
    let onOpenFeatures: () -> Void
    let onOpenCollection: () -> Void
    let onAddDevice: () -> Void

    private var totalEstimate: Double { devices.compactMap(collectionEstimate).reduce(0, +) }
    private var estimateCount: Int { devices.compactMap(collectionEstimate).count }
    private var alertCount: Int {
        devices.filter { device in
            guard !device.warningsIgnored else { return false }
            let lowBattery = alertLowBattery && (batteryPercent(from: device.batteryHealth).map { $0 < 80 } ?? false)
            let needsRepair = !device.repairsTodo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            let warrantyCutoff = Calendar.current.date(byAdding: .day, value: 30, to: .now) ?? .now
            let warranty = alertWarranty && (device.warrantyEndDate.map { $0 <= warrantyCutoff } ?? false)
            return lowBattery || needsRepair || warranty
        }.count + (alertIncomplete ? incompleteCount : 0)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(spacing: 18) {
                    Image("AppleVaultBrand")
                        .resizable()
                        .scaledToFill()
                        .frame(width: 240, height: 240)
                        .clipShape(RoundedRectangle(cornerRadius: 54, style: .continuous))
                        .accessibilityLabel("Logo AppleVault avec le symbole de verrouillage")

                    VStack(alignment: .leading, spacing: 7) {
                        Text("AppleVault")
                            .font(.system(size: 34, weight: .bold, design: .rounded))
                        Text("Ta collection Apple, réunie au même endroit.")
                            .font(.title3).foregroundStyle(.secondary)
                        Text("Version \(version)").font(.caption.weight(.semibold)).padding(.horizontal, 10).padding(.vertical, 5)
                            .background(.blue.opacity(0.12), in: Capsule()).foregroundStyle(.blue)
                    }
                    Spacer(minLength: 0)
                }
                .padding(24)
                .background(LinearGradient(colors: [.blue.opacity(0.14), .purple.opacity(0.08)], startPoint: .topLeading, endPoint: .bottomTrailing), in: RoundedRectangle(cornerRadius: 22))

                WeatherClockCard(city: weatherCity, sourceURL: weatherSourceURL)

                HStack(spacing: 14) {
                    ForEach(homeCardOrder.split(separator: ",").map(String.init), id: \.self) { key in
                        if key == "devices" {
                            HomeStatCard(title: "Appareils", value: "\(devices.count)", symbol: "square.stack.3d.up.fill", tint: .blue)
                        } else if key == "value" {
                            HomeStatCard(title: "Valeur indicative", value: estimateCount == 0 ? "—" : formatEuro(totalEstimate), symbol: "eurosign.circle.fill", tint: .green)
                        } else if key == "alerts" {
                            HomeStatCard(title: "À vérifier", value: "\(alertCount)", symbol: "bell.badge.fill", tint: alertCount == 0 ? .mint : .orange)
                        } else if key == "favorites" {
                            HomeStatCard(title: "Favoris", value: "\(devices.filter(\.isFavorite).count)", symbol: "heart.fill", tint: .pink)
                        } else if key == "repairs" {
                            HomeStatCard(title: "Réparations", value: "\(devices.filter { !$0.repairsTodo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.count)", symbol: "wrench.and.screwdriver.fill", tint: .orange)
                        }
                    }
                }

                HStack(spacing: 12) {
                    Button(action: onAddDevice) {
                        Label("Ajouter un appareil", systemImage: "plus.circle.fill")
                            .frame(maxWidth: .infinity).padding(.vertical, 12)
                    }.buttonStyle(.borderedProminent)
                    Button(action: onOpenCollection) {
                        Label("Ma collection", systemImage: "square.stack.3d.up")
                            .frame(maxWidth: .infinity).padding(.vertical, 12)
                    }.buttonStyle(.bordered)
                    Button(action: onOpenFeatures) {
                        Label("Toutes les fonctions", systemImage: "square.grid.2x2")
                            .frame(maxWidth: .infinity).padding(.vertical, 12)
                    }.buttonStyle(.bordered)
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Nouveautés de la version \(version)", systemImage: "sparkles")
                            .font(.title3.bold())
                        HomeNewsRow(symbol: "tag", text: "Numéro A et référence commerciale Apple (ex. M21HFZU/A) sur chaque fiche.")
                        HomeNewsRow(symbol: "chart.bar.fill", text: "Estimation indicative automatique selon le modèle, le stockage, l’état, la batterie et les réparations.")
                        HomeNewsRow(symbol: "person.2.fill", text: "Profils locaux séparés, avec collection et préférences propres à chacun.")
                        HomeNewsRow(symbol: "externaldrive.fill", text: "Sauvegardes locales automatiques et restauration/export de la collection.")
                        HomeNewsRow(symbol: "bell.badge.fill", text: "Rappels d’entretien, alertes batterie, favoris et réparations à prévoir.")
                        HomeNewsRow(symbol: "clock.arrow.circlepath", text: "Chronologie par appareil pour suivre les changements, réparations, accessoires et garantie.")
                        HomeNewsRow(symbol: "shippingbox", text: "Suivi de la boîte, du chargeur, de la facture et des autres accessoires.")
                        HomeNewsRow(symbol: "magnifyingglass", text: "Recherche locale par numéro A ou par référence Apple déjà enregistrée.")
                        HomeNewsRow(symbol: "doc.richtext", text: "Export PDF de la collection, avec les références et les informations principales.")
                        HomeNewsRow(symbol: "bell.slash", text: "Ignorer ou réactiver les avertissements fiche par fiche.")
                        HomeNewsRow(symbol: "slider.horizontal.3", text: "Personnaliser les cartes de l’accueil et leur ordre d’affichage.")
                        HomeNewsRow(symbol: "externaldrive.badge.timemachine", text: "Choisir la fréquence et la conservation des sauvegardes, puis restaurer une ancienne copie.")
                        HomeNewsRow(symbol: "lock.fill", text: "Masquer les numéros de série et choisir les champs des exports PDF et CSV.")
                        HomeNewsRow(symbol: "bell.badge", text: "Activer ou désactiver séparément les alertes batterie, garantie et fiches à compléter.")
                        HomeNewsRow(symbol: "cloud.sun.fill", text: "Météo actuelle et horloge locale pour la ville choisie dans les réglages.")
                        HomeNewsRow(symbol: "square.grid.2x2", text: "Nouvelle rubrique qui présente les fonctions d’AppleVault par catégorie.")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 5)
                }

                Text("Les estimations sont indicatives et ne représentent pas une cote de revente en temps réel.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(26)
            .frame(maxWidth: 1050, alignment: .leading)
        }
        .navigationTitle("Accueil")
    }
}


private struct GeoSearchResponse: Decodable { let results: [GeoLocation]? }

private struct GeoLocation: Decodable {
    let name: String
    let country: String?
    let latitude: Double
    let longitude: Double
    let timezone: String?
}

private struct WeatherResponse: Decodable {
    let timezone: String?
    let current: CurrentWeather
}

private struct CurrentWeather: Decodable {
    let temperature_2m: Double
    let apparent_temperature: Double
    let relative_humidity_2m: Int
    let weather_code: Int
    let wind_speed_10m: Double
    let is_day: Int
}

private struct WeatherClockCard: View {
    let city: String
    let sourceURL: String
    @State private var weather: CurrentWeather?
    @State private var timezoneIdentifier: String?
    @State private var resolvedCity: String?
    @State private var isLoading = false
    @State private var hasError = false

    private var timezone: TimeZone {
        timezoneIdentifier.flatMap(TimeZone.init(identifier:)) ?? .current
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { timeline in
            HStack(spacing: 18) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(timeline.date.formatted(Date.FormatStyle(date: .omitted, time: .shortened, locale: Locale(identifier: "fr_FR"), calendar: .current, timeZone: timezone)))
                        .font(.system(size: 38, weight: .semibold, design: .rounded))
                        .monospacedDigit()
                    Text(timeline.date.formatted(Date.FormatStyle(date: .complete, time: .omitted, locale: Locale(identifier: "fr_FR"), calendar: .current, timeZone: timezone)))
                        .font(.callout.weight(.medium)).foregroundStyle(.secondary)
                    Label(resolvedCity ?? city.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty ?? "Choisir une ville",
                          systemImage: "mappin.and.ellipse")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                if let weather {
                    VStack(alignment: .trailing, spacing: 5) {
                        HStack(spacing: 8) {
                            Image(systemName: Self.symbol(for: weather.weather_code, isDay: weather.is_day == 1))
                                .symbolRenderingMode(.multicolor).font(.system(size: 32))
                            Text(weather.temperature_2m.formatted(.number.precision(.fractionLength(0))) + "°")
                                .font(.system(size: 34, weight: .medium, design: .rounded)).monospacedDigit()
                        }
                        Text(Self.description(for: weather.weather_code)).font(.subheadline.weight(.medium))
                        Text("Ressenti \(weather.apparent_temperature.formatted(.number.precision(.fractionLength(0))))° · Vent \(weather.wind_speed_10m.formatted(.number.precision(.fractionLength(0)))) km/h")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: 250, alignment: .trailing)
                } else {
                    VStack(alignment: .trailing, spacing: 6) {
                        if isLoading {
                            ProgressView().controlSize(.small)
                            Text("Chargement de la météo…").font(.caption).foregroundStyle(.secondary)
                        } else {
                            Image(systemName: hasError ? "cloud.slash" : "cloud.sun")
                                .font(.system(size: 25)).foregroundStyle(.secondary)
                            Text(hasError ? "Météo indisponible" : "Météo actuelle").font(.subheadline.weight(.medium))
                            Text("Vérifie la ville ou la connexion.").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: 230, alignment: .trailing)
                }
            }
            .padding(.horizontal, 24).padding(.vertical, 19)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(LinearGradient(colors: [Color.blue.opacity(0.10), Color.cyan.opacity(0.06), Color.purple.opacity(0.08)],
                                       startPoint: .topLeading, endPoint: .bottomTrailing), in: RoundedRectangle(cornerRadius: 20))
            .overlay(RoundedRectangle(cornerRadius: 20).strokeBorder(.quaternary, lineWidth: 1))
        }
        .task(id: city.trimmingCharacters(in: .whitespacesAndNewlines) + "|" + sourceURL) {
            let requestedCity = city.trimmingCharacters(in: .whitespacesAndNewlines)
            weather = nil
            timezoneIdentifier = nil
            resolvedCity = nil
            guard !requestedCity.isEmpty else { hasError = false; isLoading = false; return }
            while !Task.isCancelled {
                await refresh(for: requestedCity)
                do { try await Task.sleep(nanoseconds: 15 * 60 * 1_000_000_000) }
                catch { break }
            }
        }
    }

    private func refresh(for city: String) async {
        isLoading = weather == nil
        hasError = false
        do {
            var geocoding = URLComponents(string: "https://geocoding-api.open-meteo.com/v1/search")!
            geocoding.queryItems = [URLQueryItem(name: "name", value: city), URLQueryItem(name: "count", value: "1"),
                                    URLQueryItem(name: "language", value: "fr"), URLQueryItem(name: "format", value: "json")]
            let (geoData, geoResponse) = try await URLSession.shared.data(from: geocoding.url!)
            guard (geoResponse as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            let locations = try JSONDecoder().decode(GeoSearchResponse.self, from: geoData).results ?? []
            guard let location = locations.first else { throw URLError(.cannotFindHost) }

            let sourceRoot = sourceURL.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            guard let forecastComponents = URLComponents(string: "\(sourceRoot)/v1/forecast"),
                  forecastComponents.scheme?.lowercased() == "https", forecastComponents.host != nil else {
                throw URLError(.badURL)
            }
            var forecast = forecastComponents
            forecast.queryItems = [URLQueryItem(name: "latitude", value: String(location.latitude)),
                                   URLQueryItem(name: "longitude", value: String(location.longitude)),
                                   URLQueryItem(name: "current", value: "temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m,is_day"),
                                   URLQueryItem(name: "timezone", value: "auto")]
            let (weatherData, weatherResponse) = try await URLSession.shared.data(from: forecast.url!)
            guard (weatherResponse as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            let result = try JSONDecoder().decode(WeatherResponse.self, from: weatherData)
            guard !Task.isCancelled else { return }
            weather = result.current
            timezoneIdentifier = result.timezone ?? location.timezone
            resolvedCity = [location.name, location.country].compactMap { $0 }.joined(separator: ", ")
            hasError = false
        } catch {
            DeveloperDiagnosticLog.write("Échec de récupération météo pour la ville configurée.")
            if weather == nil { hasError = true }
        }
        isLoading = false
    }

    private static func description(for code: Int) -> String {
        switch code {
        case 0: "Ciel dégagé"
        case 1: "Peu nuageux"
        case 2: "Partiellement nuageux"
        case 3: "Couvert"
        case 45, 48: "Brouillard"
        case 51, 53, 55: "Bruine"
        case 56, 57: "Bruine verglaçante"
        case 61, 63, 65: "Pluie"
        case 66, 67: "Pluie verglaçante"
        case 71, 73, 75, 77: "Neige"
        case 80, 81, 82: "Averses"
        case 85, 86: "Averses de neige"
        case 95: "Orage"
        case 96, 99: "Orage et grêle"
        default: "Conditions météo"
        }
    }

    private static func symbol(for code: Int, isDay: Bool) -> String {
        switch code {
        case 0: isDay ? "sun.max.fill" : "moon.stars.fill"
        case 1, 2: isDay ? "cloud.sun.fill" : "cloud.moon.fill"
        case 3: "cloud.fill"
        case 45, 48: "cloud.fog.fill"
        case 51...57: "cloud.drizzle.fill"
        case 61...67, 80...82: "cloud.rain.fill"
        case 71...77, 85...86: "cloud.snow.fill"
        case 95...99: "cloud.bolt.rain.fill"
        default: "cloud.sun.fill"
        }
    }
}

private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }

private struct FeatureCategory: Identifiable {
    let title: String
    let symbol: String
    let summary: String
    let items: [String]
    var id: String { title }
}

private struct FeaturesView: View {
    private let categories: [FeatureCategory] = [
        FeatureCategory(title: "Collection et fiches", symbol: "square.stack.3d.up.fill",
                        summary: "Constitue un inventaire détaillé de tes appareils Apple.",
                        items: ["Ajouter et modifier les fiches iPhone, iPad, Mac, Apple Watch, AirPods et autres appareils.",
                                "Renseigner le modèle, l’identifiant, le numéro A, la référence commerciale, le stockage, la couleur et le numéro de série.",
                                "Suivre iOS/iPadOS, l’état, la batterie, les accessoires, la boîte, le chargeur et la facture.",
                                "Ajouter des notes, des étiquettes, des informations de jailbreak et des blobs SHSH."]),
        FeatureCategory(title: "Valeur et achats", symbol: "eurosign.circle.fill",
                        summary: "Garde une vue sur le prix et la valeur indicative de ta collection.",
                        items: ["Enregistrer la date et le prix d’achat.",
                                "Obtenir une estimation automatique selon le modèle et son état, ou saisir une valeur manuelle.",
                                "Consulter la valeur estimée de la collection dans les statistiques et sur l’accueil."]),
        FeatureCategory(title: "Entretien et historique", symbol: "wrench.and.screwdriver.fill",
                        summary: "Retrouve rapidement ce qui a été fait ou reste à faire.",
                        items: ["Consigner les réparations, leurs dates et leurs coûts.",
                                "Noter les réparations à prévoir et programmer un entretien.",
                                "Suivre la date de fin de garantie et les alertes batterie.",
                                "Consulter la chronologie des changements et ignorer les avertissements d’une fiche."]),
        FeatureCategory(title: "Recherche et organisation", symbol: "line.3.horizontal.decrease.circle",
                        summary: "Parcours et compare tes appareils sans perdre le fil.",
                        items: ["Rechercher dans les fiches et filtrer par famille, état ou étiquette.",
                                "Créer une liste de favoris et une liste des réparations à prévoir.",
                                "Comparer les caractéristiques de deux appareils.",
                                "Voir un tableau de bord et des statistiques sur la collection."]),
        FeatureCategory(title: "Accueil personnalisé", symbol: "house.fill",
                        summary: "L’accueil rassemble les informations importantes.",
                        items: ["Afficher les nouveautés de l’application et personnaliser les cartes statistiques.",
                                "Consulter l’heure, la date et la météo de la ville choisie dans les réglages."]),
        FeatureCategory(title: "Profils, sauvegardes et réglages", symbol: "gearshape.fill",
                        summary: "Gère les collections et adapte l’application à tes préférences.",
                        items: ["Créer plusieurs profils locaux avec une collection indépendante et protéger l’ouverture par mot de passe.",
                                "Conserver les données localement, choisir la fréquence et le nombre de sauvegardes, puis restaurer une ancienne copie.",
                                "Importer ou exporter en JSON, exporter en CSV ou PDF et choisir les champs exportés.",
                                "Masquer les numéros de série dans les fiches et les exports, choisir le thème et consulter les informations système.",
                                "Consulter la version de l’app et rechercher une mise à jour."])
    ]
    private let columns = [GridItem(.flexible(), spacing: 14), GridItem(.flexible(), spacing: 14)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Tout ce qu’AppleVault peut faire", systemImage: "square.grid.2x2.fill")
                        .font(.largeTitle.bold())
                    Text("Un aperçu des outils disponibles pour organiser ta collection Apple.")
                        .foregroundStyle(.secondary)
                }
                LazyVGrid(columns: columns, alignment: .leading, spacing: 14) {
                    ForEach(categories) { category in FeatureCategoryCard(category: category) }
                }
                Text("Les estimations sont indicatives. Les données et sauvegardes sont conservées localement sur ce Mac.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(26).frame(maxWidth: 1100, alignment: .leading)
        }
        .navigationTitle("Fonctionnalités")
    }
}

private struct FeatureCategoryCard: View {
    let category: FeatureCategory
    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Label(category.title, systemImage: category.symbol).font(.title3.bold())
                Text(category.summary).font(.subheadline).foregroundStyle(.secondary)
                ForEach(category.items, id: \.self) { item in
                    Label(item, systemImage: "checkmark.circle.fill")
                        .font(.callout).fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
        }
    }
}

private struct HomeStatCard: View {
    let title: String
    let value: String
    let symbol: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: symbol).font(.subheadline.weight(.medium)).foregroundStyle(.secondary)
            Text(value).font(.title2.bold()).foregroundStyle(tint).lineLimit(1).minimumScaleFactor(0.75)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(.background, in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(.quaternary, lineWidth: 1))
    }
}

private struct HomeNewsRow: View {
    let symbol: String
    let text: String

    var body: some View {
        Label(text, systemImage: symbol)
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct DashboardView: View {
    let devices: [AppleDevice]
    let onSelectDevice: (UUID) -> Void

    private let columns = [GridItem(.flexible(), spacing: 14), GridItem(.flexible(), spacing: 14)]

    private var batteries: [(AppleDevice, Double)] {
        devices.compactMap { device in
            guard let value = number(from: device.batteryHealth), (0...100).contains(value) else { return nil }
            return (device, value)
        }
    }

    private var knownCosts: [Double] { devices.compactMap { number(from: $0.purchasePrice) } }
    private var knownEstimates: [Double] { devices.compactMap(collectionEstimate) }
    private var repairSpend: [Double] { devices.flatMap(\.repairHistory).compactMap { number(from: $0.cost) } }
    private var knownStorage: [Double] { devices.compactMap { storageGB(from: $0.storage) } }
    private var totalStorageGB: Double { knownStorage.reduce(0, +) }
    private var avgBattery: Double? { batteries.isEmpty ? nil : batteries.map { $0.1 }.reduce(0, +) / Double(batteries.count) }
    private var lowBattery: Int { batteries.filter { $0.1 < 80 }.count }
    private var pendingRepairs: [AppleDevice] {
        devices.filter { !$0.repairsTodo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }
    private var filledPhotos: Int { devices.filter { !$0.photoPath.isEmpty || !$0.appleImageURL.isEmpty }.count }
    private var filledSerials: Int { devices.filter { !$0.serial.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.count }
    private var filledIOS: Int { devices.filter { !$0.ios.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.count }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Tableau de bord").font(.largeTitle.bold())
                        Text("Un aperçu complet de ta collection Apple").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(Date.now, format: .dateTime.day().month(.wide).year())
                        .font(.callout).foregroundStyle(.secondary)
                }

                LazyVGrid(columns: columns, spacing: 14) {
                    MetricCard(title: "Appareils", value: "\(devices.count)", detail: "dans la collection", icon: "square.stack.3d.up.fill", tint: .blue)
                    MetricCard(title: "Dépenses connues", value: money(knownCosts.reduce(0, +)), detail: "\(knownCosts.count) prix renseigné(s)", icon: "eurosign.circle.fill", tint: .green)
                    MetricCard(title: "Valeur estimée", value: money(knownEstimates.reduce(0, +)), detail: "estimation automatique indicative", icon: "chart.line.uptrend.xyaxis", tint: .mint)
                    MetricCard(title: "Coût des réparations", value: money(repairSpend.reduce(0, +)), detail: "\(repairSpend.count) coût(s) enregistré(s)", icon: "wrench.and.screwdriver", tint: .orange)
                    MetricCard(title: "Batterie moyenne", value: avgBattery.map { "\(Int($0.rounded()))%" } ?? "—", detail: "sur \(batteries.count) appareil(s) renseigné(s)", icon: "battery.75percent", tint: .orange)
                    MetricCard(title: "Batteries à surveiller", value: "\(lowBattery)", detail: "sous 80% de capacité", icon: "battery.25percent", tint: lowBattery > 0 ? .red : .green)
                    MetricCard(title: "Réparations à prévoir", value: "\(pendingRepairs.count)", detail: "fiche(s) avec une intervention notée", icon: "wrench.and.screwdriver.fill", tint: pendingRepairs.isEmpty ? .green : .orange)
                    MetricCard(title: "Jailbreak", value: "\(devices.filter { !$0.jailbreak.isEmpty }.count)", detail: "appareil(s) documenté(s)", icon: "lock.open.fill", tint: .purple)
                    MetricCard(title: "Blobs SHSH", value: "\(devices.filter { !$0.shsh.isEmpty }.count)", detail: "fiche(s) avec blobs notés", icon: "externaldrive.fill", tint: .indigo)
                    MetricCard(title: "Photos", value: "\(filledPhotos)", detail: "sur \(devices.count) appareil(s)", icon: "photo.fill", tint: .pink)
                    MetricCard(title: "Stockage cumulé", value: storageLabel, detail: "\(knownStorage.count) capacité(s) renseignée(s)", icon: "internaldrive.fill", tint: .cyan)
                    MetricCard(title: "Modèles différents", value: "\(Set(devices.map(\.model).filter { !$0.isEmpty }).count)", detail: "références distinctes", icon: "square.grid.2x2.fill", tint: .teal)
                }

                LazyVGrid(columns: columns, spacing: 14) {
                    ChartCard(title: "Collection par famille", subtitle: "Nombre d’appareils") {
                        let values = distribution(devices.map(familyName))
                        Chart(values) { item in
                            BarMark(x: .value("Famille", item.label), y: .value("Appareils", item.value))
                                .foregroundStyle(by: .value("Famille", item.label))
                                .cornerRadius(5)
                        }
                        .chartLegend(.hidden)
                        .chartXAxis { AxisMarks(preset: .aligned) { AxisValueLabel().font(.caption2) } }
                    }
                    ChartCard(title: "État des appareils", subtitle: "Répartition des états renseignés") {
                        let values = distribution(devices.map(\.condition).filter { !$0.isEmpty })
                        if values.isEmpty { EmptyChartNote() }
                        else {
                            Chart(values) { item in
                                SectorMark(angle: .value("Appareils", item.value), innerRadius: .ratio(0.58), angularInset: 2)
                                    .foregroundStyle(by: .value("État", item.label))
                            }
                            .chartLegend(position: .bottom, alignment: .leading, spacing: 10)
                        }
                    }
                    ChartCard(title: "Versions iOS / iPadOS", subtitle: "Appareils par version") {
                        let values = distribution(devices.map(\.ios).filter { !$0.isEmpty })
                        if values.isEmpty { EmptyChartNote() }
                        else {
                            Chart(values) { item in
                                BarMark(x: .value("Version", item.label), y: .value("Appareils", item.value))
                                    .foregroundStyle(.blue.gradient).cornerRadius(5)
                            }
                            .chartXAxis { AxisMarks { AxisValueLabel().font(.caption2) } }
                        }
                    }
                    ChartCard(title: "Stockage", subtitle: "Capacités les plus fréquentes") {
                        let values = distribution(devices.map(\.storage).filter { !$0.isEmpty })
                        if values.isEmpty { EmptyChartNote() }
                        else {
                            Chart(values) { item in
                                BarMark(x: .value("Capacité", item.label), y: .value("Appareils", item.value))
                                    .foregroundStyle(.purple.gradient).cornerRadius(5)
                            }
                            .chartXAxis { AxisMarks { AxisValueLabel().font(.caption2) } }
                        }
                    }
                }

                HStack(alignment: .top, spacing: 14) {
                    GroupBox("Batteries à surveiller") {
                        VStack(alignment: .leading, spacing: 8) {
                            if batteries.filter({ $0.1 < 80 }).isEmpty { Text("Aucune batterie sous 80%.").foregroundStyle(.secondary) }
                            ForEach(devices.filter({ (number(from: $0.batteryHealth) ?? 100) < 80 })) { device in
                                Button { onSelectDevice(device.id) } label: {
                                    HStack { Text(device.model); Spacer(); Text("\(Int(number(from: device.batteryHealth) ?? 0))%") }
                                }.buttonStyle(.plain)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 4)
                    }
                    GroupBox("Réparations à prévoir") {
                        VStack(alignment: .leading, spacing: 8) {
                            if pendingRepairs.isEmpty { Text("Aucune réparation notée.").foregroundStyle(.secondary) }
                            ForEach(pendingRepairs) { device in
                                Button { onSelectDevice(device.id) } label: {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(device.model).font(.headline)
                                        Text(device.repairsTodo).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                                    }.frame(maxWidth: .infinity, alignment: .leading)
                                }.buttonStyle(.plain)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 4)
                    }
                }

                GroupBox("Complétude de l’inventaire") {
                    VStack(spacing: 12) {
                        CompletionRow(title: "Numéro de série", filled: filledSerials, total: devices.count)
                        CompletionRow(title: "Version iOS / iPadOS", filled: filledIOS, total: devices.count)
                        CompletionRow(title: "Batterie renseignée", filled: batteries.count, total: devices.count)
                        CompletionRow(title: "Photo disponible", filled: filledPhotos, total: devices.count)
                    }.padding(.vertical, 5)
                }
            }
            .padding(26)
            .frame(maxWidth: 1100, alignment: .leading)
        }
        .navigationTitle("AppleVault")
    }

    private func number(from text: String) -> Double? {
        let separators = text.indices.filter { text[$0] == "," || text[$0] == "." }
        let decimalSeparator = separators.last
        var normalized = ""
        for index in text.indices {
            let character = text[index]
            if character.isNumber { normalized.append(character) }
            else if index == decimalSeparator { normalized.append(".") }
        }
        return Double(normalized)
    }

    private func storageGB(from text: String) -> Double? {
        guard let amount = number(from: text) else { return nil }
        let normalized = text.lowercased()
        if normalized.contains("tb") || normalized.contains("to") { return amount * 1024 }
        return amount
    }

    private var storageLabel: String {
        if totalStorageGB >= 1024 { return "\((totalStorageGB / 1024).formatted(.number.precision(.fractionLength(1)))) To" }
        return "\(Int(totalStorageGB.rounded())) Go"
    }

    private func money(_ amount: Double) -> String {
        amount.formatted(.currency(code: "EUR").locale(Locale(identifier: "fr_FR")))
    }

    private func familyName(_ device: AppleDevice) -> String {
        let model = device.model.lowercased()
        if model.contains("iphone") { return "iPhone" }
        if model.contains("ipad") { return "iPad" }
        if model.contains("watch") { return "Watch" }
        if model.contains("mac") || model.contains("macbook") || model.contains("imac") { return "Mac" }
        if model.contains("airpods") { return "AirPods" }
        return "Autre"
    }

    private func distribution(_ values: [String]) -> [ChartDatum] {
        Dictionary(grouping: values, by: { $0 })
            .map { ChartDatum(label: $0.key, value: $0.value.count) }
            .sorted { $0.value == $1.value ? $0.label.localizedStandardCompare($1.label) == .orderedAscending : $0.value > $1.value }
    }
}

private struct ChartDatum: Identifiable {
    let label: String
    let value: Int
    var id: String { label }
}

private struct ComparisonView: View {
    let devices: [AppleDevice]
    @State private var leftID = ""
    @State private var rightID = ""

    private var leftDevice: AppleDevice? { devices.first { $0.id.uuidString == leftID } }
    private var rightDevice: AppleDevice? { devices.first { $0.id.uuidString == rightID } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Comparer deux appareils").font(.largeTitle.bold())
                    Text("Choisis deux fiches pour mettre leurs informations côte à côte.")
                        .foregroundStyle(.secondary)
                }
                if devices.count < 2 {
                    ContentUnavailableView("Il faut deux appareils", systemImage: "rectangle.split.2x1", description: Text("Ajoute au moins deux appareils pour pouvoir les comparer."))
                } else {
                    HStack(spacing: 16) {
                        devicePicker("Premier appareil", selection: $leftID)
                        devicePicker("Deuxième appareil", selection: $rightID)
                    }
                    if let leftDevice, let rightDevice {
                        HStack(alignment: .top, spacing: 18) {
                            comparisonColumn(leftDevice)
                            comparisonColumn(rightDevice)
                        }
                    }
                }
            }
            .padding(28)
            .frame(maxWidth: 1000, alignment: .leading)
        }
        .navigationTitle("Comparaison")
        .onAppear {
            if leftID.isEmpty { leftID = devices.first?.id.uuidString ?? "" }
            if rightID.isEmpty { rightID = devices.dropFirst().first?.id.uuidString ?? "" }
        }
    }

    private func devicePicker(_ title: String, selection: Binding<String>) -> some View {
        Picker(title, selection: selection) {
            ForEach(devices) { device in
                Text(device.model.isEmpty ? "Appareil sans nom" : device.model).tag(device.id.uuidString)
            }
        }
        .pickerStyle(.menu)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func comparisonColumn(_ device: AppleDevice) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                DeviceImage(device: device).frame(width: 56, height: 64)
                Text(device.model).font(.title3.bold())
            }
            GroupBox {
                VStack(spacing: 10) {
                    CompareRow("Identifiant", device.identifier)
                    CompareRow("Numéro A", device.aNumber)
                    CompareRow("Stockage", device.storage)
                    CompareRow("Couleur", device.color)
                    CompareRow("Version système", device.ios)
                    CompareRow("État", device.condition)
                    CompareRow("Batterie", device.batteryHealth.isEmpty ? "" : "\(device.batteryHealth)%")
                    CompareRow("Prix d’achat", device.purchasePrice.isEmpty ? "" : "\(device.purchasePrice) €")
                    CompareRow("Valeur estimée", collectionEstimate(for: device).map { formatEuro($0) } ?? "À estimer")
                    CompareRow("Jailbreak", device.jailbreak)
                    CompareRow("SHSH", device.shsh)
                    CompareRow("Réparations enregistrées", "\(device.repairHistory.count)")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct CompareRow: View {
    let title: String
    let value: String
    init(_ title: String, _ value: String) { self.title = title; self.value = value }
    var body: some View {
        HStack(alignment: .top) {
            Text(title).foregroundStyle(.secondary)
            Spacer(minLength: 8)
            Text(value.isEmpty ? "—" : value).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
        .font(.callout)
    }
}

private struct MetricCard: View {
    let title: String
    let value: String
    let detail: String
    let icon: String
    let tint: Color

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon).font(.title2).foregroundStyle(tint)
                .frame(width: 46, height: 46).background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 13))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.caption).foregroundStyle(.secondary)
                Text(value).font(.title2.bold()).lineLimit(1).minimumScaleFactor(0.75)
                Text(detail).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(15)
        .frame(maxWidth: .infinity, minHeight: 100, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
    }
}

private struct ChartCard<Content: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder let content: Content

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 2) {
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
                content.frame(height: 190)
            }.frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(title).font(.headline)
        }
    }
}

private struct EmptyChartNote: View {
    var body: some View {
        ContentUnavailableView("Pas encore de données", systemImage: "chart.bar", description: Text("Complète les fiches pour afficher ce graphique."))
            .font(.caption)
    }
}

private struct CompletionRow: View {
    let title: String
    let filled: Int
    let total: Int

    var body: some View {
        HStack {
            Text(title).frame(width: 190, alignment: .leading)
            ProgressView(value: Double(filled), total: Double(max(total, 1)))
            Text("\(filled) / \(total)").font(.caption.monospacedDigit()).foregroundStyle(.secondary).frame(width: 60, alignment: .trailing)
        }
    }
}

private struct ShareSheetView: View {
    @Environment(\.dismiss) private var dismiss
    let fileURL: URL
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "tablecells").font(.largeTitle).foregroundStyle(.tint)
            Text("Collection exportée").font(.title2.bold())
            Text("Le fichier CSV peut être ouvert dans Numbers ou Excel.").foregroundStyle(.secondary)
            ShareLink(item: fileURL) { Label("Partager le fichier CSV", systemImage: "square.and.arrow.up") }
            Button("Terminé") { dismiss() }.keyboardShortcut(.defaultAction)
        }.padding(32).frame(minWidth: 340)
    }
}

private struct CSVImportPreviewView: View {
    @Environment(\.dismiss) private var dismiss
    let devices: [AppleDevice]
    let existingDevices: [AppleDevice]
    let onImport: (Bool) -> Void
    @State private var ignoreExistingSerials = true

    private var existingSerials: Set<String> {
        Set(existingDevices.map { $0.serial.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() }.filter { !$0.isEmpty })
    }
    private var duplicateCount: Int {
        var seen = existingSerials
        return devices.filter { device in
            let serial = device.serial.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            guard !serial.isEmpty else { return false }
            if seen.contains(serial) { return true }
            seen.insert(serial)
            return false
        }.count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "tablecells.badge.ellipsis").font(.largeTitle).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Aperçu de l’import CSV").font(.title2.bold())
                    Text("\(devices.count) appareil(s) détecté(s) · \(duplicateCount) numéro(s) de série déjà présent(s)")
                        .foregroundStyle(.secondary)
                }
            }
            Toggle("Ignorer les numéros de série déjà présents", isOn: $ignoreExistingSerials)
            Text("Les lignes sans numéro de série sont conservées. Les données ne seront ajoutées qu’après confirmation.")
                .font(.caption).foregroundStyle(.secondary)
            List(Array(devices.prefix(12).enumerated()), id: \.offset) { index, device in
                HStack(spacing: 12) {
                    Text(String(format: "%02d", index + 1)).font(.caption.monospacedDigit()).foregroundStyle(.tertiary).frame(width: 28)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(device.model.isEmpty ? "Appareil sans nom" : device.model).font(.headline)
                        Text([device.serial.isEmpty ? "Sans numéro de série" : "N° série : \(device.serial)", device.storage, device.color]
                            .filter { !$0.isEmpty }.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if !device.serial.isEmpty && existingSerials.contains(device.serial.uppercased()) {
                        Label("Déjà présent", systemImage: "arrow.triangle.2.circlepath").font(.caption).foregroundStyle(.orange)
                    }
                }.padding(.vertical, 3)
            }
            if devices.count > 12 { Text("Et \(devices.count - 12) autre(s) appareil(s)…").font(.caption).foregroundStyle(.secondary) }
            HStack {
                Button("Annuler") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Ajouter \(ignoreExistingSerials ? devices.count - duplicateCount : devices.count) appareil(s)") {
                    onImport(ignoreExistingSerials)
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            }
        }
        .padding(24).frame(minWidth: 620, minHeight: 520)
    }
}

private struct InventoryModeView: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage("appleVault.inventory.checkedIDs") private var checkedIDsData = ""
    @AppStorage("appleVault.inventory.presentIDs") private var presentIDsData = ""
    let devices: [AppleDevice]
    @State private var currentIndex = 0

    private var checkedIDs: Set<String> { Set(checkedIDsData.split(separator: ",").map(String.init)) }
    private var presentIDs: Set<String> { Set(presentIDsData.split(separator: ",").map(String.init)) }
    private var currentDevice: AppleDevice? { devices.indices.contains(currentIndex) ? devices[currentIndex] : nil }

    var body: some View {
        VStack(spacing: 20) {
            HStack {
                Image(systemName: "checklist.checked").font(.title).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Mode inventaire").font(.title2.bold())
                    Text("Vérifie chaque appareil de ta collection, un par un.").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Terminer", systemImage: "xmark") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            if devices.isEmpty {
                ContentUnavailableView("Collection vide", systemImage: "square.stack.3d.up", description: Text("Ajoute d’abord un appareil pour commencer l’inventaire."))
            } else if let device = currentDevice {
                HStack {
                    Text("Progression").font(.caption).foregroundStyle(.secondary)
                    ProgressView(value: Double(checkedIDs.count), total: Double(devices.count))
                    Text("\(min(checkedIDs.count, devices.count)) / \(devices.count)").font(.caption.monospacedDigit().weight(.semibold))
                }
                GroupBox {
                    HStack(alignment: .top, spacing: 24) {
                        DeviceImage(device: device)
                            .frame(width: 230, height: 250)
                            .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                        VStack(alignment: .leading, spacing: 14) {
                            Text(device.model.isEmpty ? "Appareil sans nom" : device.model).font(.largeTitle.bold())
                            Text([device.identifier, device.storage, device.color].filter { !$0.isEmpty }.joined(separator: " · "))
                                .foregroundStyle(.secondary)
                            Divider()
                            LabeledContent("Numéro de série", value: device.serial.isEmpty ? "Non renseigné" : maskedSerial(device.serial))
                            LabeledContent("État noté", value: device.condition.isEmpty ? "À renseigner" : device.condition)
                            LabeledContent("Système", value: device.ios.isEmpty ? "Non renseigné" : device.ios)
                            Divider()
                            Toggle("J’ai vérifié la présence physique", isOn: Binding(
                                get: { presentIDs.contains(device.id.uuidString) },
                                set: { set(device.id, included: $0, in: &presentIDsData) }
                            ))
                            Toggle("J’ai vérifié cette fiche et son état", isOn: Binding(
                                get: { checkedIDs.contains(device.id.uuidString) },
                                set: { set(device.id, included: $0, in: &checkedIDsData) }
                            ))
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }.padding(10)
                }
                GroupBox("Accessoires enregistrés") {
                    HStack(spacing: 18) {
                        inventoryAccessory("Boîte", present: device.hasBox)
                        inventoryAccessory("Chargeur", present: device.hasCharger)
                        inventoryAccessory("Facture", present: device.hasInvoice)
                        inventoryAccessory("Autres", present: !device.accessories.isEmpty, detail: device.accessories)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
                }
                HStack {
                    Button("Précédent", systemImage: "chevron.left") { currentIndex = max(0, currentIndex - 1) }
                        .disabled(currentIndex == 0)
                    Spacer()
                    Text("Appareil \(currentIndex + 1) sur \(devices.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    Spacer()
                    Button("Suivant", systemImage: "chevron.right") { currentIndex = min(devices.count - 1, currentIndex + 1) }
                        .disabled(currentIndex >= devices.count - 1)
                }
            }
        }
        .padding(28)
        .frame(minWidth: 760, minHeight: 620)
    }

    private func set(_ id: UUID, included: Bool, in storage: inout String) {
        var ids = Set(storage.split(separator: ",").map(String.init))
        if included { ids.insert(id.uuidString) } else { ids.remove(id.uuidString) }
        storage = ids.sorted().joined(separator: ",")
    }

    private func inventoryAccessory(_ title: String, present: Bool, detail: String = "") -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                if !detail.isEmpty { Text(detail).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
            }
        } icon: {
            Image(systemName: present ? "checkmark.circle.fill" : "minus.circle")
                .foregroundStyle(present ? .green : .secondary)
        }
    }
}

private struct FullScreenCollectionView: View {
    let devices: [AppleDevice]
    let onClose: () -> Void
    @State private var search = ""
    @State private var selectedFamily = "Tous"

    private let families = ["Tous", "iPhone", "iPad", "Mac", "Watch", "AirPods", "Autre"]
    private var filteredDevices: [AppleDevice] {
        devices.filter { device in
            let model = device.model.lowercased()
            let family = model.contains("iphone") ? "iPhone" : model.contains("ipad") ? "iPad" :
                (model.contains("mac") || model.contains("imac")) ? "Mac" : model.contains("watch") ? "Watch" :
                model.contains("airpods") ? "AirPods" : "Autre"
            let matchesSearch = search.isEmpty || "\(device.model) \(device.identifier) \(device.aNumber) \(device.storage) \(device.color) \(device.tags.joined(separator: " "))"
                .localizedCaseInsensitiveContains(search)
            return (selectedFamily == "Tous" || selectedFamily == family) && matchesSearch
        }.sorted { $0.model.localizedStandardCompare($1.model) == .orderedAscending }
    }

    var body: some View {
        VStack(spacing: 18) {
            HStack(spacing: 14) {
                Image("AppleVaultBrand").resizable().scaledToFill().frame(width: 54, height: 54)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                VStack(alignment: .leading, spacing: 3) {
                    Text("AppleVault").font(.largeTitle.bold())
                    Text("Collection · \(filteredDevices.count) appareil(s)").foregroundStyle(.secondary)
                }
                Spacer()
                Picker("Famille", selection: $selectedFamily) {
                    ForEach(families, id: \.self) { Text($0) }
                }.frame(width: 140)
                TextField("Rechercher", text: $search).textFieldStyle(.roundedBorder).frame(width: 220)
                Button("Quitter le plein écran", systemImage: "arrow.down.right.and.arrow.up.left", action: onClose)
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 28).padding(.top, 22)
            if filteredDevices.isEmpty {
                ContentUnavailableView("Aucun appareil trouvé", systemImage: "magnifyingglass", description: Text("Modifie la recherche ou le filtre de famille."))
            } else {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 220, maximum: 330), spacing: 22)], spacing: 22) {
                        ForEach(filteredDevices) { device in
                            VStack(alignment: .leading, spacing: 12) {
                                DeviceImage(device: device).frame(maxWidth: .infinity).frame(height: 210)
                                    .background(.quaternary.opacity(0.38), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(device.model.isEmpty ? "Appareil sans nom" : device.model).font(.title3.bold()).lineLimit(2)
                                    Text([device.storage, device.color, device.condition].filter { !$0.isEmpty }.joined(separator: " · "))
                                        .font(.callout).foregroundStyle(.secondary).lineLimit(1)
                                    if let value = collectionEstimate(for: device) {
                                        Text(formatEuro(value)).font(.headline.monospacedDigit()).foregroundStyle(.tint)
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .padding(16)
                            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
                        }
                    }.padding(28)
                }
            }
            Text("Échap pour quitter l’affichage plein écran").font(.caption2).foregroundStyle(.tertiary).padding(.bottom, 12)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

@MainActor
private final class GalleryWindowController: NSWindowController {
    init(devices: [AppleDevice]) {
        let galleryWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1280, height: 850),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        super.init(window: galleryWindow)
        galleryWindow.title = "AppleVault — Ma collection"
        galleryWindow.contentView = NSHostingView(rootView: FullScreenCollectionView(devices: devices, onClose: { [weak self] in
            self?.window?.performClose(nil)
        }))
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) n’est pas pris en charge") }

    func showGallery() {
        guard let window else { return }
        showWindow(nil)
        window.center()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            if !window.styleMask.contains(.fullScreen) { window.toggleFullScreen(nil) }
        }
    }
}

private enum CSVImportError: LocalizedError {
    case invalidEncoding
    case missingModelColumn
    case noDevices
    var errorDescription: String? {
        switch self {
        case .invalidEncoding: "Impossible de lire le fichier CSV. Enregistre-le en UTF-8 puis réessaie."
        case .missingModelColumn: "La colonne « Modèle » est obligatoire. Utilise un export AppleVault ou ajoute une colonne Modèle."
        case .noDevices: "Aucun appareil avec un modèle n’a été trouvé dans ce fichier."
        }
    }
}

private func parseCollectionCSV(_ data: Data) throws -> [AppleDevice] {
    guard var text = String(data: data, encoding: .utf8) else { throw CSVImportError.invalidEncoding }
    text = text.replacingOccurrences(of: "\u{feff}", with: "")
    guard let firstLine = text.split(whereSeparator: \.isNewline).first else { throw CSVImportError.noDevices }
    func delimiterCount(_ delimiter: Character) -> Int {
        var quoted = false
        var count = 0
        for character in firstLine {
            if character == "\"" { quoted.toggle() }
            else if character == delimiter && !quoted { count += 1 }
        }
        return count
    }
    let separator: Character = {
        let semicolons = delimiterCount(";")
        let commas = delimiterCount(",")
        let tabs = delimiterCount("\t")
        if semicolons >= commas && semicolons >= tabs && semicolons > 0 { return ";" }
        if commas >= tabs && commas > 0 { return "," }
        return "\t"
    }()

    var rows: [[String]] = []
    var row: [String] = []
    var cell = ""
    var quoted = false
    let characters = Array(text)
    var index = 0
    while index < characters.count {
        let character = characters[index]
        if character == "\"" {
            if quoted, index + 1 < characters.count, characters[index + 1] == "\"" {
                cell.append("\""); index += 1
            } else { quoted.toggle() }
        } else if character == separator && !quoted {
            row.append(cell); cell = ""
        } else if (character == "\n" || character == "\r") && !quoted {
            row.append(cell); cell = ""
            if !row.allSatisfy({ $0.trimmingCharacters(in: .whitespaces).isEmpty }) { rows.append(row) }
            row = []
            if character == "\r", index + 1 < characters.count, characters[index + 1] == "\n" { index += 1 }
        } else { cell.append(character) }
        index += 1
    }
    row.append(cell)
    if !row.allSatisfy({ $0.trimmingCharacters(in: .whitespaces).isEmpty }) { rows.append(row) }
    guard let header = rows.first else { throw CSVImportError.noDevices }
    func normalized(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(options: [.diacriticInsensitive, .caseInsensitive], locale: Locale(identifier: "fr_FR"))
            .replacingOccurrences(of: "_", with: " ").lowercased()
    }
    var fieldsByHeader = Dictionary(uniqueKeysWithValues: exportFieldOptions.flatMap { field in
        [(normalized(field.title), field.id), (normalized(field.id), field.id)]
    })
    fieldsByHeader[normalized("name")] = "model"
    fieldsByHeader[normalized("device")] = "model"
    fieldsByHeader[normalized("nom appareil")] = "model"
    fieldsByHeader[normalized("serial number")] = "serial"
    fieldsByHeader[normalized("numero de serie")] = "serial"
    let columns = header.enumerated().compactMap { index, name -> (Int, String)? in
        guard let field = fieldsByHeader[normalized(name)] else { return nil }
        return (index, field)
    }
    let hasModel = columns.contains { $0.1 == "model" } || header.contains { ["nom appareil", "device", "name"].contains(normalized($0)) }
    guard hasModel else { throw CSVImportError.missingModelColumn }
    let mapping = Dictionary(columns.map { ($0.1, $0.0) }, uniquingKeysWith: { first, _ in first })
    func value(_ key: String, in cells: [String]) -> String {
        guard let column = mapping[key], cells.indices.contains(column) else { return "" }
        return cells[column].trimmingCharacters(in: .whitespacesAndNewlines)
    }
    func boolValue(_ value: String) -> Bool {
        ["oui", "yes", "true", "1", "x"].contains(normalized(value))
    }
    let devices = rows.dropFirst().compactMap { cells -> AppleDevice? in
        let model = value("model", in: cells)
        guard !model.isEmpty else { return nil }
        var serial = value("serial", in: cells)
        if serial.contains("•") || serial.contains("*") { serial = "" }
        return AppleDevice(model: model, identifier: value("identifier", in: cells),
            aNumber: value("aNumber", in: cells), partNumber: value("partNumber", in: cells),
            storage: value("storage", in: cells), color: value("color", in: cells), serial: serial,
            ios: value("ios", in: cells), condition: value("condition", in: cells),
            repairsDone: value("repairsDone", in: cells), repairsTodo: value("repairsTodo", in: cells),
            notes: value("notes", in: cells), jailbreak: value("jailbreak", in: cells), shsh: value("shsh", in: cells),
            batteryHealth: value("battery", in: cells).replacingOccurrences(of: "%", with: ""),
            purchaseDate: value("purchaseDate", in: cells), purchasePrice: value("purchasePrice", in: cells),
            estimatedValue: value("estimatedValue", in: cells),
            tags: value("tags", in: cells).split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) },
            accessories: value("accessories", in: cells),
            hasBox: boolValue(value("box", in: cells)), hasCharger: boolValue(value("charger", in: cells)),
            hasInvoice: boolValue(value("invoice", in: cells)))
    }
    guard !devices.isEmpty else { throw CSVImportError.noDevices }
    return devices
}

private struct DeviceDetailView: View {
    let device: AppleDevice
    let hideSerialNumbers: Bool
    let privateNotesRequirePassword: Bool
    let verifyPassword: (String) -> Bool
    let onEdit: () -> Void
    let onToggleFavorite: () -> Void
    let onToggleWarningsIgnored: () -> Void
    let onAddDocument: () -> Void
    @State private var privateNotesUnlocked = false
    @State private var privateNotePassword = ""
    @State private var privateNoteError = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(alignment: .top, spacing: 16) {
                    DeviceImage(device: device)
                        .frame(width: 92, height: 100)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(device.model.isEmpty ? "Appareil sans nom" : device.model)
                            .font(.largeTitle.bold())
                        Text([device.identifier, device.storage, device.color]
                            .filter { !$0.isEmpty }.joined(separator: " · "))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(action: onToggleFavorite) {
                        Label(device.isFavorite ? "Retirer des favoris" : "Ajouter aux favoris",
                              systemImage: device.isFavorite ? "heart.fill" : "heart")
                    }
                    .help(device.isFavorite ? "Retirer des favoris" : "Ajouter aux favoris")
                    Button("Modifier", systemImage: "pencil", action: onEdit)
                    Text(device.condition)
                        .font(.callout.weight(.semibold))
                        .padding(.horizontal, 12).padding(.vertical, 7)
                        .background(.quaternary, in: Capsule())
                }

                GroupBox("Identification") {
                    Grid(alignment: .leading, horizontalSpacing: 40, verticalSpacing: 14) {
                        infoRow("Numéro de modèle", device.aNumber)
                        infoRow("Référence commerciale Apple", device.partNumber)
                        infoRow("Numéro de série", hideSerialNumbers ? maskedSerial(device.serial) : device.serial)
                        infoRow("Version iOS / iPadOS", device.ios)
                        infoRow("Année de sortie", device.releaseYear)
                        infoRow("Stockage", device.storage)
                        infoRow("Couleur", device.color)
                        infoRow("Santé de la batterie", device.batteryHealth.isEmpty ? "—" : "\(device.batteryHealth)%")
                        infoRow("Prochain entretien", device.maintenanceDate?.formatted(date: .abbreviated, time: .omitted) ?? "Aucun rappel")
                        infoRow("Fin de garantie", device.warrantyEndDate?.formatted(date: .abbreviated, time: .omitted) ?? "Non renseignée")
                        infoRow("Date d’achat", device.purchaseDate)
                        infoRow("Prix d’achat", device.purchasePrice.isEmpty ? "" : "\(device.purchasePrice) €")
                        infoRow("Valeur estimée actuelle", collectionEstimate(for: device).map { formatEuro($0) + (device.estimatedValue.isEmpty ? " (automatique)" : " (personnalisée)") } ?? "À estimer")
                        infoRow("Fourchette estimée", valueRange)
                        infoRow("Lieu d’achat", device.purchaseLocation)
                        infoRow("Vendeur", device.seller)
                        infoRow("Coût total connu", totalDeviceCost)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 6)
                }

                GroupBox("Accessoires et boîte") {
                    VStack(alignment: .leading, spacing: 10) {
                        Label(device.hasBox ? "Boîte d’origine incluse" : "Boîte d’origine absente", systemImage: device.hasBox ? "checkmark.circle.fill" : "xmark.circle")
                        Label(device.hasCharger ? "Chargeur inclus" : "Chargeur absent", systemImage: device.hasCharger ? "checkmark.circle.fill" : "xmark.circle")
                        Label(device.hasInvoice ? "Facture disponible" : "Facture non renseignée", systemImage: device.hasInvoice ? "checkmark.circle.fill" : "doc")
                        if !device.accessories.isEmpty { noteRow("Autres accessoires", device.accessories) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 5)
                }

                GroupBox("Avertissements de la fiche") {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(device.warningsIgnored ? "Avertissements ignorés" : "Avertissements actifs").font(.headline)
                            Text(device.warningsIgnored ? "Cette fiche n’apparaît plus dans les listes d’alertes et de fiches à compléter." : "Tu peux masquer les alertes de cette fiche sans supprimer ses informations.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(device.warningsIgnored ? "Réactiver" : "Ignorer", systemImage: device.warningsIgnored ? "arrow.uturn.backward" : "bell.slash", action: onToggleWarningsIgnored)
                    }
                    .padding(.vertical, 5)
                }

                GroupBox("Chronologie de l’appareil") {
                    if device.timeline.isEmpty {
                        Text("Les modifications enregistrées apparaîtront ici.").foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
                    } else {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(device.timeline.sorted { $0.date > $1.date }) { event in
                                HStack(alignment: .top, spacing: 10) {
                                    Image(systemName: "circle.fill").font(.system(size: 8)).foregroundStyle(.tint).padding(.top, 5)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(event.title).font(.callout.weight(.semibold))
                                        Text(event.detail).font(.caption).foregroundStyle(.secondary)
                                        Text(event.date, format: .dateTime.day().month(.abbreviated).year().hour().minute()).font(.caption2).foregroundStyle(.tertiary)
                                    }
                                    Spacer()
                                }
                            }
                        }.padding(.vertical, 5)
                    }
                }

                GroupBox("Étiquettes") {
                    VStack(alignment: .leading) {
                        if device.tags.isEmpty {
                            Text("Aucune étiquette. Ajoute par exemple « rare », « à réparer » ou « à vendre » dans Modifier.")
                                .foregroundStyle(.secondary)
                        } else {
                            HStack(spacing: 8) {
                                ForEach(device.tags, id: \.self) { tag in
                                    Text(tag).font(.callout.weight(.medium))
                                        .padding(.horizontal, 10).padding(.vertical, 5)
                                        .background(.tint.opacity(0.12), in: Capsule())
                                }
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 5)
                }

                GroupBox("Entretien") {
                    VStack(alignment: .leading, spacing: 14) {
                        noteRow("Réparations effectuées", device.repairsDone)
                        Divider()
                        noteRow("À prévoir", device.repairsTodo)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 5)
                }

                GroupBox("Historique des réparations") {
                    if device.repairHistory.isEmpty {
                        Text("Aucune réparation enregistrée pour le moment.")
                            .foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
                    } else {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(device.repairHistory) { repair in
                                HStack(alignment: .top) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(repair.description).font(.headline)
                                        Text(repair.date).font(.caption).foregroundStyle(.secondary)
                                        if !repair.parts.isEmpty { Text("Pièces : \(repair.parts)").font(.caption) }
                                        if !repair.repairer.isEmpty { Text("Réparateur : \(repair.repairer)").font(.caption).foregroundStyle(.secondary) }
                                    }
                                    Spacer()
                                    if !repair.cost.isEmpty { Text("\(repair.cost) €").font(.callout.monospacedDigit()) }
                                }
                                if repair.id != device.repairHistory.last?.id { Divider() }
                            }
                        }.padding(.vertical, 5)
                    }
                }

                GroupBox("Jailbreak et SHSH") {
                    VStack(alignment: .leading, spacing: 14) {
                        noteRow("Jailbreak", device.jailbreak)
                        Divider()
                        noteRow("Blobs SHSH sauvegardés", device.shsh)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 5)
                }

                GroupBox("Notes") {
                    noteRow("Informations", device.notes)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 5)
                }

                GroupBox("Documents associés") {
                    VStack(alignment: .leading, spacing: 10) {
                        if device.documents.isEmpty {
                            Text("Aucun document ajouté. Tu peux joindre une facture, un certificat ou un autre fichier.")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(device.documents) { document in
                                Button {
                                    NSWorkspace.shared.open(URL(fileURLWithPath: document.path))
                                } label: {
                                    Label(document.name, systemImage: "doc.text")
                                }.buttonStyle(.link)
                            }
                        }
                        Button("Ajouter un document…", systemImage: "paperclip", action: onAddDocument)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 5)
                }
                GroupBox("Suivi dans le temps") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Batterie").font(.headline)
                        if device.batteryHistory.isEmpty { Text("Aucun historique de batterie.").foregroundStyle(.secondary) }
                        ForEach(device.batteryHistory.sorted { $0.date > $1.date }) { point in
                            Label("\(point.health)% · \(point.date.formatted(date: .abbreviated, time: .omitted))", systemImage: "battery.75percent")
                        }
                        Divider()
                        Text("Valeur estimée").font(.headline)
                        if device.valueHistory.isEmpty { Text("Aucune évolution de valeur enregistrée.").foregroundStyle(.secondary) }
                        ForEach(device.valueHistory.sorted { $0.date > $1.date }) { point in
                            Label("\(point.value) € · \(point.date.formatted(date: .abbreviated, time: .omitted))", systemImage: "eurosign.circle")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 5)
                }
                if !device.loanedTo.isEmpty {
                    GroupBox("Appareil prêté") {
                        Label("Prêté à \(device.loanedTo)", systemImage: "person.2")
                        if let date = device.loanDueDate { Text("Retour prévu le \(date.formatted(date: .abbreviated, time: .omitted))").foregroundStyle(.secondary) }
                    }
                }
                GroupBox("Notes privées — trousseau macOS") {
                    if privateNotesRequirePassword && !privateNotesUnlocked {
                        SecureField("Mot de passe du profil", text: $privateNotePassword)
                        if !privateNoteError.isEmpty { Text(privateNoteError).foregroundStyle(.red).font(.caption) }
                        Button("Afficher les notes privées", systemImage: "lock.open") {
                            if verifyPassword(privateNotePassword) { privateNotesUnlocked = true; privateNoteError = "" }
                            else { privateNoteError = "Mot de passe incorrect." }
                            privateNotePassword = ""
                        }
                    } else { noteRow("Informations privées", device.privateNotes) }
                }
                GroupBox("Code QR d’inventaire") {
                    HStack {
                        DeviceQRCode(payload: "AppleVault|\(device.id.uuidString)|\(device.model)|\(device.identifier)")
                            .frame(width: 110, height: 110)
                        Text("Code à joindre à une étiquette d’inventaire. Il contient le modèle et l’identifiant, sans numéro de série.")
                            .foregroundStyle(.secondary)
                    }
                }
                Button("Imprimer la fiche…", systemImage: "printer") { printDevice() }
            }
            .padding(28)
            .frame(maxWidth: 850, alignment: .leading)
        }
        .navigationTitle(device.model)
    }

    private func infoRow(_ title: String, _ value: String) -> some View {
        GridRow {
            Text(title).foregroundStyle(.secondary)
            Text(value.isEmpty ? "—" : value).textSelection(.enabled)
        }
    }

    private func noteRow(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.subheadline.weight(.semibold))
            Text(value.isEmpty ? "Aucune information" : value)
                .foregroundStyle(value.isEmpty ? .tertiary : .primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var valueRange: String {
        let low = device.estimatedValueMin.isEmpty ? "?" : "\(device.estimatedValueMin) €"
        let high = device.estimatedValueMax.isEmpty ? "?" : "\(device.estimatedValueMax) €"
        return device.estimatedValueMin.isEmpty && device.estimatedValueMax.isEmpty ? "—" : "\(low) – \(high)"
    }

    private var totalDeviceCost: String {
        let purchase = Double(device.purchasePrice.replacingOccurrences(of: ",", with: ".")) ?? 0
        let repairs = device.repairHistory.compactMap { Double($0.cost.replacingOccurrences(of: ",", with: ".")) }.reduce(0, +)
        return purchase + repairs > 0 ? formatEuro(purchase + repairs) : "—"
    }

    private func printDevice() {
        let view = NSHostingView(rootView: PrintableDeviceSheet(device: device))
        NSPrintOperation(view: view).run()
    }
}

private struct PrintableDeviceSheet: View {
    let device: AppleDevice
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("APPLEVAULT — FICHE APPAREIL").font(.title.bold())
            Text(device.model).font(.largeTitle)
            Text("\(device.identifier) · \(device.aNumber) · \(device.partNumber)")
            Divider()
            Text("Stockage : \(device.storage)    Couleur : \(device.color)    État : \(device.condition)")
            Text("Numéro de série : \(maskedSerial(device.serial))")
            Text("Année : \(device.releaseYear)    Système : \(device.ios)    Batterie : \(device.batteryHealth)%")
            Text("Acheté le \(device.purchaseDate) chez \(device.seller) — \(device.purchasePrice) €")
            Text("Réparations : \(device.repairsDone)")
            Text("À prévoir : \(device.repairsTodo)")
            Text("Notes : \(device.notes)")
            Spacer()
        }.padding(36).frame(width: 595, height: 842, alignment: .topLeading)
    }
}

private struct DeviceQRCode: View {
    let payload: String
    private var image: NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8); filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 6, y: 6)),
              let representation = NSCIImageRep(ciImage: output) as NSImageRep? else { return nil }
        let image = NSImage(size: representation.size); image.addRepresentation(representation); return image
    }
    var body: some View {
        if let image { Image(nsImage: image).interpolation(.none).resizable().scaledToFit() }
        else { Image(systemName: "qrcode").resizable().scaledToFit().foregroundStyle(.secondary) }
    }
}

private struct DeviceImage: View {
    let device: AppleDevice
    var body: some View {
        Group {
            if !device.photoPath.isEmpty, let image = NSImage(contentsOfFile: device.photoPath) {
                Image(nsImage: image).resizable().scaledToFit()
            } else if !device.appleImageURL.isEmpty, let url = URL(string: device.appleImageURL) {
                AppleArtwork(url: url, fallback: AnyView(fallback))
            } else { fallback }
        }
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
    private var fallback: some View {
        Image(systemName: device.model.localizedCaseInsensitiveContains("ipad") ? "ipad" : "iphone.gen3")
            .font(.system(size: 42)).foregroundStyle(.tint)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct AppleArtwork: View {
    let url: URL
    let fallback: AnyView
    @State private var image: NSImage?

    var body: some View {
        Group {
            if let image {
                Image(nsImage: image).resizable().scaledToFit()
            } else {
                fallback
            }
        }
        .task(id: url) {
            do {
                var request = URLRequest(url: url, cachePolicy: .returnCacheDataElseLoad, timeoutInterval: 20)
                request.setValue("Mozilla/5.0 AppleVault", forHTTPHeaderField: "User-Agent")
                let (data, response) = try await URLSession.shared.data(for: request)
                guard (response as? HTTPURLResponse)?.statusCode == 200,
                      let downloaded = NSImage(data: data) else { return }
                image = downloaded
            } catch {
                image = nil
            }
        }
    }
}

struct AddDeviceView: View {
    @Environment(\.dismiss) private var dismiss
    let profileID: UUID?
    let knownDevices: [AppleDevice]
    let onSave: (AppleDevice) -> Void

    @State private var model = ""
    @State private var identifier = ""
    @State private var aNumber = ""
    @State private var partNumber = ""
    @State private var referenceSearch = ""
    @State private var referenceLookupMessage = ""
    @State private var storage = ""
    @State private var color = ""
    @State private var serial = ""
    @State private var ios = ""
    @State private var condition = "Bon état"
    @State private var repairsDone = ""
    @State private var repairsTodo = ""
    @State private var notes = ""
    @State private var jailbreak = ""
    @State private var shsh = ""
    @State private var batteryHealth = ""
    @State private var purchaseDate = ""
    @State private var purchasePrice = ""
    @State private var releaseYear = ""
    @State private var purchaseLocation = ""
    @State private var seller = ""
    @State private var estimatedValueMin = ""
    @State private var estimatedValueMax = ""
    @State private var photoPath = ""
    @State private var appleImageURL = ""
    @State private var catalogSelection = ""
    @State private var estimatedValue = ""
    @State private var tagsText = ""
    @State private var hasMaintenanceReminder = false
    @State private var maintenanceDate = Date.now
    @State private var hasWarrantyReminder = false
    @State private var warrantyEndDate = Date.now
    @State private var accessories = ""
    @State private var hasBox = false
    @State private var hasCharger = false
    @State private var hasInvoice = false
    @State private var loanedTo = ""
    @State private var hasLoanDueDate = false
    @State private var loanDueDate = Date.now

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Nouvel appareil").font(.title2.bold())
                Spacer()
                Button("Annuler") { dismiss() }
                Button("Enregistrer") {
                    onSave(AppleDevice(model: model, identifier: identifier, aNumber: aNumber, partNumber: partNumber,
                        storage: storage, color: color, serial: serial, ios: ios,
                        condition: condition, repairsDone: repairsDone, repairsTodo: repairsTodo,
                        notes: notes, jailbreak: jailbreak, shsh: shsh,
                        batteryHealth: batteryHealth, purchaseDate: purchaseDate,
                        purchasePrice: purchasePrice, photoPath: photoPath,
                        appleImageURL: appleImageURL, estimatedValue: estimatedValue,
                        tags: parseTags(tagsText),
                        maintenanceDate: hasMaintenanceReminder ? maintenanceDate : nil,
                        warrantyEndDate: hasWarrantyReminder ? warrantyEndDate : nil,
                        accessories: accessories, hasBox: hasBox, hasCharger: hasCharger, hasInvoice: hasInvoice,
                        timeline: [.init(title: "Appareil ajouté", detail: "Fiche créée dans AppleVault")],
                        releaseYear: releaseYear, purchaseLocation: purchaseLocation, seller: seller,
                        estimatedValueMin: estimatedValueMin, estimatedValueMax: estimatedValueMax,
                        batteryHistory: batteryHealth.isEmpty ? [] : [BatterySnapshot(health: batteryHealth)],
                        loanedTo: loanedTo, loanDueDate: hasLoanDueDate ? loanDueDate : nil))
                    dismiss()
                }
                .disabled(model.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .keyboardShortcut(.defaultAction)
            }
            .padding()
            Divider()
            Form {
                Section("Identification") {
                    HStack {
                        TextField("Saisir un numéro A ou une référence Apple", text: $referenceSearch)
                        Button("Rechercher", systemImage: "magnifyingglass") { lookupReference() }
                            .disabled(referenceSearch.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    if !referenceLookupMessage.isEmpty { Text(referenceLookupMessage).font(.caption).foregroundStyle(.secondary) }
                    Picker("Choisir dans le catalogue Apple", selection: $catalogSelection) {
                        Text("Choisir un appareil…").tag("")
                        ForEach(AppleCatalogItem.all) { item in Text(item.model).tag(item.model) }
                    }
                    if let item = AppleCatalogItem.all.first(where: { $0.model == catalogSelection }) {
                        HStack(spacing: 12) {
                            DeviceImage(device: AppleDevice(model: item.model, identifier: "", aNumber: "", storage: "", color: "", serial: "", ios: "", condition: "", repairsDone: "", repairsTodo: "", notes: "", appleImageURL: item.imageURL ?? ""))
                                .frame(width: 60, height: 74)
                            VStack(alignment: .leading) {
                                Text(item.model).font(.headline)
                                Link("Fiche technique Apple", destination: URL(string: item.productPage)!)
                                    .font(.caption)
                            }
                        }
                    }
                    TextField("Modèle (iPhone 5s…)", text: $model)
                    TextField("Identifiant (iPhone6,1…)", text: $identifier)
                    TextField("Numéro de modèle (Axxxx)", text: $aNumber)
                    TextField("Référence commerciale Apple (ex. M21HFZU/A)", text: $partNumber)
                    TextField("Stockage (32 Go…)", text: $storage)
                    TextField("Couleur", text: $color)
                    TextField("Numéro de série", text: $serial)
                    TextField("Version iOS / iPadOS", text: $ios)
                    TextField("Année de sortie", text: $releaseYear)
                    Picker("État", selection: $condition) {
                        ForEach(["Comme neuf", "Bon état", "Usé", "Abîmé", "Pour pièces"], id: \.self) {
                            Text($0)
                        }
                    }
                }
                Section("Réparations") {
                    TextField("Réparations effectuées", text: $repairsDone, axis: .vertical)
                    TextField("Réparations à prévoir", text: $repairsTodo, axis: .vertical)
                }
                Section("Rappel d’entretien") {
                    Toggle("Programmer une date d’entretien", isOn: $hasMaintenanceReminder)
                    if hasMaintenanceReminder {
                        DatePicker("Date", selection: $maintenanceDate, displayedComponents: .date)
                    }
                }
                Section("Garantie") {
                    Toggle("Suivre la date de fin de garantie", isOn: $hasWarrantyReminder)
                    if hasWarrantyReminder { DatePicker("Fin de garantie", selection: $warrantyEndDate, displayedComponents: .date) }
                }
                Section("Accessoires et boîte") {
                    TextField("Autres accessoires (câble, écouteurs…)", text: $accessories, axis: .vertical)
                    Toggle("Boîte d’origine incluse", isOn: $hasBox)
                    Toggle("Chargeur inclus", isOn: $hasCharger)
                    Toggle("Facture disponible", isOn: $hasInvoice)
                }
                Section("Batterie et achat") {
                    TextField("Santé de la batterie (%)", text: $batteryHealth)
                    TextField("Date d’achat (ex. 17/10/2024)", text: $purchaseDate)
                    TextField("Prix d’achat (€)", text: $purchasePrice)
                    TextField("Lieu d’achat", text: $purchaseLocation)
                    TextField("Vendeur", text: $seller)
                    TextField("Valeur personnalisée (€, facultatif)", text: $estimatedValue, prompt: Text(automaticEstimate(for: AppleDevice(model: model, identifier: identifier, aNumber: aNumber, storage: storage, color: color, serial: serial, ios: ios, condition: condition, repairsDone: repairsDone, repairsTodo: repairsTodo, notes: notes, batteryHealth: batteryHealth)).map { "Auto : \(Int($0)) €" } ?? "Calculée automatiquement si possible"))
                    HStack {
                        TextField("Valeur minimum (€)", text: $estimatedValueMin)
                        TextField("Valeur maximum (€)", text: $estimatedValueMax)
                    }
                }
                Section("Prêt de l’appareil") {
                    TextField("Prêté à (laisser vide si non prêté)", text: $loanedTo)
                    Toggle("Date de retour prévue", isOn: $hasLoanDueDate)
                    if hasLoanDueDate { DatePicker("Retour prévu", selection: $loanDueDate, displayedComponents: .date) }
                }
                Section("Jailbreak et SHSH") {
                    TextField("Jailbreak (outil, statut…)", text: $jailbreak, axis: .vertical)
                    TextField("Blobs SHSH sauvegardés (versions, fichiers…)", text: $shsh, axis: .vertical)
                }
                Section("Notes") {
                    TextField("Informations supplémentaires", text: $notes, axis: .vertical)
                }
                Section("Étiquettes") {
                    TextField("Séparées par des virgules (rare, à réparer…)", text: $tagsText)
                }
                Section("Photo personnelle") { PhotoPickerField(photoPath: $photoPath, profileID: profileID) }
            }
            .formStyle(.grouped)
        }
        .frame(minWidth: 540, minHeight: 680)
        .onChange(of: catalogSelection) { _, selected in
            guard let item = AppleCatalogItem.all.first(where: { $0.model == selected }) else { return }
            model = item.model
            appleImageURL = item.imageURL ?? ""
            if let aNumber = item.aNumber { self.aNumber = aNumber }
        }
    }

    private func lookupReference() {
        let query = referenceSearch.trimmingCharacters(in: .whitespacesAndNewlines)
        if let device = knownDevices.first(where: { $0.aNumber.localizedCaseInsensitiveContains(query) || $0.partNumber.caseInsensitiveCompare(query) == .orderedSame }) {
            model = device.model; identifier = device.identifier; aNumber = device.aNumber; partNumber = device.partNumber
            storage = device.storage; color = device.color; appleImageURL = device.appleImageURL
            referenceLookupMessage = "Fiche correspondante trouvée dans cette collection."
        } else if let item = AppleCatalogItem.all.first(where: { $0.aNumber?.localizedCaseInsensitiveContains(query) == true }) {
            model = item.model; aNumber = item.aNumber ?? ""; appleImageURL = item.imageURL ?? ""
            catalogSelection = item.model
            referenceLookupMessage = "Modèle trouvé dans le catalogue Apple local. Complète les autres détails de l’appareil."
        } else {
            referenceLookupMessage = "Aucune correspondance locale. Tu peux saisir le numéro dans les champs de la fiche."
        }
    }
}

private struct EditDeviceView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var device: AppleDevice
    private let initialDevice: AppleDevice
    @State private var repairParts = ""
    @State private var repairer = ""
    @State private var repairDescription = ""
    @State private var repairCost = ""
    @State private var repairDate = Date.now.formatted(date: .numeric, time: .omitted)
    @State private var tagsText: String
    @State private var hasMaintenanceReminder: Bool
    @State private var maintenanceDate: Date
    @State private var hasWarrantyReminder: Bool
    @State private var warrantyEndDate: Date
    @State private var hasLoanDueDate: Bool
    @State private var loanDueDate: Date
    let profileID: UUID?
    let hideSerialNumbers: Bool
    let onSave: (AppleDevice) -> Void

    init(device: AppleDevice, profileID: UUID?, hideSerialNumbers: Bool = false, onSave: @escaping (AppleDevice) -> Void) {
        self.profileID = profileID
        self.hideSerialNumbers = hideSerialNumbers
        self.onSave = onSave
        initialDevice = device
        _device = State(initialValue: device)
        _tagsText = State(initialValue: device.tags.joined(separator: ", "))
        _hasMaintenanceReminder = State(initialValue: device.maintenanceDate != nil)
        _maintenanceDate = State(initialValue: device.maintenanceDate ?? .now)
        _hasWarrantyReminder = State(initialValue: device.warrantyEndDate != nil)
        _warrantyEndDate = State(initialValue: device.warrantyEndDate ?? .now)
        _hasLoanDueDate = State(initialValue: device.loanDueDate != nil)
        _loanDueDate = State(initialValue: device.loanDueDate ?? .now)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Modifier la fiche").font(.title2.bold())
                Spacer()
                Button("Annuler") { dismiss() }
                Button("Enregistrer") {
                    device.maintenanceDate = hasMaintenanceReminder ? maintenanceDate : nil
                    device.warrantyEndDate = hasWarrantyReminder ? warrantyEndDate : nil
                    device.loanDueDate = hasLoanDueDate ? loanDueDate : nil
                    if device.batteryHealth != initialDevice.batteryHealth, !device.batteryHealth.isEmpty {
                        device.batteryHistory.append(BatterySnapshot(health: device.batteryHealth))
                    }
                    if device.estimatedValue != initialDevice.estimatedValue, !device.estimatedValue.isEmpty {
                        device.valueHistory.append(DeviceValueSnapshot(value: device.estimatedValue))
                    }
                    PrivateNoteVault.store(device.privateNotes, for: device.id)
                    onSave(device)
                    dismiss()
                }.keyboardShortcut(.defaultAction)
            }.padding()
            Divider()
            Form {
                Section("Identification") {
                    TextField("Modèle", text: $device.model)
                    TextField("Identifiant", text: $device.identifier)
                    TextField("Numéro de modèle (Axxxx)", text: $device.aNumber)
                    TextField("Référence commerciale Apple (ex. M21HFZU/A)", text: $device.partNumber)
                    TextField("Stockage", text: $device.storage)
                    TextField("Couleur", text: $device.color)
                    if hideSerialNumbers {
                        SecureField("Numéro de série (masqué)", text: $device.serial)
                    } else {
                        TextField("Numéro de série", text: $device.serial)
                    }
                    TextField("Version iOS / iPadOS", text: $device.ios)
                    TextField("Année de sortie", text: $device.releaseYear)
                    Picker("État", selection: $device.condition) {
                        ForEach(["Comme neuf", "Bon état", "Usé", "Abîmé", "Pour pièces"], id: \.self) { Text($0) }
                    }
                    TextField("Santé batterie (%)", text: $device.batteryHealth)
                }
                Section("Réparations") {
                    TextField("Réparations effectuées", text: $device.repairsDone, axis: .vertical)
                    TextField("À prévoir", text: $device.repairsTodo, axis: .vertical)
                    if !device.repairHistory.isEmpty {
                        ForEach(device.repairHistory) { repair in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(repair.description)
                                    Text([repair.date, repair.cost.isEmpty ? "" : "\(repair.cost) €"].filter { !$0.isEmpty }.joined(separator: " · "))
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Supprimer", systemImage: "trash", role: .destructive) {
                                    device.repairHistory.removeAll { $0.id == repair.id }
                                }.labelStyle(.iconOnly)
                            }
                        }
                    }
                    TextField("Date de l’intervention", text: $repairDate)
                    TextField("Description de l’intervention", text: $repairDescription)
                    TextField("Pièces utilisées", text: $repairParts)
                    TextField("Réparateur", text: $repairer)
                    TextField("Coût (€), facultatif", text: $repairCost)
                    Button("Ajouter à l’historique", systemImage: "plus.circle") {
                        let description = repairDescription.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !description.isEmpty else { return }
                        device.repairHistory.append(RepairEntry(date: repairDate, description: description, cost: repairCost, parts: repairParts, repairer: repairer))
                        repairDescription = ""; repairParts = ""; repairer = ""; repairCost = ""
                    }.disabled(repairDescription.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                Section("Rappel d’entretien") {
                    Toggle("Programmer une date d’entretien", isOn: $hasMaintenanceReminder)
                    if hasMaintenanceReminder {
                        DatePicker("Date", selection: $maintenanceDate, displayedComponents: .date)
                    }
                }
                Section("Garantie") {
                    Toggle("Suivre la date de fin de garantie", isOn: $hasWarrantyReminder)
                    if hasWarrantyReminder { DatePicker("Fin de garantie", selection: $warrantyEndDate, displayedComponents: .date) }
                }
                Section("Accessoires et boîte") {
                    TextField("Autres accessoires (câble, écouteurs…)", text: $device.accessories, axis: .vertical)
                    Toggle("Boîte d’origine incluse", isOn: $device.hasBox)
                    Toggle("Chargeur inclus", isOn: $device.hasCharger)
                    Toggle("Facture disponible", isOn: $device.hasInvoice)
                }
                Section("Jailbreak et SHSH") {
                    TextField("Jailbreak", text: $device.jailbreak, axis: .vertical)
                    TextField("Blobs SHSH", text: $device.shsh, axis: .vertical)
                }
                Section("Achat et notes") {
                    TextField("Date d’achat", text: $device.purchaseDate)
                    TextField("Lieu d’achat", text: $device.purchaseLocation)
                    TextField("Vendeur", text: $device.seller)
                    TextField("Prix d’achat (€)", text: $device.purchasePrice)
                    TextField("Valeur personnalisée (€, facultatif)", text: $device.estimatedValue, prompt: Text("Laisser vide pour l’estimation automatique"))
                    TextField("Estimation basse (€)", text: $device.estimatedValueMin)
                    TextField("Estimation haute (€)", text: $device.estimatedValueMax)
                    TextField("Notes", text: $device.notes, axis: .vertical)
                    TextField("Notes privées (stockées dans le trousseau macOS)", text: $device.privateNotes, axis: .vertical)
                }
                Section("Prêt de l’appareil") {
                    TextField("Prêté à (laisser vide si non prêté)", text: $device.loanedTo)
                    Toggle("Date de retour prévue", isOn: $hasLoanDueDate)
                    if hasLoanDueDate { DatePicker("Retour prévu", selection: $loanDueDate, displayedComponents: .date) }
                }
                Section("Étiquettes") {
                    TextField("Séparées par des virgules (rare, à réparer…)", text: $tagsText)
                }
                Section("Photo personnelle") { PhotoPickerField(photoPath: $device.photoPath, profileID: profileID) }
            }.formStyle(.grouped)
        }
        .onAppear { device.tags = parseTags(tagsText) }
        .onChange(of: tagsText) { _, newValue in device.tags = parseTags(newValue) }
        .frame(minWidth: 540, minHeight: 700)
    }
}

private struct PhotoPickerField: View {
    @Binding var photoPath: String
    var profileID: UUID? = nil
    @State private var selection: PhotosPickerItem?

    var body: some View {
        HStack(spacing: 14) {
            if !photoPath.isEmpty, let image = NSImage(contentsOfFile: photoPath) {
                Image(nsImage: image).resizable().scaledToFit().frame(width: 60, height: 60)
            }
            PhotosPicker(selection: $selection, matching: .images) {
                Label(photoPath.isEmpty ? "Choisir une photo…" : "Changer la photo…", systemImage: "photo")
            }
            if !photoPath.isEmpty { Button("Retirer") { photoPath = ""; selection = nil } }
        }
        .onChange(of: selection) { _, item in
            Task {
                guard let data = try? await item?.loadTransferable(type: Data.self) else { return }
                var directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                    .appendingPathComponent("AppleVault/Photos", isDirectory: true)
                if let profileID {
                    directory.appendPathComponent(profileID.uuidString, isDirectory: true)
                }
                try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let file = directory.appendingPathComponent(UUID().uuidString + ".img")
                do { try data.write(to: file, options: .atomic); photoPath = file.path } catch { }
            }
        }
    }
}

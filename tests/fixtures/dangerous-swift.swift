// Dangerous Swift file for testing Vibe Coding Guard
// This file contains intentional security anti-patterns covering OWASP Mobile Top 10

import Foundation
import UIKit
import LocalAuthentication
import CommonCrypto

// M1: Improper Credential Usage — hardcoded secret
let apiKey = "sk-proj-abc123def456ghi789jklmnop"
let password = "SuperSecretPassword123!"

class InsecureApp {

    // M9: Insecure Data Storage — secrets in UserDefaults
    func saveCredentials(token: String) {
        UserDefaults.standard.set(token, forKey: "authToken")
        UserDefaults.standard.set("mypassword", forKey: "password")
    }

    // M4: SQL injection via string interpolation
    func queryUser(userId: String) {
        let query = "SELECT * FROM users WHERE id = '\(userId)'"
        db.execute(query)
    }

    // M5: Insecure Communication — HTTP URL
    func fetchData() {
        let url = URL(string: "http://api.myapp.com/data")!
        let task = URLSession.shared.dataTask(with: url)
        task.resume()
    }

    // M5: Disabled ATS
    // NSAllowsArbitraryLoads = true

    // M10: Weak crypto — MD5
    func hashPassword(password: String) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5(password, CC_LONG(password.count), &digest)
        return Data(digest)
    }

    // M10: CryptoKit insecure hash
    func insecureHash(data: Data) {
        let hash = Insecure.MD5.hash(data: data)
        print("Hash: \(hash)")
    }

    // M10: Hardcoded encryption key
    let encryptionKey = "0123456789abcdef0123456789abcdef"

    // M6: Sensitive data in logs
    func logSensitiveData(token: String) {
        NSLog("Auth token: %@", token)
        print("User password is \(password)")
    }

    // M3: Biometric without server validation
    func authenticateUser() {
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Login") { success, error in
            if success {
                self.grantAccess()
            }
        }
    }

    // M4: WebView with dynamic HTML
    func showContent(html: String) {
        let webView = WKWebView()
        webView.loadHTMLString(html, baseURL: nil)
        webView.evaluateJavaScript("document.title") { result, error in }
    }

    // M4: UIWebView (deprecated)
    func oldWebView() {
        let webView = UIWebView()
    }

    // M8: Insecure file permissions
    func writeFile(data: Data) {
        let attrs: [FileAttributeKey: Any] = [.posixPermissions: 0o777]
        FileManager.default.createFile(atPath: "/tmp/data.txt", contents: data, attributes: attrs)
    }

    // M9: Keychain with insecure accessibility
    func storeInKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecValueData as String: "secret".data(using: .utf8)!
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    // M10: ECB mode
    func encryptData() {
        let options = kCCOptionECBMode
    }

    // Insecure deserialization
    func loadArchive(data: Data) {
        let obj = NSKeyedUnarchiver.unarchiveObject(with: data)
    }

    // Deprecated security API
    func oldConnection() {
        let conn = NSURLConnection()
    }

    // Command injection
    func runCommand(input: String) {
        let task = Process()
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", "echo \(input)"]
    }

    // Deep link without validation
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        handleDeepLink(url)
        return true
    }

    // isSecureTextEntry disabled
    func setupTextField() {
        let field = UITextField()
        field.isSecureTextEntry = false
    }

    func grantAccess() {}
    func handleDeepLink(_ url: URL) {}
}

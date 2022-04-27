///
/// Copyright (c) 2016 Dropbox, Inc. All rights reserved.
///

#if os(iOS)

import Foundation
import AuthenticationServices
import SafariServices
import UIKit
import WebKit

extension DropboxClientsManager {
    /// Starts a "token" flow.
    ///
    /// This method should no longer be used.
    /// Long-lived access tokens are deprecated. See https://dropbox.tech/developers/migrating-app-permissions-and-access-tokens.
    /// Please use `authorizeFromControllerV2` instead.
    ///
    /// - Parameters:
    ///     - sharedApplication: The shared UIApplication instance in your app.
    ///     - controller: A UIViewController to present the auth flow from. Reference is weakly held.
    ///     - openURL: Handler to open a URL.
    @available(*, deprecated, message: "This method was used for long-lived access tokens, which are now deprecated. Please use `authorizeFromControllerV2` instead.")
    public static func authorizeFromController(_ sharedApplication: UIApplication,
                                               controller: UIViewController?,
                                               openURL: @escaping ((URL) -> Void), completion: @escaping DropboxOAuthCompletion) {
        precondition(DropboxOAuthManager.sharedOAuthManager != nil, "Call `DropboxClientsManager.setupWithAppKey` or `DropboxClientsManager.setupWithTeamAppKey` before calling this method")
        let sharedMobileApplication = MobileSharedApplication(sharedApplication: sharedApplication, controller: controller, openURL: openURL, completion: completion)
        MobileSharedApplication.sharedMobileApplication = sharedMobileApplication
        DropboxOAuthManager.sharedOAuthManager.authorizeFromSharedApplication(sharedMobileApplication)
    }

    /// Starts the OAuth 2 Authorization Code Flow with PKCE.
    ///
    /// PKCE allows "authorization code" flow without "client_secret"
    /// It enables "native application", which is ensafe to hardcode client_secret in code, to use "authorization code".
    /// PKCE is more secure than "token" flow. If authorization code is compromised during
    /// transmission, it can't be used to exchange for access token without random generated
    /// code_verifier, which is stored inside this SDK.
    ///
    /// - Parameters:
    ///     - sharedApplication: The shared UIApplication instance in your app.
    ///     - controller: A UIViewController to present the auth flow from. Reference is weakly held.
    ///     - loadingStatusDelegate: An optional delegate to handle loading experience during auth flow.
    ///       e.g. Show a loading spinner and block user interaction while loading/waiting.
    ///       If a delegate is not provided, the SDK will show a default loading spinner when necessary.
    ///     - openURL: Handler to open a URL.
    ///     - scopeRequest: Contains requested scopes to obtain.
    /// - NOTE:
    ///     If auth completes successfully, A short-lived Access Token and a long-lived Refresh Token will be granted.
    ///     API calls with expired Access Token will fail with AuthError. An expired Access Token must be refreshed
    ///     in order to continue to access Dropbox APIs.
    ///
    ///     API clients set up by `DropboxClientsManager` will get token refresh logic for free.
    ///     If you need to set up `DropboxClient`/`DropboxTeamClient` without `DropboxClientsManager`,
    ///     you will have to set up the clients with an appropriate `AccessTokenProvider`.
    public static func authorizeFromControllerV2(_ sharedApplication: UIApplication,
                                                 controller: UIViewController?,
                                                 loadingStatusDelegate: LoadingStatusDelegate?,
                                                 openURL: @escaping ((URL) -> Void), completion: @escaping DropboxOAuthCompletion,
                                                 scopeRequest: ScopeRequest?
    ) {
        precondition(DropboxOAuthManager.sharedOAuthManager != nil, "Call `DropboxClientsManager.setupWithAppKey` or `DropboxClientsManager.setupWithTeamAppKey` before calling this method")
        let sharedMobileApplication = MobileSharedApplication(sharedApplication: sharedApplication, controller: controller, openURL: openURL, completion: completion)
        sharedMobileApplication.loadingStatusDelegate = loadingStatusDelegate
        MobileSharedApplication.sharedMobileApplication = sharedMobileApplication
        DropboxOAuthManager.sharedOAuthManager.authorizeFromSharedApplication(sharedMobileApplication, usePKCE: true, scopeRequest: scopeRequest)
    }

    public static func setupWithAppKey(_ appKey: String, transportClient: DropboxTransportClient? = nil) {
        setupWithOAuthManager(appKey, oAuthManager: DropboxMobileOAuthManager(appKey: appKey), transportClient: transportClient)
    }

    public static func setupWithAppKeyMultiUser(_ appKey: String, transportClient: DropboxTransportClient? = nil, tokenUid: String?) {
        setupWithOAuthManagerMultiUser(appKey, oAuthManager: DropboxMobileOAuthManager(appKey: appKey), transportClient: transportClient, tokenUid: tokenUid)
    }

    public static func setupWithTeamAppKey(_ appKey: String, transportClient: DropboxTransportClient? = nil) {
        setupWithOAuthManagerTeam(appKey, oAuthManager: DropboxMobileOAuthManager(appKey: appKey), transportClient: transportClient)
    }

    public static func setupWithTeamAppKeyMultiUser(_ appKey: String, transportClient: DropboxTransportClient? = nil, tokenUid: String?) {
        setupWithOAuthManagerMultiUserTeam(appKey, oAuthManager: DropboxMobileOAuthManager(appKey: appKey), transportClient: transportClient, tokenUid: tokenUid)
    }
}

open class DropboxMobileOAuthManager: DropboxOAuthManager {
    let dauthRedirectURL: URL
    
    public override init(appKey: String, host: String) {
        self.dauthRedirectURL = URL(string: "db-\(appKey)://1/connect")!
        super.init(appKey: appKey, host:host)
        self.urls.append(self.dauthRedirectURL)
    }

    internal override func extractFromUrl(_ url: URL, completion: @escaping DropboxOAuthCompletion) {
        if let host = url.host, host == dauthRedirectURL.host { // dauth
            extractfromDAuthURL(url, completion: completion)
        } else {
            extractFromRedirectURL(url, completion: completion)
        }
    }
    
    internal override func checkAndPresentPlatformSpecificAuth(_ sharedApplication: SharedApplication) -> Bool {
        if !self.hasApplicationQueriesSchemes() {
            let message = "DropboxSDK: unable to link; app isn't registered to query for URL schemes dbapi-2 and dbapi-8-emm. Add a dbapi-2 entry and a dbapi-8-emm entry to LSApplicationQueriesSchemes"
            let title = "SwiftyDropbox Error"
            sharedApplication.presentErrorMessage(message, title: title)
            return true
        }
        
        if let scheme = dAuthScheme(sharedApplication) {
            let url: URL
            if let authSession = authSession {
                // Code flow
                url = dAuthURL(scheme, authSession: authSession)
            } else {
                // Token flow
                let nonce = UUID().uuidString
                UserDefaults.standard.set(nonce, forKey: kDBLinkNonce)
                url = dAuthURL(scheme, nonce: nonce)
            }
            sharedApplication.presentExternalApp(url)
            return true
        }
        return false
    }
    
    open override func handleRedirectURL(_ url: URL, completion: @escaping DropboxOAuthCompletion) -> Bool {
        super.handleRedirectURL(url, completion: {
            if let sharedMobileApplication = MobileSharedApplication.sharedMobileApplication {
                sharedMobileApplication.dismissAuthController()
            }
            completion($0)
        })
    }

    fileprivate func dAuthURL(_ scheme: String, nonce: String?) -> URL {
        var components = dauthUrlCommonComponents(with: scheme)
        if let n = nonce {
            let state = "oauth2:\(n)"
            components.queryItems?.append(URLQueryItem(name: OAuthConstants.stateKey, value: state))
        }
        guard let url = components.url else { fatalError("Failed to create dauth url.") }
        return url
    }

    private func dAuthURL(_ scheme: String, authSession: OAuthPKCESession) -> URL {
        var components = dauthUrlCommonComponents(with: scheme)
        let extraQueryParams = Self.createExtraQueryParamsString(for: authSession)
        components.queryItems?.append(contentsOf: [
            URLQueryItem(name: OAuthConstants.stateKey, value: authSession.state),
            URLQueryItem(name: OAuthConstants.extraQueryParamsKey, value: extraQueryParams),
        ])
        guard let url = components.url else { fatalError("Failed to create dauth url.") }
        return url
    }

    private func dauthUrlCommonComponents(with scheme: String) -> URLComponents {
        var components = URLComponents()
        components.scheme = scheme
        components.host = "1"
        components.path = "/connect"
        components.queryItems = [
            URLQueryItem(name: "k", value: appKey),
            URLQueryItem(name: "s", value: ""),
        ]
        return components
    }
    
    fileprivate func dAuthScheme(_ sharedApplication: SharedApplication) -> String? {
        if sharedApplication.canPresentExternalApp(dAuthURL("dbapi-2", nonce: nil)) {
            return "dbapi-2"
        } else if sharedApplication.canPresentExternalApp(dAuthURL("dbapi-8-emm", nonce: nil)) {
            return "dbapi-8-emm"
        } else {
            return nil
        }
    }
    
    func extractfromDAuthURL(_ url: URL, completion: @escaping DropboxOAuthCompletion) {
        switch url.path {
        case "/connect":
            if let authSession = authSession {
                handleCodeFlowUrl(url, authSession: authSession, completion: completion)
            } else {
                completion(extractFromTokenFlowUrl(url))
            }
        default:
            completion(.error(.accessDenied, "User cancelled Dropbox link"))
        }
    }

    /// Handles code flow response URL from DBApp.
    /// Auth results are passed back in URL query parameters.
    /// Expect results look like below:
    /// 1. DBApp that can handle dauth code flow properly
    /// ```
    /// [
    ///     "state": "<state_string>",
    ///     "oauth_code": "<oauth_code>"
    /// ]
    /// ```
    /// 2. Legacy DBApp that calls legacy dauth api, oauth_token should be "oauth2code:" and the code is stored under
    /// "oauth_token_secret" key.
    /// ```
    /// [
    ///     "state": "<state_string>",
    ///     "oauth_token": "oauth2code:",
    ///     "oauth_token_secret": "<oauth_code>"
    /// ]
    /// ```
    private func handleCodeFlowUrl(
        _ url: URL, authSession: OAuthPKCESession, completion: @escaping DropboxOAuthCompletion
    ) {
        let parametersMap = OAuthUtils.extractDAuthResponseFromUrl(url)

        let state = parametersMap[OAuthConstants.stateKey]
        guard state == authSession.state else {
            completion(.error(.unknown, "Unable to verify link request"))
            return
        }

        let authCode: String?
        if let code = parametersMap[OAuthConstants.oauthCodeKey] {
            authCode = code
        } else if parametersMap[OAuthConstants.oauthTokenKey] == "oauth2code:",
            let code = parametersMap[OAuthConstants.oauthSecretKey] {
            authCode = code
        } else {
            authCode = nil
        }
        if let authCode = authCode {
            finishPkceOAuth(
                authCode: authCode, codeVerifier: authSession.pkceData.codeVerifier, completion: completion
            )
        } else {
            completion(.error(.unknown, "Unable to verify link request"))
        }
    }

    /// Handles token flow response URL from DBApp.
    /// Auth results are passed back in URL query parameters.
    /// Expect results look like below:
    /// ```
    /// [
    ///     "state": "oauth2:<nonce>",
    ///     "oauth_token_secret": "<oauth2_access_token>",
    ///     "uid": "<uid>"
    /// ]
    /// ```
    private func extractFromTokenFlowUrl(_ url: URL) -> DropboxOAuthResult {
        let parametersMap = OAuthUtils.extractDAuthResponseFromUrl(url)
        let state = parametersMap[OAuthConstants.stateKey]
        if let nonce = UserDefaults.standard.object(forKey: kDBLinkNonce) as? String, state == "oauth2:\(nonce)",
            let accessToken = parametersMap[OAuthConstants.oauthSecretKey],
            let uid = parametersMap[OAuthConstants.uidKey] {
            return .success(DropboxAccessToken(accessToken: accessToken, uid: uid))
        } else {
            return .error(.unknown, "Unable to verify link request")
        }
    }
    
    fileprivate func hasApplicationQueriesSchemes() -> Bool {
        let queriesSchemes = Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String] ?? []
        
        var foundApi2 = false
        var foundApi8Emm = false
        for scheme in queriesSchemes {
            if scheme == "dbapi-2" {
                foundApi2 = true
            } else if scheme == "dbapi-8-emm" {
                foundApi8Emm = true
            }
            if foundApi2 && foundApi8Emm {
                return true
            }
        }
        return false
    }

    /// Creates a string that contains all code flow query parameters.
    private static func createExtraQueryParamsString(for authSession: OAuthPKCESession) -> String {
        let pkceData = authSession.pkceData
        var extraQueryParams = "\(OAuthConstants.codeChallengeKey)=\(pkceData.codeChallenge)"
            + "&\(OAuthConstants.codeChallengeMethodKey)=\(pkceData.codeChallengeMethod)"
            + "&\(OAuthConstants.tokenAccessTypeKey)=\(authSession.tokenAccessType)"
            + "&\(OAuthConstants.responseTypeKey)=\(authSession.responseType)"
        if let scopeRequest = authSession.scopeRequest {
            if let scopeString = scopeRequest.scopeString {
                extraQueryParams += "&\(OAuthConstants.scopeKey)=\(scopeString)"
            }
            if scopeRequest.includeGrantedScopes {
                extraQueryParams += "&\(OAuthConstants.includeGrantedScopesKey)=\(scopeRequest.scopeType.rawValue)"
            }
        }
        return extraQueryParams
    }
}

open class MobileSharedApplication: SharedApplication {
    public static var sharedMobileApplication: MobileSharedApplication?

    let sharedApplication: UIApplication
    weak var controller: UIViewController?
    let openURL: ((URL) -> Void)
    let completion: DropboxOAuthCompletion
    
    weak var loadingStatusDelegate: LoadingStatusDelegate?
    
    // Authentication sessions need to be retained, and prevents showing two sessions/VCs at the same time
    private var sessionOrViewController: AnyObject?

    public init(sharedApplication: UIApplication, controller: UIViewController?, openURL: @escaping ((URL) -> Void), completion: @escaping DropboxOAuthCompletion) {
        // fields saved for app-extension safety
        self.sharedApplication = sharedApplication
        self.controller = controller
        self.openURL = openURL
        self.completion = completion
    }

    open func presentErrorMessage(_ message: String, title: String) {
        let alertController = UIAlertController(
            title: title,
            message: message,
            preferredStyle: UIAlertController.Style.alert)
        if let controller = controller {
            controller.present(alertController, animated: true, completion: { fatalError(message) })
        }
    }

    open func presentErrorMessageWithHandlers(_ message: String, title: String, buttonHandlers: Dictionary<String, () -> Void>) {
        let alertController = UIAlertController(
            title: title,
            message: message,
            preferredStyle: UIAlertController.Style.alert)

        alertController.addAction(UIAlertAction(title: "Cancel", style: .cancel) { (_) in
            if let handler = buttonHandlers["Cancel"] {
                handler()
            }
        })

        alertController.addAction(UIAlertAction(title: "Retry", style: .default) { (_) in
            if let handler = buttonHandlers["Retry"] {
                handler()
            }
        })

        if let controller = controller {
            controller.present(alertController, animated: true, completion: {})
        }
    }

    open func presentPlatformSpecificAuth(_ authURL: URL) -> Bool {
        presentExternalApp(authURL)
        return true
    }

    open func presentAuthChannel(_ authURL: URL, tryIntercept: @escaping ((URL) -> Bool), cancelHandler: @escaping (() -> Void)) {
        guard self.sessionOrViewController == nil else {
            return
        }
        guard let controller = self.controller else {
            return
        }
        
        // ASWebAuthenticationSession and SFAuthenticationSession don't work with guided access (rdar://40809553)
        if !UIAccessibility.isGuidedAccessEnabled {
            // Sessions don't use openURL for communication like MobileSafariViewController, they just need to be retained
            if #available(iOS 12.0, *) {
                let session = MobileWebAuthenticationSession(url: authURL, presentingVC: controller) { [weak self] callbackUrl in
                    self?.sessionOrViewController = nil
                    if let url = callbackUrl {
                        DropboxClientsManager.handleRedirectURL(url) { [weak self] result in
                            self?.completion(result)
                        }
                    } else {
                        // cancelHandler is only for URL redirect flow
                        self?.completion(.cancel)
                    }
                }
                self.sessionOrViewController = session
                session.start()
                return
            }
        }
        
        let safariVC = MobileSafariViewController(url: authURL, cancelHandler: cancelHandler, dismissHandler: { [weak self] svc, didCancel in
            self?.sessionOrViewController = nil
            
            if didCancel {
                cancelHandler()
            } else {
                svc.dismiss(animated: true, completion: nil)
            }
        })
        self.sessionOrViewController = safariVC
        controller.present(safariVC, animated: true, completion: nil)
    }

    open func presentExternalApp(_ url: URL) {
        self.openURL(url)
        
        // Handed over control to safari. End flow with unknown login result
        self.completion(nil)
    }

    open func canPresentExternalApp(_ url: URL) -> Bool {
        return self.sharedApplication.canOpenURL(url)
    }

    open func dismissAuthController() {
        // Only MobileSafariViewController needs to be manually dismissed
        if let presentedViewController = self.sessionOrViewController as? MobileSafariViewController, !presentedViewController.isBeingDismissed {
            self.sessionOrViewController = nil
            presentedViewController.dismiss(animated: true, completion: nil)
        }
    }

    public func presentLoading() {
        if isWebOAuthFlow {
            presentLoadingInWeb()
        } else {
            presentLoadingInApp()
        }
    }

    public func dismissLoading() {
        if isWebOAuthFlow {
            dismissLoadingInWeb()
        } else {
            dismissLoadingInApp()
        }
    }

    private var isWebOAuthFlow: Bool {
        return controller?.presentedViewController is MobileSafariViewController
    }

    /// Web OAuth flow, present the spinner over the MobileSafariViewController.
    private func presentLoadingInWeb() {
        let safariViewController = controller?.presentedViewController as? MobileSafariViewController
        let loadingVC = LoadingViewController(nibName: nil, bundle: nil)
        loadingVC.modalPresentationStyle = .overFullScreen
        safariViewController?.present(loadingVC, animated: false)
    }

    // Web OAuth flow, dismiss loading view on the MobileSafariViewController.
    private func dismissLoadingInWeb() {
        let safariViewController = controller?.presentedViewController as? MobileSafariViewController
        let loadingView = safariViewController?.presentedViewController as? LoadingViewController
        loadingView?.dismiss(animated: false)
    }

    /// Delegate to app to present loading if delegate is set.
    /// Otherwise, present the spinner in the view controller.
    private func presentLoadingInApp() {
        if let loadingStatusDelegate = loadingStatusDelegate {
            loadingStatusDelegate.showLoading()
        } else {
            let loadingVC = LoadingViewController(nibName: nil, bundle: nil)
            loadingVC.modalPresentationStyle = .overFullScreen
            controller?.present(loadingVC, animated: false)
        }
    }

    /// Delegate to app to dismiss loading if delegate is set.
    /// Otherwise, dismiss the spinner in the view controller.
    private func dismissLoadingInApp() {
        if let loadingStatusDelegate = loadingStatusDelegate {
            loadingStatusDelegate.dismissLoading()
        } else if let loadingView = controller?.presentedViewController as? LoadingViewController {
            loadingView.dismiss(animated: false)
        }
    }
}

@available(iOS 12.0, *)
fileprivate class MobileWebAuthenticationSession: ASWebAuthenticationSession {
    
    weak var presentingWindow: UIWindow?
    
    public init(url: URL, presentingVC: UIViewController, completion: @escaping ((URL?) -> Void)) {
        // Assume the the custom URL scheme is registered in the app's Info.plist
        super.init(url: url, callbackURLScheme: nil) { callbackURL, error in
            completion(callbackURL)
        }
        
        if #available(iOS 13.0, *) {
            self.presentingWindow = presentingVC.viewIfLoaded?.window
            self.presentationContextProvider = self
        }
    }
    
}

@available(iOS 13.0, *)
extension MobileWebAuthenticationSession: ASWebAuthenticationPresentationContextProviding {
    
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return self.presentingWindow ?? UIApplication.shared.windows.first { $0.isKeyWindow }!
    }
    
}

open class MobileSafariViewController: SFSafariViewController, SFSafariViewControllerDelegate {
    var cancelHandler: (() -> Void) = {}
    var dismissHandler: ((MobileSafariViewController, Bool) -> Void)

    public init(url: URL, cancelHandler: @escaping (() -> Void), dismissHandler: @escaping ((MobileSafariViewController, Bool) -> Void)) {
        self.dismissHandler = dismissHandler
        if #available(iOS 11.0, *) {
            let configuration = SFSafariViewController.Configuration()
            configuration.entersReaderIfAvailable = false
            super.init(url: url, configuration: configuration)
        } else {
            super.init(url: url, entersReaderIfAvailable: false)
        }

        self.cancelHandler = cancelHandler
        self.delegate = self;
    }

    public func safariViewController(_ controller: SFSafariViewController, didCompleteInitialLoad didLoadSuccessfully: Bool) {
        if (!didLoadSuccessfully) {
            self.dismissHandler(self, false)
        }
    }

    public func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        self.dismissHandler(self, true)
    }
    
}

#endif

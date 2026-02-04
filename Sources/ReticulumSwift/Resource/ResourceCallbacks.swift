//
//  ResourceCallbacks.swift
//  ReticulumSwift
//
//  Protocol for resource transfer callbacks.
//  Notifies application of resource lifecycle events.
//
//  Matches Python RNS Link.py resource callback pattern.
//

import Foundation

// MARK: - ResourceCallbacks

/// Protocol for receiving resource transfer notifications.
///
/// ResourceCallbacks provides hooks into the resource transfer lifecycle:
/// - resourceAdvertised: Called when a resource is advertised, return true to accept
/// - resourceStarted: Called when resource transfer begins
/// - resourceConcluded: Called when resource transfer completes
///
/// All methods have default implementations so only override what you need.
///
/// Example usage:
/// ```swift
/// class MyResourceHandler: ResourceCallbacks {
///     func resourceAdvertised(_ resource: Resource) async -> Bool {
///         // Check if we want this resource
///         let size = await resource.transferSize
///         return size < 10_000_000 // Only accept resources < 10MB
///     }
///
///     func resourceStarted(_ resource: Resource) async {
///         print("Transfer started")
///     }
///
///     func resourceConcluded(_ resource: Resource) async {
///         print("Transfer complete")
///     }
/// }
/// ```
public protocol ResourceCallbacks: AnyObject, Sendable {
    /// Called when a resource is advertised.
    ///
    /// This is your opportunity to inspect the resource metadata and decide
    /// whether to accept the transfer. Return true to accept, false to reject.
    ///
    /// Only called when link resource strategy is .acceptApp.
    ///
    /// - Parameter resource: The advertised resource
    /// - Returns: true to accept the resource, false to reject
    func resourceAdvertised(_ resource: Resource) async -> Bool

    /// Called when a resource transfer starts.
    ///
    /// Called after accepting a resource and beginning the transfer.
    ///
    /// - Parameter resource: The resource that started transferring
    func resourceStarted(_ resource: Resource) async

    /// Called when a resource transfer concludes.
    ///
    /// Called when the transfer completes successfully or fails.
    ///
    /// - Parameter resource: The resource that concluded
    func resourceConcluded(_ resource: Resource) async
}

// MARK: - Default Implementations

extension ResourceCallbacks {
    /// Default implementation accepts all advertised resources.
    public func resourceAdvertised(_ resource: Resource) async -> Bool {
        return true
    }

    /// Default implementation does nothing on resource start.
    public func resourceStarted(_ resource: Resource) async {
        // No-op
    }

    /// Default implementation does nothing on resource conclusion.
    public func resourceConcluded(_ resource: Resource) async {
        // No-op
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ResourceStrategy.swift
//  ReticulumSwift
//
//  Resource acceptance strategy for link resource handling.
//  Determines how a link handles incoming resource advertisements.
//
//  Matches Python RNS Link.py resource acceptance strategy.
//

import Foundation

// MARK: - ResourceStrategy

/// Strategy for accepting incoming resources on a link.
///
/// ResourceStrategy controls how a link handles incoming resource advertisements:
/// - acceptNone: Reject all incoming resources
/// - acceptApp: Accept only if callback returns true
/// - acceptAll: Accept all incoming resources
///
/// Example usage:
/// ```swift
/// await link.setResourceStrategy(.acceptApp)
/// await link.setResourceCallbacks(myCallbackHandler)
/// // Now resources will be accepted based on callback decision
/// ```
public enum ResourceStrategy: Sendable {
    /// Reject all incoming resources
    case acceptNone

    /// Accept only if callback returns true
    case acceptApp

    /// Accept all incoming resources
    case acceptAll
}

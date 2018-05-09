//
//  main.swift
//  KeychainFinder
//
//  Created by Joel Rennich on 11/23/17.
//  Copyright © 2017 Joel Rennich. All rights reserved.
//

import Foundation
import Security

// An application to query for keychain items and determine attributes

var searchReturn: AnyObject? = nil
var myErr = OSStatus()
var internetPassword = false
var searchTerm = false
var everything = false
var rawOutput = false

var account = ""
var service = ""
var label = ""

let dateFormatter = DateFormatter()
dateFormatter.dateStyle = .medium
dateFormatter.timeStyle = .short

func printHelp() {
    print("""
Info:
    A quick utlity to determine what exact attributes a keychain item has.
    Search for an item using Account Name, Service Name or Label. If you want to search for all items use -e or -everything to return all items.

    By default only Generic Passwords will be searched for. Use "-i" to search for Internet Passwords.
    
    To get the raw results for the keychain item use "-r".

Useage:
    keychainfinder [-i] [-r] [ -everything || -e ] [-account || -a <account name>] [-service || -s <service name>] [-label || -l <label>]
""")
    exit(0)
}

if CommandLine.arguments.count == 1 {
    
    // nothing specified, so print help
    
    printHelp()
}

// get arguments

for arg in 0...(CommandLine.arguments.count - 1) {
    
    switch CommandLine.arguments[arg] {
    case "-i" :
        internetPassword = true
    case "-r" :
        rawOutput = true
    case "-account", "-a" :
        if arg <= (CommandLine.arguments.count - 1) {
            account = CommandLine.arguments[arg + 1]
            searchTerm = true
        } else {
            print("Invalid argument")
            exit(0)
        }
    case "-service", "-s" :
        if arg <= (CommandLine.arguments.count - 1) {
            service = CommandLine.arguments[arg + 1]
            searchTerm = true
        } else {
            print("Invalid argument")
            exit(0)
        }
    case "-everything", "-e" :
        searchTerm = true
    case "-label", "-l" :
        if arg <= (CommandLine.arguments.count - 1) {
            label = CommandLine.arguments[arg + 1]
            searchTerm = true
        } else {
            print("Invalid argument")
            exit(0)
        }
    case "-help", "-h" :
        printHelp()
    default:
        break
    }
}

if !searchTerm {
    // nothing to search for
    
    print("No search terms specified.")
    exit(0)
}

// Build the search dictionary

var searchTerms : [ String : AnyObject ] = [
    kSecReturnAttributes as String: true as AnyObject,          // return attributes for things we find
    kSecReturnRef as String : true as AnyObject,                // return the SecKeychain reference
    kSecMatchLimit as String : kSecMatchLimitAll as AnyObject   // return all matches
]

// add in search terms

if internetPassword {
    searchTerms[kSecClass as String] = kSecClassInternetPassword as AnyObject
} else {
    searchTerms[kSecClass as String] = kSecClassGenericPassword as AnyObject
}

if account != "" {
    searchTerms[kSecAttrAccount as String] = account as AnyObject
}

if service != "" {
    searchTerms[kSecAttrService as String] = service as AnyObject
}

if label != "" {
    searchTerms[kSecAttrLabel as String] = label as AnyObject
}

// Now search for the items

myErr = SecItemCopyMatching(searchTerms as CFDictionary, &searchReturn)

if myErr != 0 {
    print("Error while searching, try different terms.")
    exit(0)
}

let items = searchReturn as! CFArray as Array

if items.count < 1 {
    print("No items found.")
    exit(0)
} else {
    print("Total of \(items.count) items found:")
    print("")
}

// now to iterate through whatever items came out

var counter = 1

for item in items {
    
    // lots of nil coalescing here to not print "Optional(...)" things
    
    let itemAccount = (item["acct"] ?? "None")
    let itemService = (item["svce"] ?? "None")
    let itemLabel = (item["labl"] ?? "None")
    let itemRef = (item["v_Ref"] ?? "None")
    let itemPort = (item["port"] ?? "None")
    let itemProtocol = (item["ptcl"] ?? "None")
    let itemServer = (item["srvr"] ?? "None")
    
    print("Item: \(counter)")
    print("   Account: \(itemAccount ?? "None")")
    print("   Service: \(itemService ?? "None")")
    print("     Label: \(itemLabel ?? "None")")
    
    // Internet password things
    
    if !(((item["class"] as? String) ?? "")  == "genp") {
        print("      Port: \(itemPort ?? "None")")
        print("  Protocol: \(itemProtocol ?? "None")")
        print("    Server: \(itemServer ?? "None")")
    }
    
    print("   Created: \(dateFormatter.string(from: item["cdat"] as! Date))")
    print("  Modified: \(dateFormatter.string(from: item["mdat"] as! Date))")
    print(" Reference: \(itemRef ?? "None")")
    
    if ((item["class"] as? String) ?? "")  == "genp" {
        print("     Class: Generic Password")
    } else {
        print("     Class: Internet Password")
    }
    
    if rawOutput {
        print("")
        print("  Raw keychain item:")
        
        let itemDict = item as! [String: AnyObject]
        itemDict.forEach({print("     \($0.key):  \($0.value)")})
    }
    
    print("")
    
    counter += 1
}


#  Keychain Finder

A quick utlity to determine what exact attributes a keychain item has.
Search for an item using Account Name, Service Name or Label. If you want to search for all items use -e or -everything to return all items.

By default only Generic Passwords will be searched for. Use "-i" to search for Internet Passwords.

To get the raw results for the keychain item use "-r".

**Synopsis:**
`keychainfinder [-i] [-r] [ -everything || -e ] [-account || -a <account name>] [-service || -s <service name>] [-label || -l <label>]`

**Options:**

-i          return internet passwords
-e          return every keychain item
-a     name
            search based upon account name of the item
-s      service
            search based on service name of the item
-l      label
            search based on label of the item
-r          return the raw keychain item with every entry


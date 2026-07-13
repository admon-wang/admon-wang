# Automated Access Control: Building a Network Security Tool

## Project description

I work as a security analyst, and one of my regular jobs is keeping our network safe by managing who gets to access sensitive company data. We maintain a file called an "allow list"—it's basically a list of IP addresses (computer locations) that are allowed to connect to our restricted systems. The problem is that when employees leave, contractors finish their projects, or security incidents happen, we need to remove certain IP addresses from that list. Instead of doing this manually every single time, I created a Python script that automates this entire process. The script reads the allow list file, finds the IP addresses that shouldn't have access anymore, removes them automatically, and then updates the file. This saves time, reduces human error, and keeps our network security up to date.

---

## Open the file that contains the allow list

When working with files in Python, it's important to handle them carefully. I used the `with` statement along with the `open()` function to safely open the allow list file. Think of `with` like a safety guard—it makes sure the file gets properly closed when we're done, even if something goes wrong. The `"r"` parameter tells Python to open the file in "read" mode, so we can look at what's inside.

```python
import_file = "allow_list.txt"
with open(import_file, "r") as file:
```

This code sets up the file opening process. We give the file a nickname (`import_file`) so we can use it throughout our script, and then we tell Python, "Please open this file safely and call it `file` while we're working with it."

---

## Read the file contents

Once the file is open, I needed to actually pull the text out of it. I used the `.read()` method, which is like a vacuum cleaner—it sucks up everything inside the file and stores it in a variable I named `ip_addresses`. Now all that file data is sitting in my script, ready for me to work with it.

```python
with open(import_file, "r") as file:
    ip_addresses = file.read()
```

At this point, `ip_addresses` contains all the text from the file as one long string. If the file had ten IP addresses, they'd all be smooshed together as one piece of text. This is fine for reading, but to remove specific addresses, I need to break them apart first.

---

## Convert the string into a list

The `.split()` method is like taking that one long string and cutting it at every space. Instead of having one huge chunk of text, I now have a nice, organized list where each IP address is its own item. This makes it much easier to find and remove specific addresses.

```python
ip_addresses = ip_addresses.split()
```

Now `ip_addresses` has changed from a single string into a list. If it had "192.168.1.1 192.168.1.2 192.168.1.3", it's now a list with three separate items: `["192.168.1.1", "192.168.1.2", "192.168.1.3"]`. Perfect for the next step!

---

## Iterate through the remove list

I set up a `for` loop to go through the allow list one IP address at a time. For each address, I check whether it matches any of the IP addresses that should be removed (my `remove_list`). It's like going through a stack of security badges and checking each one against a list of employees who should no longer have access.

```python
for element in ip_addresses:
```

This loop says, "Take each IP address from `ip_addresses`, call it `element`, and do something with it." On the first pass, `element` is the first IP. On the second pass, it's the second IP. And so on, until we've checked every single one.

---

## Remove IP addresses that are on the remove list

Once I'm checking each IP, I use an `if` statement to ask: "Is this IP in my remove list?" If the answer is yes, I use the `.remove()` method to delete it from the allow list. The `.remove()` method works perfectly here because there are no duplicate IP addresses in the allow list—each address appears only once, so removing it is safe and clean.

```python
for element in ip_addresses:
    if element in remove_list:
        ip_addresses.remove(element)
```

This code is the heart of the security automation. For every IP in our allow list, we check if it's on the removal list. If it is, we delete it. If it's not, we leave it alone and move to the next one.

---

## Update the file with the revised list of IP addresses

After I've removed all the unauthorized IPs, I need to put the updated list back into the file. First, I use the `.join()` method to stitch the list back together into one string, with spaces between each IP address. Then I use `with open()` again, but this time with `"w"` (write mode), which lets me replace the old file contents with this new, cleaned-up version.

```python
ip_addresses = " ".join(ip_addresses)
with open(import_file, "w") as file:
    file.write(ip_addresses)
```

The `.join()` method takes our list of IPs and stitches them back into a single string with spaces between them. Then `.write()` replaces everything in the file with this new, secure version. The old unauthorized IPs are gone for good, and the file now only contains the IPs that should have access.

---

## Summary

This Python script automates one of the most important security tasks in our organization. The workflow is straightforward: open the allow list file, read all the IP addresses into our script, convert that text into a list so we can work with individual addresses, loop through every IP and check it against our removal list, delete any addresses that shouldn't have access, and finally overwrite the file with the updated, secure version. By automating this process, we eliminate manual errors, save time, and make sure our network access controls stay current. This kind of automation is exactly what modern cybersecurity is about—making security faster, more reliable, and less dependent on humans doing repetitive tasks by hand. Every time this script runs, it's like a security checkpoint that keeps our restricted systems safe.

---

*Project Completed: 2026-07-11*

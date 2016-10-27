
  _____   _                          ___     _      _  _     _              __ _
 |_   _| | |_      ___      o O O   | __|   | |    | || |   (_)    _ _     / _` |
   | |   | ' \    / -_)    o        | _|    | |     \_, |   | |   | ' \    \__, |
  _|_|_  |_||_|   \___|   TS__[O]  _|_|_   _|_|_   _|__/   _|_|_  |_||_|   |___/
_|"""""|_|"""""|_|"""""| {======|_| """ |_|"""""|_| """"|_|"""""|_|"""""|_|"""""|
"`-0-0-'"`-0-0-'"`-0-0-'./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'
           ___      _
   o O O  / __|    (_)      _ _    __     _  _     ___
  o      | (__     | |     | '_|  / _|   | +| |   (_-<
 TS__[O]  \___|   _|_|_   _|_|_   \__|_   \_,_|   /__/_
 {======|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|
./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

And now for something completely different...

A Mountain Lion rootkit for Phrack #69!

Copyright (c) fG!, 2012, 2013 - reverser@put.as - http://reverse.put.as
All rights reserved.

This is the sample code to Revisiting Mac OS X Kernel Rootkits paper.
Most of the techniques described are implemented here. A few in a simplistic
way to show how it can be done, others more complete and mature.

It is not an offensive, ready to use, and commercial grade rootkit (although 
probably better than most there are out there), and probably with some insecure
code and not robust enough (requires further error checking). Targets only
Mountain Lion 64 bits kernel. Hey, it's free! These things are expensive ;-).

Tested with Mountain Lion 10.8.2 and 10.8.3, should work with previous versions.
The described techniques also apply to (all?) previous OS X versions.

Its main goal is to show how two simple ideas can be helpful to build a powerful
rootkit. This should help to improve the defensive and detection tools. If not,
well, pay attention to what you execute and reinstall your machine from time
to time ;-).

Check configuration.h to activate the different features.

The source code includes diStorm 3, which is GPL3, while my code is public 
domain. I asked for a special favor to keep this inconsistency, but keep it in
mind if you plan to do anything with this code. Although me and diStorm's author
agree that malicious rootkit writers certainly don't care about licenses.
Many thanks to Gil Dabah for this and his awesome work with diStorm.

Feel free to send me any bug fixes, vulnerabilities, ideas, etc.

UPDATE:
So this took longer to release than expected and this code feels a bit old.
For example it still depends on proc structures definitions which are always
changing between OS X versions. An updated version of this rootkit finds all
the required offsets making it compatible with all OS X versions without any
particular dependency.
Most (if not all) of the described techniques still work with Mavericks with minor
adaptations.
An updated version with more features will be released with the book.

Enjoy & have fun,
fG!
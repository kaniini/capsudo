# capsudo

sudo, but [object-capability style][ocap]!

   [ocap]: https://en.wikipedia.org/wiki/Object-capability_model

## Build & install

```
# make
# make install PREFIX=/wherever
```

By default it will install to `/usr`.

## Using it from the command-line

Run `capsudod -S socket-path-here` to create a socket and listen on it.
This socket acts as an *object capability*: anyone who can access the socket
can make use of it.

Run `capsudo -S socket-path-here [arguments]` to *invoke* the object capability you created.
The capsudo daemon will accept a connection, stitch everything together and run the program
bound to the object capability.

## Some quick command-line examples

Allowing anyone in `%wheel` to run any program you want (classical sudo/doas setup on Alpine):

```
# mkdir -p /run/cap
# capsudod -S /run/cap/sudo-capability &
# chgrp wheel /run/cap/sudo-capability
# chmod 770 /run/cap/sudo-capability
$ capsudo -S /run/cap/sudo-capability
```

Allowing someone to reboot the machine:

```
# capsudod -S /home/user/reboot-capability reboot &
# chown user:user /home/user/reboot-capability && chmod 700 /home/user/reboot-capability
$ capsudo -S /home/user/reboot-capability
```

## Other examples

Consult the [capsudod manual page] for more examples.

   [capsudod manual page]: man/capsudod.8

My blog [rethinking sudo with object capabilities][rethink-sudo] also has some good examples of
capability delegation.

   [rethink-sudo]: https://ariadne.space/2025/12/12/rethinking-sudo-with-object-capabilities.html

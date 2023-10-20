# Auth server

Minecraft server which allows clients of any Minecraft version to join,
and will immediately be kicked with a 6-digit token.

This token can be verified by sending a http request to `/token/<token>`,
which returns the Minecraft uuid and username.


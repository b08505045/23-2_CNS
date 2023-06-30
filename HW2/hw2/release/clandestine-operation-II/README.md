# Clandestine Operation II

- This challenge requires you to communicate with a NTLMv2 authentication and NTLM2 session security control panel.
- Except for the error message, the authentication procedures follow the [specification](https://curl.se/rfc/ntlm.html), e.g. you have to send type 1 message if you want to login.
- To successfully communicate with the control panel after login, you have to send the correct signature after each command you just sent. Note that sealing is not required, i.e. you don't need to implement procedures implied by 'Negotiate Seal' flag.
- To authenticate using NTLMv2 rather than NTLM, please add 'Negotiate NTLM2 Key' in your header.

Hint1: Please refer to template.py, there are some template functions and tools you might want to use.\
Hint2: You are recommended to read "What is NTLM?", "NTLM Terminology", "The NTLM Message Header Layout", "The Type 1 Message", "The Type 2 Message" and "The Type 3 Message" sections of the specification first. You can refer to Appendix C for some implementation examples.
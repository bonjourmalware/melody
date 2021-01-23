Welcome to the ~**Melodoc**~.

Melody is an internet sensor built for threat intelligence. This tool have multiple use cases :

+ Build historic data to extract trends and patterns 
+ Keep an eye on specific threats
+ Monitor emerging threats exploitation
+ Index malicious activity by detecting exploitation attempts and targeted scanners
+ Log every contact your application receives from the internet to find potentially malicious activity

Deploying it can be as easy as pulling the latest compiled binary or the official Docker image. 

Add your favorite rules, some configuration tweaks, a BPF to clean the noise a bit and then forget it[^1] and let the internet symphony flow to you.

You can tweak the options either with a file or directly by passing options trough the CLI, allowing Melody to act as a standalone application.

Melody will also handle log rotation for you. It has been designed to be able to run forever on the smallest VPS while handling millions of packets a day.

[^1]: You should either setup an automated patching process or come back often to apply security patches on the host though

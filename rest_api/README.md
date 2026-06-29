This is just some bullshit, don't worry 

1) First to ensure all dependencies are installed, run install.sh, which 
is an interactive program for creating environment variable and all things related. 

2) If there are some errors, find a knife and destroy your computer's screen with it (Be careful with broken glass) 

3) When all dependencies are configured, check inside /etc/vhsmd. Configuration files should be there. 

4) copy vhsm.service to /etc/systemd/system (You need to change this shit, verify all path) 

5) start the service, and test the API, Now MinIO, the Go API and the Signature works fine at the same time 

6) And lastly, go ask your mom if have permission to do the step 2
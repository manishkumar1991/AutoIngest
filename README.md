# Attack Use Case Simulator
 ## Prerequisites:
 Kindly make sure that you have an app registered in Microsoft Entra ID
 1. How to register an app, Open the Microsoft Entra ID and click on app Registration
    ![image](https://github.com/user-attachments/assets/eb40c4be-bcf6-42e7-9a50-df856cf4fd0f)

 3. Click on Register and then Go to Certificates and secrets and generate a client secrets. Make a note of client secret value
 4. Go to overview page and make a note of Application (client) ID and Directory (Tenant) ID.
Once you have the app registered then make sure that you have the provide the proper permission to app on resource group where the log analytics workspace is residing where you want the data to be ingested.
 1. How to assign role and permissions, open the resource group and click on Access control IAM
    ![image](https://github.com/user-attachments/assets/7f74b58c-f535-4ea4-9048-bc630d719edb)

 3. Click on Add role assignment , Assign three permissions (one by one)
    a. Log Analytics contributor
    b. Monitoring metric publisher
    c. Monitoring contributor
 4. Then on next page click on select members and provide your app name, and then Review and assign it.

 ## How to use:
 

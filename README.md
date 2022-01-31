Config Manager Agent
====================


Config Manager Agent is a EII service responsible for below:
- Puts the EII services configs to EII config manager data store
- Additionally in PROD mode, generates
  - Required config manager data store keys/certificates to interact with 
  EII config manager data store like etcd and puts in the volume mounts to be shared with
  other EII services
  - Required messagebus keys for EII services communication
- Creates required provisioning folders with the right permissions needed for other 
  EII services via volume mounts

The diagram below shows a high level flow of `ConfigMgrAgent` service .

```mermaid
%% name: EII Provisioning

sequenceDiagram
    participant User
    participant EdgeNode
    participant EIIService
    Participant ConfigMgrAgent
    participant ETCD

    User->>EdgeNode: Start container (docker-compose up)
    EIIService->>EIIService: Wait for ETCD certificates
    ConfigMgrAgent->>ConfigMgrAgent: Generate x509 certificates for ETCD
    ConfigMgrAgent->>ETCD: Start ETCD
    ConfigMgrAgent->>ETCD: Register services to be able to connect
    ConfigMgrAgent->>ETCD: Load default configuration
    ConfigMgrAgent->>ETCD: Generate and load ZeroMQ Keys
    ConfigMgrAgent->>EIIService: Copy ETCD certificates to the shared volume
    Note right of ConfigMgrAgent: Each service has its own certs volume
    EIIService->>ETCD: Connect to ETCD with certificate to get configuration
```

>**Note:** 
> Any EII service `waits/restarts` if the config manager data store client key
and certificates are yet to be made available for the container.

 **Optional:** For capturing the data back from Etcd to a JSON file, run the etcd_capture.sh script. This can be achieved using the following command:

```
$ docker exec -it ia_configmgr_agent ./scripts/etcd_capture.sh
```

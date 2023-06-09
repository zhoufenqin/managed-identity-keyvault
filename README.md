# Access Key Vault with Managed Identity

This sample shows how to access Key Vault with Managed Identity in `Azure Spring Cloud`.

## Prerequisite

* [JDK 8](https://docs.microsoft.com/en-us/azure/java/jdk/java-jdk-install)
* [Maven 3.0 and above](http://maven.apache.org/install.html)
* [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest) or [Azure Cloud Shell](https://docs.microsoft.com/en-us/azure/cloud-shell/overview)

## How to run 

1. Run `mvn clean package`.
2. Install Azure CLI extension for Azure Spring Cloud by running below command.
    ```
    az extension add -y --source https://azureclitemp.blob.core.windows.net/spring-cloud/spring_cloud-0.1.0-py2.py3-none-any.whl
    ```
3. Create an instance of Azure Spring Cloud.
    ```
    az spring-cloud create -n <resource name> -g <resource group name>
    ```
4. Create an app with public domain assigned.
    ```
    az spring-cloud app create -n <app name> -s <resource name> -g <resource group name> --is-public true 
    ```
5. Enable system assigned Managed Identity.
   ```
   az spring-cloud app identity assign -n <app name> -s <resource name> -g <resource group name>
   ```
6. Grant permission of Key Vault to the system-assigned Managed Identity
    ```
    az keyvault set-policy -n keyvault_name -g resource_group_of_keyvault --secret-permissions {backup, delete, get, list, purge, recover, restore, set} --object-id <principal-id-you-got-in-step5>
    ```
7. Deploy app with jar
    ```
    az spring-cloud app deploy -n <app name> -s <resource name> -g <resource group name> --jar-path ./target/asc-managed-identity-keyvault-sample-0.1.0.jar
    ```
8.  Verify app is running. Instances should have status `RUNNING` and discoveryStatus `UP`. 
    ```
    az spring-cloud app show -n <app name> -s <resource name> -g <resource group name>
    ```
9. Verify sample is working. The url is fetched from previous step.
    ```
    # Create a secret in Key Vault
    curl -X PUT {url}/secret/{secret-name}?value={value}

    # Get the value of secret-name 
    curl {url}/secret/{secret-name}
    # return the secret value you just created before
    ```
   

- ASA-E az command:
```shell
az spring app deploy -n test1 --source-path . --build-cpu 4 --build-memory 8Gi --builder native --build-env BP_NATIVE_IMAGE=true BP_JVM_VERSION=17 BP_NATIVE_IMAGE_BUILD_ARGUMENTS="--no-fallback --trace-object-instantiation=ch.qos.logback.classic.Logger --initialize-at-run-time=io.netty -H:+AddAllCharsets -H:ReflectionConfigurationFiles=/workspace/META-INF/native-image/reflect-config.json -H:IncludeResources=.*/.*properties$"
```
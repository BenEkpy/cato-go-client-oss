<a id="readme-top"></a>

# OSS Cato Go Client

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li>
        <a href="#usage">Usage</a>
      <ul>
        <li><a href="#example">Example</a></li>
        <li><a href="#supported-methods">Supported Methods</a></li>
      </ul>
    </li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

The OSS Cato Go Client is an API Client developped in GO to use the Cato API.  

This GO Client has been developed for the OSS Terraform Provider for Cato Networks : https://registry.terraform.io/providers/BenEkpy/cato-oss/latest/docs

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

To run the the OSS Cato Go Client, you should have GO version >= 1.21.5

for more details, refer to the official GO installation guide : https://go.dev/doc/install

To install the last version of the OSS Cato Go Client, please execute the following command :

```sh
go get github.com/BenEkpy/cato-go-client-oss@latest
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

Prior to OSS Cato Go Client execution, you should 
- generate an API Key with the apropriate rights in the CMA 
- retrieve you accountId 

### Example

Here is an example of go code using OSS Cato Go Client to retrieve list of Cato Admins :

```go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/BenEkpy/cato-go-client-oss/catogo"
)

func main() {

	var baseurl string = "https://api.catonetworks.com/api/v1/graphql2"
	var token string = "YOUR_API_KEY"
	var accountId string = "YOUR_ACCOUNT_ID"

	client := catogo.CatoClient(baseurl, token, accountId)

	response, err := client.GetAdmins()
	if err != nil {
		fmt.Println("error:", err)
	}

	b, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Print(string(b))

}
```


<p align="right">(<a href="#readme-top">back to top</a>)</p>

package catogo

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Entity struct {
	Id   string  `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
	Type string  `json:"type,omitempty"`
}

type EntityInfo struct {
	Entity      Entity `json:"entity,omitempty"`
	Description string `json:"description,omitempty"`
	// HelperFields Map    `json:"helperFields,omitempty"`
}

type EntityLookupResult struct {
	Items []EntityInfo `json:"items,omitempty"`
	Total *int64       `json:"total,omitempty"`
}

func (c *Client) GetSocketSiteNativeRangeId(siteId string) (*Entity, error) {

	query := graphQLRequest{
		Query: `
		query entityLookup($accountId: ID!, $type: EntityType!, $siteId: ID!) {
		entityLookup(accountID: $accountId, type: $type, parent: {id: $siteId, type: site}) {
			items {
			entity {
				id
				name
			}
			helperFields
			}
			total
		}
		}`,
		Variables: map[string]interface{}{
			"accountId": c.accountId,
			"siteId":    siteId,
			"type":      "siteRange",
		},
	}

	body, err := c.do(query)
	if err != nil {
		return nil, err
	}

	var response struct{ EntityLookup EntityLookupResult }
	var entity Entity

	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	for _, item := range response.EntityLookup.Items {

		splitName := strings.Split(*item.Entity.Name, " \\ ")

		fmt.Println(splitName)

		fmt.Println(splitName[2])
		if splitName[2] == "Native Range" {
			entity = item.Entity
		}

	}

	return &entity, nil
}

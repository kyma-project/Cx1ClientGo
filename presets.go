package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Presets

func (p *Preset) String() string {
	return fmt.Sprintf("[%d] %v", p.PresetID, p.Name)
}

func (c Cx1Client) GetPresets(count uint64) ([]Preset, error) {
	c.logger.Debug("Get Cx1 Presets")
	var preset_response struct {
		TotalCount uint64   `json:"totalCount"`
		Presets    []Preset `json:"presets"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/presets?limit=%d&include_details=true", count), nil, nil)
	if err != nil {
		return preset_response.Presets, err
	}

	err = json.Unmarshal(response, &preset_response)
	c.logger.Tracef("Got %d presets", len(preset_response.Presets))
	return preset_response.Presets, err
}

func (c Cx1Client) GetPresetCount() (uint64, error) {
	c.logger.Debug("Get Cx1 Presets count")

	response, err := c.sendRequest(http.MethodGet, "/presets?limit=1", nil, nil)
	if err != nil {
		return 0, err
	}

	var preset_response struct {
		TotalCount uint64 `json:"totalCount"`
	}

	err = json.Unmarshal(response, &preset_response)
	if err != nil {
		c.logger.Tracef("Failed to unmarshal response: %s", err)
		c.logger.Tracef("Response was: %v", string(response))

	}

	return preset_response.TotalCount, err
}

func (c Cx1Client) GetPresetByName(name string) (Preset, error) {
	c.logger.Debugf("Get preset by name %v", name)
	var preset_response struct {
		TotalCount uint64   `json:"totalCount"`
		Presets    []Preset `json:"presets"`
	}

	params := url.Values{
		"offset":          {"0"},
		"limit":           {"1"},
		"exact_match":     {"true"},
		"include_details": {"true"},
		"name":            {name},
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/presets?%v", params.Encode()), nil, nil)
	if err != nil {
		return Preset{}, err
	}

	err = json.Unmarshal(response, &preset_response)

	if err != nil {
		return Preset{}, err
	}
	if len(preset_response.Presets) == 0 {
		return Preset{}, fmt.Errorf("no such preset %v found", name)
	}
	return preset_response.Presets[0], nil
}

func (c Cx1Client) GetPresetByID(id uint64) (Preset, error) {
	c.logger.Debugf("Get preset by id %d", id)
	var temp_preset struct {
		Preset
		QueryStr []string `json:"queryIds"`
	}
	var preset Preset

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/presets/%d", id), nil, nil)
	if err != nil {
		return preset, fmt.Errorf("failed to get preset %d: %s", id, err)
	}

	err = json.Unmarshal(response, &temp_preset)

	preset = Preset{PresetID: temp_preset.PresetID, Name: temp_preset.Name, Description: temp_preset.Description, Custom: temp_preset.Custom}

	preset.QueryIDs = make([]uint64, len(temp_preset.QueryStr))
	for id, q := range temp_preset.QueryStr {
		var u uint64
		u, _ = strconv.ParseUint(q, 0, 64)
		preset.QueryIDs[id] = u
	}

	return preset, err
}

func (c Cx1Client) GetPresetContents(p *Preset, qc *QueryCollection) error {
	c.logger.Tracef("Fetching contents for preset %v", p.PresetID)
	if !p.Filled {
		preset, err := c.GetPresetByID(p.PresetID)
		if err != nil {
			return err
		}
		p.Filled = true
		p.QueryIDs = preset.QueryIDs
	}

	populate_queries := true
	if qc == nil {
		c.logger.Tracef(" - GetPresetContents call was provided with an empty query collection, will not populate the Preset.Queries array")
		populate_queries = false
	} else {
		p.Queries = make([]Query, len(p.QueryIDs))
	}

	for id, qid := range p.QueryIDs {
		if populate_queries {
			q := qc.GetQueryByID(qid)
			if q != nil {
				p.Queries[id] = *q
				c.logger.Tracef(" - linked query: %v", q.String())
			}
		}
	}

	return nil
}

// convenience
func (c Cx1Client) GetAllPresets() ([]Preset, error) {
	count, err := c.GetPresetCount()
	if err != nil {
		return []Preset{}, err
	}

	return c.GetPresets(count)
}

func (c Cx1Client) CreatePreset(name, description string, queryIDs []uint64) (Preset, error) {
	c.logger.Debugf("Creating preset %v", name)
	var preset Preset

	if len(description) > 60 {
		c.logger.Warn("Description is longer than 60 characters, will be truncated")
		description = description[:60]
	}

	stringIDs := make([]string, len(queryIDs))
	for id, q := range queryIDs {
		stringIDs[id] = fmt.Sprintf("%d", q)
	}

	body := map[string]interface{}{
		"name":        name,
		"description": description,
		"queryIDs":    stringIDs,
		"custom":      true,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return preset, err
	}

	response, err := c.sendRequest(http.MethodPost, "/presets", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return preset, err
	}

	var responseStruct struct {
		Id      uint64 `json:"id"`
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return preset, err
	}

	return c.GetPresetByID(responseStruct.Id)
}

func (p *Preset) AddQueryID(queryId uint64) {
	p.QueryIDs = append(p.QueryIDs, queryId)
}

func (c Cx1Client) UpdatePreset(preset *Preset) error {
	c.logger.Debugf("Saving preset %v", preset.Name)

	qidstr := make([]string, len(preset.QueryIDs))

	for id, q := range preset.QueryIDs {
		qidstr[id] = fmt.Sprintf("%d", q)
	}

	description := preset.Description
	if len(description) > 60 {
		c.logger.Warn("Description is longer than 60 characters, will be truncated")
		description = description[:60]
	}

	body := map[string]interface{}{
		"name":        preset.Name,
		"description": description,
		"queryIds":    qidstr,
	}

	json, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/presets/%d", preset.PresetID), bytes.NewReader(json), nil)
	return err
}

func (c Cx1Client) DeletePreset(preset *Preset) error {
	c.logger.Debugf("Removing preset %v", preset.Name)
	if !preset.Custom {
		return fmt.Errorf("cannot delete preset %v - this is a product-default preset", preset.String())
	}

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/presets/%d", preset.PresetID), nil, nil)
	return err
}

func (c Cx1Client) PresetLink(p *Preset) string {
	return fmt.Sprintf("%v/resourceManagement/presets?presetId=%d", c.baseUrl, p.PresetID)
}

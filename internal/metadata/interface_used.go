// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

const DefaultInterface = "erouter0"

// this class is only used if we want websocket to populate this value dynamically, currently not used
type InterfaceUsedProvider struct {
	interfaceUsed string
}

func NewInterfaceUsedProvider() (*InterfaceUsedProvider, error) {
	return &InterfaceUsedProvider{
		interfaceUsed: DefaultInterface,
	}, nil
}

func (i *InterfaceUsedProvider) GetInterfaceUsed() string {
	return i.interfaceUsed
}

func (i *InterfaceUsedProvider) SetInterfaceUsed(interfaceUsed string) {
	i.interfaceUsed = interfaceUsed
}

// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	context "context"

	models "github.com/grafana/grafana/pkg/models"
	mock "github.com/stretchr/testify/mock"
)

// Store is an autogenerated mock type for the Store type
type Store struct {
	mock.Mock
}

// GetOrgByNameHandler provides a mock function with given fields: ctx, query
func (_m *Store) GetOrgByNameHandler(ctx context.Context, query *models.GetOrgByNameQuery) error {
	ret := _m.Called(ctx, query)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *models.GetOrgByNameQuery) error); ok {
		r0 = rf(ctx, query)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetPluginSettingById provides a mock function with given fields: ctx, query
func (_m *Store) GetPluginSettingById(ctx context.Context, query *models.GetPluginSettingByIdQuery) error {
	ret := _m.Called(ctx, query)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *models.GetPluginSettingByIdQuery) error); ok {
		r0 = rf(ctx, query)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdatePluginSetting provides a mock function with given fields: ctx, cmd
func (_m *Store) UpdatePluginSetting(ctx context.Context, cmd *models.UpdatePluginSettingCmd) error {
	ret := _m.Called(ctx, cmd)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *models.UpdatePluginSettingCmd) error); ok {
		r0 = rf(ctx, cmd)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

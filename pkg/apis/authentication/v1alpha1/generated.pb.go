/*
Copyright SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/gardener/gardener/pkg/apis/authentication/v1alpha1/generated.proto

package v1alpha1

import (
	fmt "fmt"

	io "io"

	proto "github.com/gogo/protobuf/proto"

	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

func (m *AdminKubeconfigRequest) Reset()      { *m = AdminKubeconfigRequest{} }
func (*AdminKubeconfigRequest) ProtoMessage() {}
func (*AdminKubeconfigRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ad0cb10cdbf25b8, []int{0}
}
func (m *AdminKubeconfigRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AdminKubeconfigRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *AdminKubeconfigRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AdminKubeconfigRequest.Merge(m, src)
}
func (m *AdminKubeconfigRequest) XXX_Size() int {
	return m.Size()
}
func (m *AdminKubeconfigRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AdminKubeconfigRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AdminKubeconfigRequest proto.InternalMessageInfo

func (m *AdminKubeconfigRequestSpec) Reset()      { *m = AdminKubeconfigRequestSpec{} }
func (*AdminKubeconfigRequestSpec) ProtoMessage() {}
func (*AdminKubeconfigRequestSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ad0cb10cdbf25b8, []int{1}
}
func (m *AdminKubeconfigRequestSpec) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AdminKubeconfigRequestSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *AdminKubeconfigRequestSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AdminKubeconfigRequestSpec.Merge(m, src)
}
func (m *AdminKubeconfigRequestSpec) XXX_Size() int {
	return m.Size()
}
func (m *AdminKubeconfigRequestSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_AdminKubeconfigRequestSpec.DiscardUnknown(m)
}

var xxx_messageInfo_AdminKubeconfigRequestSpec proto.InternalMessageInfo

func (m *AdminKubeconfigRequestStatus) Reset()      { *m = AdminKubeconfigRequestStatus{} }
func (*AdminKubeconfigRequestStatus) ProtoMessage() {}
func (*AdminKubeconfigRequestStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ad0cb10cdbf25b8, []int{2}
}
func (m *AdminKubeconfigRequestStatus) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AdminKubeconfigRequestStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *AdminKubeconfigRequestStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AdminKubeconfigRequestStatus.Merge(m, src)
}
func (m *AdminKubeconfigRequestStatus) XXX_Size() int {
	return m.Size()
}
func (m *AdminKubeconfigRequestStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_AdminKubeconfigRequestStatus.DiscardUnknown(m)
}

var xxx_messageInfo_AdminKubeconfigRequestStatus proto.InternalMessageInfo

func (m *ViewerKubeconfigRequest) Reset()      { *m = ViewerKubeconfigRequest{} }
func (*ViewerKubeconfigRequest) ProtoMessage() {}
func (*ViewerKubeconfigRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ad0cb10cdbf25b8, []int{3}
}
func (m *ViewerKubeconfigRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ViewerKubeconfigRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *ViewerKubeconfigRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ViewerKubeconfigRequest.Merge(m, src)
}
func (m *ViewerKubeconfigRequest) XXX_Size() int {
	return m.Size()
}
func (m *ViewerKubeconfigRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ViewerKubeconfigRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ViewerKubeconfigRequest proto.InternalMessageInfo

func (m *ViewerKubeconfigRequestSpec) Reset()      { *m = ViewerKubeconfigRequestSpec{} }
func (*ViewerKubeconfigRequestSpec) ProtoMessage() {}
func (*ViewerKubeconfigRequestSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ad0cb10cdbf25b8, []int{4}
}
func (m *ViewerKubeconfigRequestSpec) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ViewerKubeconfigRequestSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *ViewerKubeconfigRequestSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ViewerKubeconfigRequestSpec.Merge(m, src)
}
func (m *ViewerKubeconfigRequestSpec) XXX_Size() int {
	return m.Size()
}
func (m *ViewerKubeconfigRequestSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_ViewerKubeconfigRequestSpec.DiscardUnknown(m)
}

var xxx_messageInfo_ViewerKubeconfigRequestSpec proto.InternalMessageInfo

func (m *ViewerKubeconfigRequestStatus) Reset()      { *m = ViewerKubeconfigRequestStatus{} }
func (*ViewerKubeconfigRequestStatus) ProtoMessage() {}
func (*ViewerKubeconfigRequestStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ad0cb10cdbf25b8, []int{5}
}
func (m *ViewerKubeconfigRequestStatus) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ViewerKubeconfigRequestStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *ViewerKubeconfigRequestStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ViewerKubeconfigRequestStatus.Merge(m, src)
}
func (m *ViewerKubeconfigRequestStatus) XXX_Size() int {
	return m.Size()
}
func (m *ViewerKubeconfigRequestStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_ViewerKubeconfigRequestStatus.DiscardUnknown(m)
}

var xxx_messageInfo_ViewerKubeconfigRequestStatus proto.InternalMessageInfo

func init() {
	proto.RegisterType((*AdminKubeconfigRequest)(nil), "github.com.gardener.gardener.pkg.apis.authentication.v1alpha1.AdminKubeconfigRequest")
	proto.RegisterType((*AdminKubeconfigRequestSpec)(nil), "github.com.gardener.gardener.pkg.apis.authentication.v1alpha1.AdminKubeconfigRequestSpec")
	proto.RegisterType((*AdminKubeconfigRequestStatus)(nil), "github.com.gardener.gardener.pkg.apis.authentication.v1alpha1.AdminKubeconfigRequestStatus")
	proto.RegisterType((*ViewerKubeconfigRequest)(nil), "github.com.gardener.gardener.pkg.apis.authentication.v1alpha1.ViewerKubeconfigRequest")
	proto.RegisterType((*ViewerKubeconfigRequestSpec)(nil), "github.com.gardener.gardener.pkg.apis.authentication.v1alpha1.ViewerKubeconfigRequestSpec")
	proto.RegisterType((*ViewerKubeconfigRequestStatus)(nil), "github.com.gardener.gardener.pkg.apis.authentication.v1alpha1.ViewerKubeconfigRequestStatus")
}

func init() {
	proto.RegisterFile("github.com/gardener/gardener/pkg/apis/authentication/v1alpha1/generated.proto", fileDescriptor_4ad0cb10cdbf25b8)
}

var fileDescriptor_4ad0cb10cdbf25b8 = []byte{
	// 524 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xd4, 0x55, 0x4f, 0x6b, 0xd4, 0x40,
	0x14, 0xcf, 0x74, 0x4b, 0x91, 0xb1, 0x14, 0x9a, 0xa2, 0x2e, 0x5b, 0xcd, 0xca, 0x9e, 0x44, 0x70,
	0xe2, 0x8a, 0x88, 0x97, 0x1e, 0x8c, 0xf4, 0x24, 0x45, 0x48, 0x45, 0xb0, 0x7a, 0x70, 0x92, 0xbc,
	0x26, 0xe3, 0x9a, 0x64, 0xcc, 0x4c, 0x56, 0x8b, 0x1e, 0x0a, 0xfa, 0x01, 0xfc, 0x58, 0xab, 0xa7,
	0x1e, 0x7b, 0x5a, 0xdc, 0xf8, 0x39, 0x04, 0x99, 0xd9, 0xb4, 0xd9, 0xee, 0x76, 0x57, 0x61, 0x5d,
	0xa4, 0xb7, 0xf7, 0x32, 0xef, 0xf7, 0x67, 0xe6, 0xfd, 0x20, 0x78, 0x27, 0x64, 0x32, 0xca, 0x3d,
	0xe2, 0xa7, 0xb1, 0x1d, 0xd2, 0x2c, 0x80, 0x04, 0xb2, 0xaa, 0xe0, 0x9d, 0xd0, 0xa6, 0x9c, 0x09,
	0x9b, 0xe6, 0x32, 0x82, 0x44, 0x32, 0x9f, 0x4a, 0x96, 0x26, 0x76, 0xb7, 0x4d, 0xdf, 0xf2, 0x88,
	0xb6, 0xed, 0x50, 0x8d, 0x51, 0x09, 0x01, 0xe1, 0x59, 0x2a, 0x53, 0x73, 0xab, 0xa2, 0x23, 0x27,
	0x2c, 0x55, 0xc1, 0x3b, 0x21, 0x51, 0x74, 0xe4, 0x2c, 0x1d, 0x39, 0xa1, 0x6b, 0xdc, 0x19, 0x75,
	0x93, 0x86, 0xa9, 0xad, 0x59, 0xbd, 0x7c, 0x5f, 0x77, 0xba, 0xd1, 0xd5, 0x50, 0xad, 0x71, 0xbf,
	0xf3, 0x50, 0x10, 0x96, 0x2a, 0x8b, 0x31, 0xf5, 0x23, 0x96, 0x40, 0x76, 0x50, 0x79, 0x8e, 0x41,
	0x52, 0xbb, 0x3b, 0xe1, 0xb1, 0x61, 0x4f, 0x43, 0x65, 0x79, 0x22, 0x59, 0x0c, 0x13, 0x80, 0x07,
	0x7f, 0x02, 0x08, 0x3f, 0x82, 0x98, 0x8e, 0xe3, 0x5a, 0xbf, 0x96, 0xf0, 0xd5, 0x47, 0x41, 0xcc,
	0x92, 0x27, 0xb9, 0x07, 0x7e, 0x9a, 0xec, 0xb3, 0xd0, 0x85, 0x77, 0x39, 0x08, 0x69, 0xbe, 0xc6,
	0x97, 0x94, 0xbd, 0x80, 0x4a, 0x5a, 0x47, 0x37, 0xd1, 0xad, 0xcb, 0xf7, 0xee, 0x92, 0xa1, 0x0a,
	0x19, 0x55, 0xa9, 0x5e, 0x4c, 0x4d, 0x93, 0x6e, 0x9b, 0x3c, 0xf5, 0xde, 0x80, 0x2f, 0x77, 0x40,
	0x52, 0xc7, 0xec, 0xf5, 0x9b, 0x46, 0xd1, 0x6f, 0xe2, 0xea, 0x9b, 0x7b, 0xca, 0x6a, 0x7e, 0xc4,
	0xcb, 0x82, 0x83, 0x5f, 0x5f, 0xd2, 0xec, 0x2f, 0xc8, 0x5c, 0x8b, 0x21, 0xe7, 0x5f, 0x63, 0x97,
	0x83, 0xef, 0xac, 0x96, 0x36, 0x96, 0x55, 0xe7, 0x6a, 0x51, 0xf3, 0x33, 0xc2, 0x2b, 0x42, 0x52,
	0x99, 0x8b, 0x7a, 0x4d, 0xeb, 0xbf, 0x5c, 0x8c, 0xbe, 0x96, 0x70, 0xd6, 0x4a, 0x07, 0x2b, 0xc3,
	0xde, 0x2d, 0xa5, 0x5b, 0x14, 0x37, 0xa6, 0xfb, 0x36, 0x1f, 0xe3, 0x75, 0xf8, 0xc0, 0x59, 0xa6,
	0x95, 0x76, 0xd5, 0x40, 0x20, 0xf4, 0x2e, 0x6a, 0xce, 0x95, 0xa2, 0xdf, 0x5c, 0xdf, 0x1e, 0x3f,
	0x74, 0x27, 0xe7, 0x5b, 0xdf, 0x10, 0xbe, 0x3e, 0xcb, 0x9b, 0x49, 0x30, 0xee, 0x9c, 0x1e, 0x69,
	0xfa, 0x55, 0x67, 0x4d, 0x2d, 0x6d, 0x04, 0x30, 0x32, 0x61, 0x1e, 0xe0, 0x8d, 0x4a, 0xe5, 0x19,
	0x8b, 0x41, 0x48, 0x1a, 0xf3, 0x72, 0x8b, 0xb7, 0xff, 0x2e, 0x23, 0x0a, 0xe6, 0x6c, 0x96, 0x8f,
	0xb2, 0xb1, 0x3d, 0x49, 0xe7, 0x9e, 0xa7, 0xd1, 0x3a, 0xac, 0xe1, 0x6b, 0xcf, 0x19, 0xbc, 0x87,
	0xec, 0x7f, 0xe4, 0xf5, 0xd3, 0x99, 0xbc, 0xee, 0xcd, 0x99, 0x97, 0x29, 0xf7, 0x98, 0x1a, 0xd8,
	0x2f, 0xe3, 0x81, 0x7d, 0xb5, 0x20, 0x03, 0xb3, 0x13, 0xeb, 0xe1, 0xcd, 0x19, 0xce, 0xff, 0x4d,
	0x64, 0xbf, 0x23, 0x7c, 0x63, 0xa6, 0xbb, 0x0b, 0x94, 0x59, 0xc7, 0xef, 0x0d, 0x2c, 0xe3, 0x68,
	0x60, 0x19, 0xc7, 0x03, 0xcb, 0x38, 0x2c, 0x2c, 0xd4, 0x2b, 0x2c, 0x74, 0x54, 0x58, 0xe8, 0xb8,
	0xb0, 0xd0, 0x8f, 0xc2, 0x42, 0x5f, 0x7f, 0x5a, 0xc6, 0xde, 0xd6, 0x5c, 0x3f, 0xb9, 0xdf, 0x01,
	0x00, 0x00, 0xff, 0xff, 0x70, 0x4f, 0x31, 0xf7, 0x24, 0x07, 0x00, 0x00,
}

func (m *AdminKubeconfigRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AdminKubeconfigRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AdminKubeconfigRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.Status.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x1a
	{
		size, err := m.Spec.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	{
		size, err := m.ObjectMeta.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *AdminKubeconfigRequestSpec) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AdminKubeconfigRequestSpec) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AdminKubeconfigRequestSpec) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.ExpirationSeconds != nil {
		i = encodeVarintGenerated(dAtA, i, uint64(*m.ExpirationSeconds))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *AdminKubeconfigRequestStatus) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AdminKubeconfigRequestStatus) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AdminKubeconfigRequestStatus) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.ExpirationTimestamp.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	if m.Kubeconfig != nil {
		i -= len(m.Kubeconfig)
		copy(dAtA[i:], m.Kubeconfig)
		i = encodeVarintGenerated(dAtA, i, uint64(len(m.Kubeconfig)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ViewerKubeconfigRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ViewerKubeconfigRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ViewerKubeconfigRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.Status.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x1a
	{
		size, err := m.Spec.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	{
		size, err := m.ObjectMeta.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *ViewerKubeconfigRequestSpec) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ViewerKubeconfigRequestSpec) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ViewerKubeconfigRequestSpec) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.ExpirationSeconds != nil {
		i = encodeVarintGenerated(dAtA, i, uint64(*m.ExpirationSeconds))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *ViewerKubeconfigRequestStatus) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ViewerKubeconfigRequestStatus) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ViewerKubeconfigRequestStatus) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.ExpirationTimestamp.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGenerated(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	if m.Kubeconfig != nil {
		i -= len(m.Kubeconfig)
		copy(dAtA[i:], m.Kubeconfig)
		i = encodeVarintGenerated(dAtA, i, uint64(len(m.Kubeconfig)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintGenerated(dAtA []byte, offset int, v uint64) int {
	offset -= sovGenerated(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *AdminKubeconfigRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.ObjectMeta.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Spec.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Status.Size()
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func (m *AdminKubeconfigRequestSpec) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.ExpirationSeconds != nil {
		n += 1 + sovGenerated(uint64(*m.ExpirationSeconds))
	}
	return n
}

func (m *AdminKubeconfigRequestStatus) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Kubeconfig != nil {
		l = len(m.Kubeconfig)
		n += 1 + l + sovGenerated(uint64(l))
	}
	l = m.ExpirationTimestamp.Size()
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func (m *ViewerKubeconfigRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.ObjectMeta.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Spec.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Status.Size()
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func (m *ViewerKubeconfigRequestSpec) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.ExpirationSeconds != nil {
		n += 1 + sovGenerated(uint64(*m.ExpirationSeconds))
	}
	return n
}

func (m *ViewerKubeconfigRequestStatus) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Kubeconfig != nil {
		l = len(m.Kubeconfig)
		n += 1 + l + sovGenerated(uint64(l))
	}
	l = m.ExpirationTimestamp.Size()
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func sovGenerated(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozGenerated(x uint64) (n int) {
	return sovGenerated(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *AdminKubeconfigRequest) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AdminKubeconfigRequest{`,
		`ObjectMeta:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.ObjectMeta), "ObjectMeta", "v1.ObjectMeta", 1), `&`, ``, 1) + `,`,
		`Spec:` + strings.Replace(strings.Replace(this.Spec.String(), "AdminKubeconfigRequestSpec", "AdminKubeconfigRequestSpec", 1), `&`, ``, 1) + `,`,
		`Status:` + strings.Replace(strings.Replace(this.Status.String(), "AdminKubeconfigRequestStatus", "AdminKubeconfigRequestStatus", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AdminKubeconfigRequestSpec) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AdminKubeconfigRequestSpec{`,
		`ExpirationSeconds:` + valueToStringGenerated(this.ExpirationSeconds) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AdminKubeconfigRequestStatus) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AdminKubeconfigRequestStatus{`,
		`Kubeconfig:` + valueToStringGenerated(this.Kubeconfig) + `,`,
		`ExpirationTimestamp:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.ExpirationTimestamp), "Time", "v1.Time", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *ViewerKubeconfigRequest) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ViewerKubeconfigRequest{`,
		`ObjectMeta:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.ObjectMeta), "ObjectMeta", "v1.ObjectMeta", 1), `&`, ``, 1) + `,`,
		`Spec:` + strings.Replace(strings.Replace(this.Spec.String(), "ViewerKubeconfigRequestSpec", "ViewerKubeconfigRequestSpec", 1), `&`, ``, 1) + `,`,
		`Status:` + strings.Replace(strings.Replace(this.Status.String(), "ViewerKubeconfigRequestStatus", "ViewerKubeconfigRequestStatus", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *ViewerKubeconfigRequestSpec) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ViewerKubeconfigRequestSpec{`,
		`ExpirationSeconds:` + valueToStringGenerated(this.ExpirationSeconds) + `,`,
		`}`,
	}, "")
	return s
}
func (this *ViewerKubeconfigRequestStatus) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ViewerKubeconfigRequestStatus{`,
		`Kubeconfig:` + valueToStringGenerated(this.Kubeconfig) + `,`,
		`ExpirationTimestamp:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.ExpirationTimestamp), "Time", "v1.Time", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringGenerated(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *AdminKubeconfigRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AdminKubeconfigRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AdminKubeconfigRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ObjectMeta", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ObjectMeta.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Spec", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Spec.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Status.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *AdminKubeconfigRequestSpec) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AdminKubeconfigRequestSpec: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AdminKubeconfigRequestSpec: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExpirationSeconds", wireType)
			}
			var v int64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.ExpirationSeconds = &v
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *AdminKubeconfigRequestStatus) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AdminKubeconfigRequestStatus: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AdminKubeconfigRequestStatus: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Kubeconfig", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Kubeconfig = append(m.Kubeconfig[:0], dAtA[iNdEx:postIndex]...)
			if m.Kubeconfig == nil {
				m.Kubeconfig = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExpirationTimestamp", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ExpirationTimestamp.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ViewerKubeconfigRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ViewerKubeconfigRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ViewerKubeconfigRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ObjectMeta", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ObjectMeta.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Spec", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Spec.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Status.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ViewerKubeconfigRequestSpec) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ViewerKubeconfigRequestSpec: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ViewerKubeconfigRequestSpec: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExpirationSeconds", wireType)
			}
			var v int64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.ExpirationSeconds = &v
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ViewerKubeconfigRequestStatus) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ViewerKubeconfigRequestStatus: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ViewerKubeconfigRequestStatus: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Kubeconfig", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Kubeconfig = append(m.Kubeconfig[:0], dAtA[iNdEx:postIndex]...)
			if m.Kubeconfig == nil {
				m.Kubeconfig = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExpirationTimestamp", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ExpirationTimestamp.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipGenerated(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthGenerated
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupGenerated
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthGenerated
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthGenerated        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowGenerated          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupGenerated = fmt.Errorf("proto: unexpected end of group")
)

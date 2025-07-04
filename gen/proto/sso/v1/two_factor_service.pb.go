// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: proto/sso/v1/two_factor_service.proto

package ssov1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// --- InitiateTOTPSetup ---
type InitiateTOTPSetupRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *InitiateTOTPSetupRequest) Reset() {
	*x = InitiateTOTPSetupRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InitiateTOTPSetupRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InitiateTOTPSetupRequest) ProtoMessage() {}

func (x *InitiateTOTPSetupRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InitiateTOTPSetupRequest.ProtoReflect.Descriptor instead.
func (*InitiateTOTPSetupRequest) Descriptor() ([]byte, []int) {
	return file_proto_sso_v1_two_factor_service_proto_rawDescGZIP(), []int{0}
}

type InitiateTOTPSetupResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Secret    string `protobuf:"bytes,1,opt,name=secret,proto3" json:"secret,omitempty"`                          // The base32 encoded TOTP secret. (For manual entry if QR fails)
	QrCodeUri string `protobuf:"bytes,2,opt,name=qr_code_uri,json=qrCodeUri,proto3" json:"qr_code_uri,omitempty"` // The otpauth:// URI to be rendered as a QR code.
}

func (x *InitiateTOTPSetupResponse) Reset() {
	*x = InitiateTOTPSetupResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InitiateTOTPSetupResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InitiateTOTPSetupResponse) ProtoMessage() {}

func (x *InitiateTOTPSetupResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InitiateTOTPSetupResponse.ProtoReflect.Descriptor instead.
func (*InitiateTOTPSetupResponse) Descriptor() ([]byte, []int) {
	return file_proto_sso_v1_two_factor_service_proto_rawDescGZIP(), []int{1}
}

func (x *InitiateTOTPSetupResponse) GetSecret() string {
	if x != nil {
		return x.Secret
	}
	return ""
}

func (x *InitiateTOTPSetupResponse) GetQrCodeUri() string {
	if x != nil {
		return x.QrCodeUri
	}
	return ""
}

// --- VerifyAndEnableTOTP ---
type VerifyAndEnableTOTPRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TotpCode string `protobuf:"bytes,1,opt,name=totp_code,json=totpCode,proto3" json:"totp_code,omitempty"` // The TOTP code from the user's authenticator app.
}

func (x *VerifyAndEnableTOTPRequest) Reset() {
	*x = VerifyAndEnableTOTPRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VerifyAndEnableTOTPRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyAndEnableTOTPRequest) ProtoMessage() {}

func (x *VerifyAndEnableTOTPRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyAndEnableTOTPRequest.ProtoReflect.Descriptor instead.
func (*VerifyAndEnableTOTPRequest) Descriptor() ([]byte, []int) {
	return file_proto_sso_v1_two_factor_service_proto_rawDescGZIP(), []int{2}
}

func (x *VerifyAndEnableTOTPRequest) GetTotpCode() string {
	if x != nil {
		return x.TotpCode
	}
	return ""
}

type VerifyAndEnableTOTPResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RecoveryCodes []string `protobuf:"bytes,1,rep,name=recovery_codes,json=recoveryCodes,proto3" json:"recovery_codes,omitempty"` // A new set of recovery codes.
}

func (x *VerifyAndEnableTOTPResponse) Reset() {
	*x = VerifyAndEnableTOTPResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VerifyAndEnableTOTPResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyAndEnableTOTPResponse) ProtoMessage() {}

func (x *VerifyAndEnableTOTPResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyAndEnableTOTPResponse.ProtoReflect.Descriptor instead.
func (*VerifyAndEnableTOTPResponse) Descriptor() ([]byte, []int) {
	return file_proto_sso_v1_two_factor_service_proto_rawDescGZIP(), []int{3}
}

func (x *VerifyAndEnableTOTPResponse) GetRecoveryCodes() []string {
	if x != nil {
		return x.RecoveryCodes
	}
	return nil
}

// --- Disable2FA ---
type Disable2FARequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// For security, disabling 2FA often requires re-authentication.
	PasswordOr_2FaCode string `protobuf:"bytes,1,opt,name=password_or_2fa_code,json=passwordOr2faCode,proto3" json:"password_or_2fa_code,omitempty"` // User provides current password or a 2FA code to confirm.
}

func (x *Disable2FARequest) Reset() {
	*x = Disable2FARequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Disable2FARequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Disable2FARequest) ProtoMessage() {}

func (x *Disable2FARequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Disable2FARequest.ProtoReflect.Descriptor instead.
func (*Disable2FARequest) Descriptor() ([]byte, []int) {
	return file_proto_sso_v1_two_factor_service_proto_rawDescGZIP(), []int{4}
}

func (x *Disable2FARequest) GetPasswordOr_2FaCode() string {
	if x != nil {
		return x.PasswordOr_2FaCode
	}
	return ""
}

// --- GenerateRecoveryCodes ---
type GenerateRecoveryCodesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// User must be 2FA enabled. May require re-authentication (password or current 2FA code).
	PasswordOr_2FaCode string `protobuf:"bytes,1,opt,name=password_or_2fa_code,json=passwordOr2faCode,proto3" json:"password_or_2fa_code,omitempty"` // Optional: for re-authentication before generating new codes.
}

func (x *GenerateRecoveryCodesRequest) Reset() {
	*x = GenerateRecoveryCodesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateRecoveryCodesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateRecoveryCodesRequest) ProtoMessage() {}

func (x *GenerateRecoveryCodesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateRecoveryCodesRequest.ProtoReflect.Descriptor instead.
func (*GenerateRecoveryCodesRequest) Descriptor() ([]byte, []int) {
	return file_proto_sso_v1_two_factor_service_proto_rawDescGZIP(), []int{5}
}

func (x *GenerateRecoveryCodesRequest) GetPasswordOr_2FaCode() string {
	if x != nil {
		return x.PasswordOr_2FaCode
	}
	return ""
}

type GenerateRecoveryCodesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RecoveryCodes []string `protobuf:"bytes,1,rep,name=recovery_codes,json=recoveryCodes,proto3" json:"recovery_codes,omitempty"` // A new set of recovery codes.
}

func (x *GenerateRecoveryCodesResponse) Reset() {
	*x = GenerateRecoveryCodesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateRecoveryCodesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateRecoveryCodesResponse) ProtoMessage() {}

func (x *GenerateRecoveryCodesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_sso_v1_two_factor_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateRecoveryCodesResponse.ProtoReflect.Descriptor instead.
func (*GenerateRecoveryCodesResponse) Descriptor() ([]byte, []int) {
	return file_proto_sso_v1_two_factor_service_proto_rawDescGZIP(), []int{6}
}

func (x *GenerateRecoveryCodesResponse) GetRecoveryCodes() []string {
	if x != nil {
		return x.RecoveryCodes
	}
	return nil
}

var File_proto_sso_v1_two_factor_service_proto protoreflect.FileDescriptor

var file_proto_sso_v1_two_factor_service_proto_rawDesc = []byte{
	0x0a, 0x25, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x73, 0x6f, 0x2f, 0x76, 0x31, 0x2f, 0x74,
	0x77, 0x6f, 0x5f, 0x66, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x73, 0x73, 0x6f, 0x2e, 0x76, 0x31, 0x1a,
	0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x1a, 0x0a, 0x18,
	0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x65, 0x54, 0x4f, 0x54, 0x50, 0x53, 0x65, 0x74, 0x75,
	0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x53, 0x0a, 0x19, 0x49, 0x6e, 0x69, 0x74,
	0x69, 0x61, 0x74, 0x65, 0x54, 0x4f, 0x54, 0x50, 0x53, 0x65, 0x74, 0x75, 0x70, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x1e, 0x0a,
	0x0b, 0x71, 0x72, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x71, 0x72, 0x43, 0x6f, 0x64, 0x65, 0x55, 0x72, 0x69, 0x22, 0x39, 0x0a,
	0x1a, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x41, 0x6e, 0x64, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65,
	0x54, 0x4f, 0x54, 0x50, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x74,
	0x6f, 0x74, 0x70, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x74, 0x6f, 0x74, 0x70, 0x43, 0x6f, 0x64, 0x65, 0x22, 0x44, 0x0a, 0x1b, 0x56, 0x65, 0x72, 0x69,
	0x66, 0x79, 0x41, 0x6e, 0x64, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x54, 0x4f, 0x54, 0x50, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x72, 0x65, 0x63, 0x6f, 0x76,
	0x65, 0x72, 0x79, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0d, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x22, 0x44,
	0x0a, 0x11, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x32, 0x46, 0x41, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x2f, 0x0a, 0x14, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x5f,
	0x6f, 0x72, 0x5f, 0x32, 0x66, 0x61, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x11, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x4f, 0x72, 0x32, 0x66, 0x61,
	0x43, 0x6f, 0x64, 0x65, 0x22, 0x4f, 0x0a, 0x1c, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65,
	0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x2f, 0x0a, 0x14, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
	0x5f, 0x6f, 0x72, 0x5f, 0x32, 0x66, 0x61, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x11, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x4f, 0x72, 0x32, 0x66,
	0x61, 0x43, 0x6f, 0x64, 0x65, 0x22, 0x46, 0x0a, 0x1d, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65,
	0x72, 0x79, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d,
	0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x32, 0xf3, 0x02,
	0x0a, 0x10, 0x54, 0x77, 0x6f, 0x46, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0x58, 0x0a, 0x11, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x65, 0x54, 0x4f,
	0x54, 0x50, 0x53, 0x65, 0x74, 0x75, 0x70, 0x12, 0x20, 0x2e, 0x73, 0x73, 0x6f, 0x2e, 0x76, 0x31,
	0x2e, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x65, 0x54, 0x4f, 0x54, 0x50, 0x53, 0x65, 0x74,
	0x75, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x73, 0x73, 0x6f, 0x2e,
	0x76, 0x31, 0x2e, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x65, 0x54, 0x4f, 0x54, 0x50, 0x53,
	0x65, 0x74, 0x75, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5e, 0x0a, 0x13,
	0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x41, 0x6e, 0x64, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x54,
	0x4f, 0x54, 0x50, 0x12, 0x22, 0x2e, 0x73, 0x73, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x65, 0x72,
	0x69, 0x66, 0x79, 0x41, 0x6e, 0x64, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x54, 0x4f, 0x54, 0x50,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x73, 0x73, 0x6f, 0x2e, 0x76, 0x31,
	0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x41, 0x6e, 0x64, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65,
	0x54, 0x4f, 0x54, 0x50, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3f, 0x0a, 0x0a,
	0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x32, 0x46, 0x41, 0x12, 0x19, 0x2e, 0x73, 0x73, 0x6f,
	0x2e, 0x76, 0x31, 0x2e, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x32, 0x46, 0x41, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x64, 0x0a,
	0x15, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72,
	0x79, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x24, 0x2e, 0x73, 0x73, 0x6f, 0x2e, 0x76, 0x31, 0x2e,
	0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
	0x43, 0x6f, 0x64, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e, 0x73,
	0x73, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x42, 0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x70, 0x69, 0x6c, 0x61, 0x62, 0x2d, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x61, 0x64,
	0x6f, 0x77, 0x2d, 0x73, 0x73, 0x6f, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x73, 0x73, 0x6f, 0x2f, 0x76, 0x31, 0x3b, 0x73, 0x73, 0x6f, 0x76, 0x31, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_sso_v1_two_factor_service_proto_rawDescOnce sync.Once
	file_proto_sso_v1_two_factor_service_proto_rawDescData = file_proto_sso_v1_two_factor_service_proto_rawDesc
)

func file_proto_sso_v1_two_factor_service_proto_rawDescGZIP() []byte {
	file_proto_sso_v1_two_factor_service_proto_rawDescOnce.Do(func() {
		file_proto_sso_v1_two_factor_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_sso_v1_two_factor_service_proto_rawDescData)
	})
	return file_proto_sso_v1_two_factor_service_proto_rawDescData
}

var file_proto_sso_v1_two_factor_service_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_proto_sso_v1_two_factor_service_proto_goTypes = []interface{}{
	(*InitiateTOTPSetupRequest)(nil),      // 0: sso.v1.InitiateTOTPSetupRequest
	(*InitiateTOTPSetupResponse)(nil),     // 1: sso.v1.InitiateTOTPSetupResponse
	(*VerifyAndEnableTOTPRequest)(nil),    // 2: sso.v1.VerifyAndEnableTOTPRequest
	(*VerifyAndEnableTOTPResponse)(nil),   // 3: sso.v1.VerifyAndEnableTOTPResponse
	(*Disable2FARequest)(nil),             // 4: sso.v1.Disable2FARequest
	(*GenerateRecoveryCodesRequest)(nil),  // 5: sso.v1.GenerateRecoveryCodesRequest
	(*GenerateRecoveryCodesResponse)(nil), // 6: sso.v1.GenerateRecoveryCodesResponse
	(*emptypb.Empty)(nil),                 // 7: google.protobuf.Empty
}
var file_proto_sso_v1_two_factor_service_proto_depIdxs = []int32{
	0, // 0: sso.v1.TwoFactorService.InitiateTOTPSetup:input_type -> sso.v1.InitiateTOTPSetupRequest
	2, // 1: sso.v1.TwoFactorService.VerifyAndEnableTOTP:input_type -> sso.v1.VerifyAndEnableTOTPRequest
	4, // 2: sso.v1.TwoFactorService.Disable2FA:input_type -> sso.v1.Disable2FARequest
	5, // 3: sso.v1.TwoFactorService.GenerateRecoveryCodes:input_type -> sso.v1.GenerateRecoveryCodesRequest
	1, // 4: sso.v1.TwoFactorService.InitiateTOTPSetup:output_type -> sso.v1.InitiateTOTPSetupResponse
	3, // 5: sso.v1.TwoFactorService.VerifyAndEnableTOTP:output_type -> sso.v1.VerifyAndEnableTOTPResponse
	7, // 6: sso.v1.TwoFactorService.Disable2FA:output_type -> google.protobuf.Empty
	6, // 7: sso.v1.TwoFactorService.GenerateRecoveryCodes:output_type -> sso.v1.GenerateRecoveryCodesResponse
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_proto_sso_v1_two_factor_service_proto_init() }
func file_proto_sso_v1_two_factor_service_proto_init() {
	if File_proto_sso_v1_two_factor_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_sso_v1_two_factor_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InitiateTOTPSetupRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_sso_v1_two_factor_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InitiateTOTPSetupResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_sso_v1_two_factor_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VerifyAndEnableTOTPRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_sso_v1_two_factor_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VerifyAndEnableTOTPResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_sso_v1_two_factor_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Disable2FARequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_sso_v1_two_factor_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateRecoveryCodesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_sso_v1_two_factor_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateRecoveryCodesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_sso_v1_two_factor_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_sso_v1_two_factor_service_proto_goTypes,
		DependencyIndexes: file_proto_sso_v1_two_factor_service_proto_depIdxs,
		MessageInfos:      file_proto_sso_v1_two_factor_service_proto_msgTypes,
	}.Build()
	File_proto_sso_v1_two_factor_service_proto = out.File
	file_proto_sso_v1_two_factor_service_proto_rawDesc = nil
	file_proto_sso_v1_two_factor_service_proto_goTypes = nil
	file_proto_sso_v1_two_factor_service_proto_depIdxs = nil
}

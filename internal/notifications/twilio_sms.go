package notifications

import (
	"fmt"

	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

// TwilioSMSService implements domain.SMSService using Twilio
type TwilioSMSService struct {
	client     *twilio.RestClient
	fromNumber string
}

// NewTwilioSMSService creates a new Twilio SMS service
func NewTwilioSMSService(accountSID, authToken, fromNumber string) *TwilioSMSService {
	if accountSID == "" || authToken == "" || fromNumber == "" {
		// Return service with nil client - will fail gracefully when used
		return &TwilioSMSService{}
	}

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	return &TwilioSMSService{
		client:     client,
		fromNumber: fromNumber,
	}
}

// SendOTP sends an OTP via SMS using Twilio
func (s *TwilioSMSService) SendOTP(phoneNumber, otp string) error {
	if s.client == nil || s.fromNumber == "" {
		return fmt.Errorf("Twilio service not properly configured")
	}

	// Format phone number (ensure it has + prefix)
	if phoneNumber[0] != '+' {
		phoneNumber = "+" + phoneNumber
	}

	params := &twilioApi.CreateMessageParams{}
	params.SetTo(phoneNumber)
	params.SetFrom(s.fromNumber)
	params.SetBody(fmt.Sprintf("Your verification code is: %s", otp))

	resp, err := s.client.Api.CreateMessage(params)
	if err != nil {
		return fmt.Errorf("failed to send SMS via Twilio: %w", err)
	}

	if resp.ErrorCode != nil {
		return fmt.Errorf("Twilio API error: %d - %s", *resp.ErrorCode, *resp.ErrorMessage)
	}

	return nil
}

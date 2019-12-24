package pay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"github.com/fintcloud/wechat/util"
	"strings"
)

const (
	profitSharingUrl = "https://api.mch.weixin.qq.com/secapi/pay/profitsharing"
	multiProfitSharingUrl = "https://api.mch.weixin.qq.com/secapi/pay/multiprofitsharing"
	profitSharingQueryUrl = "https://api.mch.weixin.qq.com/pay/profitsharingquery"
	profitSharingAddReceiverUrl = "https://api.mch.weixin.qq.com/pay/profitsharingaddreceiver"
	profitSharingRemoveReceiverUrl = "https://api.mch.weixin.qq.com/pay/profitsharingremovereceiver"
	profitSharingFinishUrl = "https://api.mch.weixin.qq.com/secapi/pay/profitsharingfinish"
	profitSharingReturnUrl = "https://api.mch.weixin.qq.com/secapi/pay/profitsharingreturn"
	profitSharingReturnQueryUrl = "https://api.mch.weixin.qq.com/pay/profitsharingreturnquery"
)

type ReceiverType string
type RelationType string

const (
	MerchantId ReceiverType = "MERCHANT_ID"
	PersonalWechatId = "PERSONAL_WECHATID"
	PersonalOpenId = "PERSONAL_OPENID"
)

const (
	ServiceProvider RelationType = "SERVICE_PROVIDER"
	Store = "STORE"
	Staff = "STAFF"
	Partner = "PARTNER"
	Headquarter = "HEADQUARTER"
	Brand = "BRAND"
	Distributor = "DISTRIBUTOR"
	User = "USER"
	Supplier = "SUPPLIER"
	Custom = "CUSTOM"
)

type ProfitSharingReceiver struct {
	Type            ReceiverType 	`json:"type"`
	Account         string			`json:"account"`
	Name            string 			`json:"name"`
	RelationType   	RelationType 	`json:"relation_type"`
	CustomRelation 	string 			`json:"custom_relation"`
}

type ProfitSharingAddReceiverRequest struct {
	XMLName   xml.Name 	`xml:"xml"`
	MchId    string   	`xml:"mch_id"`
	Appid     string   	`xml:"appid"`
	NonceStr string   	`xml:"nonce_str"`
	Sign      string   	`xml:"sign"`
	SignType string   	`xml:"sign_type"`
	Receiver  string 	`xml:"receiver"` //go xml.Marshal()
}

type ProfitSharingAddReceiverResponse struct {
	XMLName      xml.Name `xml:"xml"`
	ReturnCode  string   `xml:"return_code"`
	ReturnMsg   string   `xml:"return_msg"`
	ResultCode  string   `xml:"result_code"`
	ErrCode     string   `xml:"err_code"`
	ErrCodeDes string   `xml:"err_code_des"`
	Mchid       string   `xml:"mch_id"`
	Appid        string   `xml:"appid"`
	Receiver     string `xml:"receiver"`
	NonceStr    string   `xml:"nonce_str"`
	Sign         string   `xml:"sign"`
}

type ReceiverAmount struct {
	Type        string `json:"type"`
	Account     string `json:"account"`
	Amount      int    `json:"amount"`
	Description string `json:"description"`
}

type ProfitSharingRequest struct {
	XMLName       xml.Name `xml:"xml"`
	Appid         string   `xml:"appid"`
	MchId         string   `xml:"mch_id"`
	NonceStr      string   `xml:"nonce_str"`
	OutOrderNo    string   `xml:"out_order_no"`
	TransactionID string   `xml:"transaction_id"`
	Sign          string   `xml:"sign"`
	SignType      string   `xml:"sign_type"`
	Receivers     string   `xml:"receivers"`
}

type ProfitSharingResponse struct {
	XMLName       xml.Name `xml:"xml"`
	ReturnCode    string   `xml:"return_code"`
	ReturnMsg     string   `xml:"return_msg"`
	ResultCode    string   `xml:"result_code"`
	ErrCode     string   `xml:"err_code"`
	ErrCodeDes string   `xml:"err_code_des"`
	MchID         string   `xml:"mch_id"`
	Appid         string   `xml:"appid"`
	NonceStr      string   `xml:"nonce_str"`
	OutOrderNo    string   `xml:"out_order_no"`
	TransactionID string   `xml:"transaction_id"`
	OrderID       string   `xml:"order_id"`
	Sign          string   `xml:"sign"`
}



func (pcf *Pay) AddProfitSharingReveiver(receiver *ProfitSharingReceiver) (resAddReceiver *ProfitSharingAddReceiverResponse, err error) {
	nonceStr := util.RandomStr(32)
	receiverJson, err := json.Marshal(receiver)
	if err != nil {
		return
	}
	params := make(map[string]string)
	params["mch_id"] = pcf.PayMchID
	params["appid"] = pcf.AppID
	params["nonce_str"] = nonceStr
	params["sign_type"] = "HMAC-SHA256"
	params["receiver"] = string(receiverJson)

	str := orderParam(params, pcf.AppSecret)
	strMd5 := util.MD5Sum(str)
	h := hmac.New(sha256.New, []byte(pcf.PayKey))
	h.Write([]byte(strMd5))
	// 签名
	sign := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	var request = ProfitSharingAddReceiverRequest{
		MchId:		pcf.PayMchID,
		Appid:		pcf.AppID,
		NonceStr:	nonceStr,
		Sign:		sign,
		SignType: 	"HMAC-SHA256",
		Receiver: 	string(receiverJson),
	}

	rawRet, err := util.PostXML(profitSharingAddReceiverUrl, request)
	if err != nil {
		return
	}
	var response = new(ProfitSharingAddReceiverResponse)
	err = xml.Unmarshal(rawRet, &response)
	if err != nil {
		return
	}

	if response.ReturnCode == "SUCCESS" {
		// pay success
		if response.ResultCode == "SUCCESS" {
			err = nil
			return
		}
		err = errors.New(response.ErrCode + response.ErrCodeDes)
		return
	}
	err = errors.New("[msg : xmlUnmarshalError] [rawReturn : " + string(rawRet) + "] [params : " + str + "] [sign : " + sign + "]")
	return

}

func (pcf *Pay) ProfitSharing(orderNo string, wechatOrderNo string, receivers []ReceiverAmount) (resProfitSharing *ProfitSharingResponse, err error) {
	nonceStr := util.RandomStr(32)
	receiverJson, err := json.Marshal(receivers)
	if err != nil {
		return
	}
	params := make(map[string]string)
	params["mch_id"] = pcf.PayMchID
	params["appid"] = pcf.AppID
	params["nonce_str"] = nonceStr
	params["sign_type"] = "HMAC-SHA256"
	params["transaction_id"] = wechatOrderNo
	params["out_order_no"] = orderNo
	params["receiver"] = string(receiverJson)

	str := orderParam(params, pcf.AppSecret)
	strMd5 := util.MD5Sum(str)
	h := hmac.New(sha256.New, []byte(pcf.PayKey))
	h.Write([]byte(strMd5))
	// 签名
	sign := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	var request = ProfitSharingRequest{
		Appid:			pcf.AppID,
		MchId:			pcf.PayMchID,
		NonceStr:		nonceStr,
		OutOrderNo: 	orderNo,
		TransactionID:	wechatOrderNo,
		Sign:			sign,
		SignType: 		"HMAC-SHA256",
		Receivers: 		string(receiverJson),
	}

	rawRet, err := util.PostXML(profitSharingUrl, request)
	if err != nil {
		return
	}
	var response = new(ProfitSharingResponse)
	err = xml.Unmarshal(rawRet, &response)
	if err != nil {
		return
	}

	if response.ReturnCode == "SUCCESS" {
		// pay success
		if response.ResultCode == "SUCCESS" {
			err = nil
			return
		}
		err = errors.New(response.ErrCode + response.ErrCodeDes)
		return
	}
	err = errors.New("[msg : xmlUnmarshalError] [rawReturn : " + string(rawRet) + "] [params : " + str + "] [sign : " + sign + "]")
	return

}












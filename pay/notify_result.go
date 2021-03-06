package pay

import (
	"fmt"
	"github.com/fintcloud/wechat/util"
	"sort"
)

type CDATA string

// Base 公用参数
type Base struct {
	AppID    string `xml:"appid"`
	MchID    string `xml:"mch_id"`
	NonceStr string `xml:"nonce_str"`
	Sign     string `xml:"sign"`
}

// NotifyResult 下单回调
type NotifyResult struct {
	Base
	SignType	  string `xml:"sign_type"`
	DeviceInfo    string `xml:"device_info"`
	ReturnCode    string `xml:"return_code"`
	ReturnMsg     string `xml:"return_msg"`
	ResultCode    string `xml:"result_code"`
	ErrCode 	  string `xml:"err_code"`
	ErrCodeDes	  string `xml:"err_code_des"`
	OpenID        string `xml:"openid"`
	IsSubscribe   string `xml:"is_subscribe"`
	TradeType     string `xml:"trade_type"`
	BankType      string `xml:"bank_type"`
	TotalFee      int    `xml:"total_fee"`
	SettlementTotalFee	int	`xml:"settlement_total_fee"`
	FeeType       string `xml:"fee_type"`
	CashFee       int    `xml:"cash_fee"`
	CashFeeType   string `xml:"cash_fee_type"`
	TransactionID string `xml:"transaction_id"`
	OutTradeNo    string `xml:"out_trade_no"`
	Attach        string `xml:"attach"`
	TimeEnd       string `xml:"time_end"`
	CouponFee     int	   `xml:"coupon_fee"`
	CouponCount   int 	   `xml:"coupon_count"`
	CouponType    string   `xml:"coupon_type"`
	CouponID      string   `xml:"coupon_id"`
	CouponID0     string `xml:"coupon_id_0"`
	CouponFee0    int64  `xml:"coupon_fee_0"`
	CouponType0    string   `xml:"coupon_type_0"`
	CouponID1     string `xml:"coupon_id_1"`
	CouponFee1    int64  `xml:"coupon_fee_1"`
	CouponType1    string   `xml:"coupon_type_1"`
	CouponID2     string `xml:"coupon_id_2"`
	CouponFee2    int64  `xml:"coupon_fee_2"`
	CouponType2    string   `xml:"coupon_type_2"`
	CouponID3     string `xml:"coupon_id_3"`
	CouponFee3    int64  `xml:"coupon_fee_3"`
	CouponType3    string   `xml:"coupon_type_3"`
	CouponID4     string `xml:"coupon_id_4"`
	CouponFee4    int64  `xml:"coupon_fee_4"`
	CouponType4    string   `xml:"coupon_type_4"`
	CouponID5     string `xml:"coupon_id_5"`
	CouponFee5    int64  `xml:"coupon_fee_5"`
	CouponType5    string   `xml:"coupon_type_5"`
}

// NotifyResp 消息通知返回
type NotifyResp struct {
	ReturnCode CDATA `xml:"return_code"`
	ReturnMsg  CDATA `xml:"return_msg"`
}

// VerifySign 验签
func (pcf *Pay) VerifySign(notifyRes NotifyResult) bool {
	// 封装map 请求过来的 map
	resMap := make(map[string]interface{})
	// base
	resMap["appid"] = notifyRes.AppID
	resMap["mch_id"] = notifyRes.MchID
	resMap["nonce_str"] = notifyRes.NonceStr
	// NotifyResult
	resMap["return_code"] = notifyRes.ReturnCode
	resMap["result_code"] = notifyRes.ResultCode
	resMap["openid"] = notifyRes.OpenID
	resMap["is_subscribe"] = notifyRes.IsSubscribe
	resMap["trade_type"] = notifyRes.TradeType
	resMap["bank_type"] = notifyRes.BankType
	resMap["total_fee"] = notifyRes.TotalFee
	resMap["fee_type"] = notifyRes.FeeType
	resMap["cash_fee"] = notifyRes.CashFee
	resMap["transaction_id"] = notifyRes.TransactionID
	resMap["out_trade_no"] = notifyRes.OutTradeNo
	resMap["attach"] = notifyRes.Attach
	resMap["time_end"] = notifyRes.TimeEnd
	resMap["coupon_fee"] = notifyRes.CouponFee
	resMap["coupon_count"] = notifyRes.CouponCount
	resMap["coupon_type"] = notifyRes.CouponType
	resMap["coupon_id"] = notifyRes.CouponID
	resMap["coupon_id_0"] = notifyRes.CouponID0
	resMap["coupon_fee_0"] = notifyRes.CouponFee0
	resMap["coupon_type_0"] = notifyRes.CouponType0
	resMap["coupon_id_1"] = notifyRes.CouponID1
	resMap["coupon_fee_1"] = notifyRes.CouponFee1
	resMap["coupon_type_1"] = notifyRes.CouponType1
	resMap["coupon_id_2"] = notifyRes.CouponID2
	resMap["coupon_fee_2"] = notifyRes.CouponFee2
	resMap["coupon_type_2"] = notifyRes.CouponType2
	resMap["coupon_id_3"] = notifyRes.CouponID3
	resMap["coupon_fee_3"] = notifyRes.CouponFee3
	resMap["coupon_type_3"] = notifyRes.CouponType3
	resMap["coupon_id_4"] = notifyRes.CouponID4
	resMap["coupon_fee_4"] = notifyRes.CouponFee4
	resMap["coupon_type_4"] = notifyRes.CouponType4
	resMap["coupon_id_5"] = notifyRes.CouponID5
	resMap["coupon_fee_5"] = notifyRes.CouponFee5
	resMap["coupon_type_5"] = notifyRes.CouponType5
	resMap["device_info"] = notifyRes.DeviceInfo
	resMap["sign_type"] = notifyRes.SignType
	resMap["err_code"] = notifyRes.ErrCode
	resMap["err_code_des"] = notifyRes.ErrCodeDes
	resMap["settlement_total_fee"] = notifyRes.SettlementTotalFee
	// 支付key
	sortedKeys := make([]string, 0, len(resMap))
	for k := range resMap {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	// STEP2, 对key=value的键值对用&连接起来，略过空值
	var signStrings string
	for _, k := range sortedKeys {
		value := fmt.Sprintf("%v", resMap[k])
		if value != "" && value != "0"{
			signStrings = signStrings + k + "=" + value + "&"
		}
	}
	// STEP3, 在键值对的最后加上key=API_KEY
	signStrings = signStrings + "key=" + pcf.PayKey
	// STEP4, 进行MD5签名并且将所有字符转为大写.
	sign := util.MD5Sum(signStrings)
	if sign != notifyRes.Sign {
		return false
	}
	return true
}

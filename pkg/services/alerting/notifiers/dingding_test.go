package notifiers

import (
	"context"
	"testing"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/alerting"
	"github.com/grafana/grafana/pkg/services/encryption/ossencryption"
	"github.com/grafana/grafana/pkg/services/validations"

	"github.com/stretchr/testify/require"
)

func TestDingDingNotifier(t *testing.T) {
	t.Run("empty settings should return error", func(t *testing.T) {
		json := `{ }`

		settingsJSON, _ := simplejson.NewJson([]byte(json))
		model := &models.AlertNotification{
			Name:     "dingding_testing",
			Type:     "dingding",
			Settings: settingsJSON,
		}

		_, err := newDingDingNotifier(model, ossencryption.ProvideService().GetDecryptedValue, nil)
		require.Error(t, err)
	})
	t.Run("settings should trigger incident", func(t *testing.T) {
		json := `{ "url": "https://www.google.com" }`

		settingsJSON, _ := simplejson.NewJson([]byte(json))
		model := &models.AlertNotification{
			Name:     "dingding_testing",
			Type:     "dingding",
			Settings: settingsJSON,
		}

		not, err := newDingDingNotifier(model, ossencryption.ProvideService().GetDecryptedValue, nil)
		notifier := not.(*DingDingNotifier)

		require.Nil(t, err)
		require.Equal(t, "dingding_testing", notifier.Name)
		require.Equal(t, "dingding", notifier.Type)
		require.Equal(t, "https://www.google.com", notifier.URL)

		t.Run("genBody should not panic", func(t *testing.T) {
			evalContext := alerting.NewEvalContext(context.Background(),
				&alerting.Rule{
					State:   models.AlertStateAlerting,
					Message: `{host="localhost"}`,
				}, &validations.OSSPluginRequestValidator{}, nil)
			body, err := notifier.genBody(evalContext, "")
			require.Nil(t, err)
			require.NotContains(t, string(body), "isAtAll")

		})
	})

	t.Run("settings should trigger atAll incident", func(t *testing.T) {
		json := `{ "url": "https://oapi.dingtalk.com/robot/send?access_token=9a301fb9dcfdf16258356e8e149d0ce6b93318eabc97c1b2c09f280355dddea8" }`

		settingsJSON, _ := simplejson.NewJson([]byte(json))
		model := &models.AlertNotification{
			Name:     "dingding_testing",
			Type:     "dingding",
			Settings: settingsJSON,
		}

		not, err := newDingDingNotifier(model, ossencryption.ProvideService().GetDecryptedValue, nil)
		notifier := not.(*DingDingNotifier)

		require.Nil(t, err)

		t.Run("genBody should not panic", func(t *testing.T) {
			var ruleTags []*models.Tag
			ruleTags = append(ruleTags, &models.Tag{Key: "isAtAll", Value: "true"})
			evalContext := alerting.NewEvalContext(context.Background(),
				&alerting.Rule{
					State:         models.AlertStateAlerting,
					Message:       `{host="localhost","content":"alert"}`,
					AlertRuleTags: ruleTags,
				}, &validations.OSSPluginRequestValidator{}, nil)
			body, err := notifier.genBody(evalContext, "")

			require.Nil(t, err)
			require.Contains(t, string(body), "isAtAll")
		})
	})
	t.Run("settings should trigger atAll incident", func(t *testing.T) {
		json := `{ "url": "https://www.google.com" }`

		settingsJSON, _ := simplejson.NewJson([]byte(json))
		model := &models.AlertNotification{
			Name:     "dingding_testing",
			Type:     "dingding",
			Settings: settingsJSON,
		}

		not, err := newDingDingNotifier(model, ossencryption.ProvideService().GetDecryptedValue, nil)
		notifier := not.(*DingDingNotifier)

		require.Nil(t, err)

		t.Run("genBody should not panic", func(t *testing.T) {
			var ruleTags []*models.Tag
			ruleTags = append(ruleTags, &models.Tag{Key: "atMobiles", Value: "12222222,22232112"})

			evalContext := alerting.NewEvalContext(context.Background(),
				&alerting.Rule{
					State:         models.AlertStateAlerting,
					Message:       `{host="localhost","content":"alert"}`,
					AlertRuleTags: ruleTags,
				}, &validations.OSSPluginRequestValidator{}, nil)
			body, err := notifier.genBody(evalContext, "")
			require.Nil(t, err)
			require.Contains(t, string(body), "atMobiles")
			require.Contains(t, string(body), "12222222")
			require.Contains(t, string(body), "22232112")

		})
	})
}

package gothfiberv2

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/session/v2"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

const providerkey key = iota

var (
	// Session is Fiber session
	Session *session.Session
)

type key int

// Params from Fiber Ctx
type Params struct {
	ctx *fiber.Ctx
}

func init() {
	config := session.Config{
		Lookup: "cookie:" + gothic.SessionName,
	}
	Session = session.New(config)
}

// Get from Params
func (p *Params) Get(key string) string {
	return p.ctx.Query(key)
}

// GetContextWithProvider return new Context with provider
func GetContextWithProvider(ctx *fiber.Ctx, provider string) *fiber.Ctx {
	ctx.Context().SetUserValue(string(providerkey), provider)
	return ctx
}

// GetProviderName return provider name from Fiber Context
func GetProviderName(ctx *fiber.Ctx) (string, error) {
	if p := ctx.Query("provider"); p != "" {
		return p, nil
	}

	if p := ctx.Params("provider"); p != "" {
		return p, nil
	}

	if p, ok := ctx.Context().UserValue("provider").(string); ok {
		return p, nil
	}

	if p, ok := ctx.Context().UserValue(string(providerkey)).(string); ok {
		return p, nil
	}

	providers := goth.GetProviders()
	store := Session.Get(ctx)

	for _, provider := range providers {
		p := provider.Name()
		value := store.Get(p)
		if _, ok := value.(string); ok {
			return p, nil
		}
	}

	return "", errors.New("You have to select a provider")
}

// GetState return state from Fiber Context
func GetState(ctx *fiber.Ctx) string {
	return ctx.Query("state")
}

// SetState set state from Query of Fiber
func SetState(ctx *fiber.Ctx) string {
	state := ctx.Query("state")
	if len(state) > 0 {
		return state
	}

	nonceBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("Source of randomness unavailable: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}

func updateSessionValue(store *session.Store, key, value string) (err error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err = gz.Write([]byte(value)); err != nil {
		return fmt.Errorf("updateSessionValue gz.Write error: %s", err)
	}
	if err = gz.Flush(); err != nil {
		return fmt.Errorf("updateSessionValue gz.Flush error: %s", err)
	}
	if err = gz.Close(); err != nil {
		return fmt.Errorf("updateSessionValue gz.Close error %s", err)
	}
	store.Set(key, b.String())
	return nil
}

// StoreInSession save into session valuee by to key
func StoreInSession(key string, value string, ctx *fiber.Ctx) error {
	store := Session.Get(ctx)
	if err := updateSessionValue(store, key, value); err != nil {
		return err
	}
	return store.Save()
}

// Logout destroy session
func Logout(ctx *fiber.Ctx) {
	store := Session.Get(ctx)
	_ = store.Destroy()
}

func getSessionValue(store *session.Store, key string) (string, error) {
	value := store.Get(key)
	if value == nil {
		return "", fmt.Errorf("could not find a matching session for this request")
	}

	rdata := strings.NewReader(value.(string))
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return "", fmt.Errorf("getSessionValue error gzip.NewReader: %s", err)
	}
	s, err := ioutil.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("getSessionValue error ioutil.ReadAll: %s", err)
	}

	return string(s), nil
}

// GetFromSession read value by key from session
func GetFromSession(key string, ctx *fiber.Ctx) (string, error) {
	store := Session.Get(ctx)
	value, err := getSessionValue(store, key)
	if err != nil {
		return "", fmt.Errorf("could not find a matching session for this request")
	}
	return value, nil
}

func validateState(ctx *fiber.Ctx, sess goth.Session) error {
	rawAuthURL, err := sess.GetAuthURL()
	if err != nil {
		return fmt.Errorf("validateState sess.GetAuthURL error: %s", err)
	}

	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		return fmt.Errorf("validateState ur.Parse error: %s", err)
	}

	originalState := authURL.Query().Get("state")
	if originalState != "" && (originalState != ctx.Query("state")) {
		return fmt.Errorf("validateState state token mismatch")
	}

	return nil
}

// CompleteUserAuth return User from Fiber Context
func CompleteUserAuth(ctx *fiber.Ctx) (goth.User, error) {
	defer Logout(ctx)
	if Session == nil {
		return goth.User{}, fmt.Errorf("session_secret environment variable is no set")
	}

	providerName, err := GetProviderName(ctx)
	if err != nil {
		return goth.User{}, err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return goth.User{}, fmt.Errorf("CompleteUserAuth goth.GetProvider error: %s", err)
	}

	value, err := GetFromSession(providerName, ctx)
	if err != nil {
		return goth.User{}, fmt.Errorf("CompleteUserAuth GetFromSession error: %s", err)
	}

	sess, err := provider.UnmarshalSession(value)
	if err != nil {
		return goth.User{}, fmt.Errorf("CompleteUserAuth provider.UnmarshalSession error: %s", err)
	}

	err = validateState(ctx, sess)
	if err != nil {
		return goth.User{}, fmt.Errorf("CompleteUserAuth validateState error: %s", err)
	}

	user, err := provider.FetchUser(sess)
	if err == nil {
		return user, fmt.Errorf("CompleteUserAuth provider.FetchUser error: %s", err)
	}

	_, err = sess.Authorize(provider, &Params{ctx: ctx})
	if err != nil {
		return goth.User{}, fmt.Errorf("CompleteUserAuth sess.Authorize error: %s", err)
	}

	err = StoreInSession(providerName, sess.Marshal(), ctx)
	if err != nil {
		return goth.User{}, fmt.Errorf("CompleteUserAuth StoreInSession error: %s", err)
	}

	gu, err := provider.FetchUser(sess)
	if err != nil {
		return goth.User{}, fmt.Errorf("CompleteUserAuth provider.FetchUser error: %s", err)
	}
	return gu, nil
}

// GetAuthURL return Auth URL from Fiber Context
func GetAuthURL(ctx *fiber.Ctx) (string, error) {
	if Session == nil {
		return "", fmt.Errorf("session_secret environment variable is no set")
	}

	providerName, err := GetProviderName(ctx)
	if err != nil {
		return "", err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", fmt.Errorf("GetAuthURL goth.GetProvider error: %s", err)
	}
	sess, err := provider.BeginAuth(SetState(ctx))
	if err != nil {
		return "", fmt.Errorf("GetAuthURL provider.BeginAuth error: %s", err)
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", fmt.Errorf("GetAuthURL sess.GetAuthURL error: %s", err)
	}

	err = StoreInSession(providerName, sess.Marshal(), ctx)
	if err != nil {
		return "", fmt.Errorf("GetAuthURL StoreInSession error: %s", err)
	}

	return url, nil
}

// BeginAuthHandler start auth
func BeginAuthHandler(ctx *fiber.Ctx) {
	url, err := GetAuthURL(ctx)
	if err != nil {
		ctx.Status(http.StatusBadRequest)
		_ = ctx.Send([]byte(err.Error()))
		return
	}

	_ = ctx.Redirect(url, http.StatusTemporaryRedirect)
}

package glance

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	pageTemplate        = mustParseTemplate("page.html", "document.html", "footer.html")
	pageContentTemplate = mustParseTemplate("page-content.html")
	manifestTemplate    = mustParseTemplate("manifest.json")
)

const STATIC_ASSETS_CACHE_DURATION = 24 * time.Hour

var reservedPageSlugs = []string{"login", "logout"}

type application struct {
	Version   string
	CreatedAt time.Time
	Config    config

	parsedManifest []byte

	slugToPage map[string]*page
	widgetByID map[uint64]widget

	RequiresAuth           bool
	authSecretKey          []byte
	usernameHashToUsername map[string]string
	authAttemptsMu         sync.Mutex
	failedAuthAttempts     map[string]*failedAuthAttempt
	oidcProviders          []OIDCProvider
	processedOIDCStates    sync.Map // map[string]bool, prevents authorization code replay
}

func newApplication(c *config) (*application, error) {
	app := &application{
		Version:    buildVersion,
		CreatedAt:  time.Now(),
		Config:     *c,
		slugToPage: make(map[string]*page),
		widgetByID: make(map[uint64]widget),
	}
	config := &app.Config

	//
	// Init auth
	//

	hasUsers := len(config.Auth.Users) > 0
	hasOIDC := len(config.Auth.OIDCProviders) > 0 || config.Auth.OIDC != nil

	if hasUsers || hasOIDC {
		secretBytes, err := base64.StdEncoding.DecodeString(config.Auth.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("decoding secret-key: %v", err)
		}

		if len(secretBytes) != AUTH_SECRET_KEY_LENGTH {
			return nil, fmt.Errorf("secret-key must be exactly %d bytes", AUTH_SECRET_KEY_LENGTH)
		}

		app.usernameHashToUsername = make(map[string]string)
		app.failedAuthAttempts = make(map[string]*failedAuthAttempt)
		app.RequiresAuth = true
		app.authSecretKey = secretBytes

		// Initialize the users map if nil (needed for OIDC-only setups where
		// ensureOIDCUser adds users at runtime)
		if config.Auth.Users == nil {
			config.Auth.Users = make(map[string]*user)
		}

		for username := range config.Auth.Users {
			user := config.Auth.Users[username]
			usernameHash, err := computeUsernameHash(username, secretBytes)
			if err != nil {
				return nil, fmt.Errorf("computing username hash for user %s: %v", username, err)
			}
			app.usernameHashToUsername[string(usernameHash)] = username

			if user.PasswordHashString != "" {
				user.PasswordHash = []byte(user.PasswordHashString)
				user.PasswordHashString = ""
			} else {
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
				if err != nil {
					return nil, fmt.Errorf("hashing password for user %s: %v", username, err)
				}

				user.Password = ""
				user.PasswordHash = hashedPassword
			}
		}

		// Collect OIDC providers from both oidc and oidc-providers config keys
		var oidcProviders []OIDCProvider
		if config.Auth.OIDC != nil {
			oidcProviders = append(oidcProviders, *config.Auth.OIDC)
		}
		oidcProviders = append(oidcProviders, config.Auth.OIDCProviders...)

		for i := range oidcProviders {
			provider := &oidcProviders[i]
			if err := provider.initOIDCProvider(); err != nil {
				return nil, fmt.Errorf("initializing OIDC provider: %w", err)
			}
			provider.setRedirectURL(config.Server.BaseURL)
		}
		app.oidcProviders = oidcProviders

		// Restore OIDC-created users from before a config reload (important
		// for Kubernetes where ConfigMap mounts trigger spurious reloads).
		app.restoreGlobalOIDCUsers()
	}

	//
	// Init themes
	//

	if !config.Theme.DisablePicker {
		themeKeys := make([]string, 0, 2)
		themeProps := make([]*themeProperties, 0, 2)

		defaultDarkTheme, ok := config.Theme.Presets.Get("default-dark")
		if ok && !config.Theme.SameAs(defaultDarkTheme) || !config.Theme.SameAs(&themeProperties{}) {
			themeKeys = append(themeKeys, "default-dark")
			themeProps = append(themeProps, &themeProperties{})
		}

		themeKeys = append(themeKeys, "default-light")
		themeProps = append(themeProps, &themeProperties{
			Light:                    true,
			BackgroundColor:          &hslColorField{240, 13, 95},
			PrimaryColor:             &hslColorField{230, 100, 30},
			NegativeColor:            &hslColorField{0, 70, 50},
			ContrastMultiplier:       1.3,
			TextSaturationMultiplier: 0.5,
		})

		themePresets, err := newOrderedYAMLMap(themeKeys, themeProps)
		if err != nil {
			return nil, fmt.Errorf("creating theme presets: %v", err)
		}
		config.Theme.Presets = *themePresets.Merge(&config.Theme.Presets)

		for key, properties := range config.Theme.Presets.Items() {
			properties.Key = key
			if err := properties.init(); err != nil {
				return nil, fmt.Errorf("initializing preset theme %s: %v", key, err)
			}
		}
	}

	config.Theme.Key = "default"
	if err := config.Theme.init(); err != nil {
		return nil, fmt.Errorf("initializing default theme: %v", err)
	}

	//
	// Init pages
	//

	app.slugToPage[""] = &config.Pages[0]

	providers := &widgetProviders{
		assetResolver: app.StaticAssetPath,
	}

	for p := range config.Pages {
		page := &config.Pages[p]
		page.PrimaryColumnIndex = -1

		if page.Slug == "" {
			page.Slug = titleToSlug(page.Title)
		}

		if slices.Contains(reservedPageSlugs, page.Slug) {
			return nil, fmt.Errorf("page slug \"%s\" is reserved", page.Slug)
		}

		app.slugToPage[page.Slug] = page

		if page.Width == "default" {
			page.Width = ""
		}

		if page.DesktopNavigationWidth == "" && page.DesktopNavigationWidth != "default" {
			page.DesktopNavigationWidth = page.Width
		}

		for i := range page.HeadWidgets {
			widget := page.HeadWidgets[i]
			app.widgetByID[widget.GetID()] = widget
			widget.setProviders(providers)
		}

		for c := range page.Columns {
			column := &page.Columns[c]

			if page.PrimaryColumnIndex == -1 && column.Size == "full" {
				page.PrimaryColumnIndex = int8(c)
			}

			for w := range column.Widgets {
				widget := column.Widgets[w]
				app.widgetByID[widget.GetID()] = widget
				widget.setProviders(providers)
			}
		}
	}

	config.Server.BaseURL = strings.TrimRight(config.Server.BaseURL, "/")
	config.Theme.CustomCSSFile = app.resolveUserDefinedAssetPath(config.Theme.CustomCSSFile)
	config.Branding.LogoURL = app.resolveUserDefinedAssetPath(config.Branding.LogoURL)

	config.Branding.FaviconURL = ternary(
		config.Branding.FaviconURL == "",
		app.StaticAssetPath("favicon.svg"),
		app.resolveUserDefinedAssetPath(config.Branding.FaviconURL),
	)

	config.Branding.FaviconType = ternary(
		strings.HasSuffix(config.Branding.FaviconURL, ".svg"),
		"image/svg+xml",
		"image/png",
	)

	if config.Branding.AppName == "" {
		config.Branding.AppName = "Glance"
	}

	if config.Branding.AppIconURL == "" {
		config.Branding.AppIconURL = app.StaticAssetPath("app-icon.png")
	}

	if config.Branding.AppBackgroundColor == "" {
		config.Branding.AppBackgroundColor = config.Theme.BackgroundColorAsHex
	}

	manifest, err := executeTemplateToString(manifestTemplate, templateData{App: app})
	if err != nil {
		return nil, fmt.Errorf("parsing manifest.json: %v", err)
	}
	app.parsedManifest = []byte(manifest)

	return app, nil
}

func (p *page) updateOutdatedWidgets() {
	now := time.Now()

	var wg sync.WaitGroup
	ctx := context.Background()

	// Collect all outdated widgets first
	var updates []widget

	for w := range p.HeadWidgets {
		wgt := p.HeadWidgets[w]
		if wgt.requiresUpdate(&now) {
			updates = append(updates, wgt)
		}
	}

	for c := range p.Columns {
		for w := range p.Columns[c].Widgets {
			wgt := p.Columns[c].Widgets[w]
			if wgt.requiresUpdate(&now) {
				updates = append(updates, wgt)
			}
		}
	}

	// Launch updates with a small stagger to avoid hammering rate-limited hosts
	for i, u := range updates {
		wg.Add(1)
		go func(w widget, idx int) {
			defer wg.Done()
			// 50ms stagger between launches — spreads 70 requests over ~3.5s
			if idx > 0 {
				time.Sleep(time.Duration(idx) * 50 * time.Millisecond)
			}
			w.update(ctx)
		}(u, i)
	}

	wg.Wait()
}

func (a *application) resolveUserDefinedAssetPath(path string) string {
	if strings.HasPrefix(path, "/assets/") {
		return a.Config.Server.BaseURL + path
	}

	return path
}

type templateRequestData struct {
	Theme *themeProperties
}

type templateData struct {
	App           *application
	Page          *page
	Request       templateRequestData
	OIDCProviders []OIDCProvider
	RedirectTo    string
	LoginError    string
}

func (a *application) populateTemplateRequestData(data *templateRequestData, r *http.Request) {
	theme := &a.Config.Theme.themeProperties

	if !a.Config.Theme.DisablePicker {
		selectedTheme, err := r.Cookie("theme")
		if err == nil {
			preset, exists := a.Config.Theme.Presets.Get(selectedTheme.Value)
			if exists {
				theme = preset
			}
		}
	}

	data.Theme = theme
}

func (a *application) handlePageRequest(w http.ResponseWriter, r *http.Request) {
	page, exists := a.slugToPage[r.PathValue("page")]
	if !exists {
		a.handleNotFound(w, r)
		return
	}

	if a.handleUnauthorizedResponse(w, r, redirectToLogin) {
		return
	}

	data := templateData{
		Page: page,
		App:  a,
	}
	a.populateTemplateRequestData(&data.Request, r)

	var responseBytes bytes.Buffer
	err := pageTemplate.Execute(&responseBytes, data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.Write(responseBytes.Bytes())
}

func (a *application) handlePageContentRequest(w http.ResponseWriter, r *http.Request) {
	page, exists := a.slugToPage[r.PathValue("page")]
	if !exists {
		a.handleNotFound(w, r)
		return
	}

	if a.handleUnauthorizedResponse(w, r, showUnauthorizedJSON) {
		return
	}

	pageData := templateData{
		Page: page,
	}

	var err error
	var responseBytes bytes.Buffer

	func() {
		page.mu.Lock()
		defer page.mu.Unlock()

		page.updateOutdatedWidgets()
		err = pageContentTemplate.Execute(&responseBytes, pageData)
	}()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.Write(responseBytes.Bytes())
}

func (a *application) addressOfRequest(r *http.Request) string {
	remoteAddrWithoutPort := func() string {
		for i := len(r.RemoteAddr) - 1; i >= 0; i-- {
			if r.RemoteAddr[i] == ':' {
				return r.RemoteAddr[:i]
			}
		}

		return r.RemoteAddr
	}

	if !a.Config.Server.Proxied {
		return remoteAddrWithoutPort()
	}

	// This should probably be configurable or look for multiple headers, not just this one
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor == "" {
		return remoteAddrWithoutPort()
	}

	ips := strings.Split(forwardedFor, ",")
	if len(ips) == 0 || ips[0] == "" {
		return remoteAddrWithoutPort()
	}

	return ips[0]
}

func (a *application) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	// TODO: add proper not found page
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Page not found"))
}

func (a *application) handleWidgetRequest(w http.ResponseWriter, r *http.Request) {
	// TODO: this requires a rework of the widget update logic so that rather
	// than locking the entire page we lock individual widgets
	w.WriteHeader(http.StatusNotImplemented)

	// widgetValue := r.PathValue("widget")

	// widgetID, err := strconv.ParseUint(widgetValue, 10, 64)
	// if err != nil {
	// 	a.handleNotFound(w, r)
	// 	return
	// }

	// widget, exists := a.widgetByID[widgetID]

	// if !exists {
	// 	a.handleNotFound(w, r)
	// 	return
	// }

	// widget.handleRequest(w, r)
}

func (a *application) StaticAssetPath(asset string) string {
	return a.Config.Server.BaseURL + "/static/" + staticFSHash + "/" + asset
}

func (a *application) VersionedAssetPath(asset string) string {
	return a.Config.Server.BaseURL + asset +
		"?v=" + strconv.FormatInt(a.CreatedAt.Unix(), 10)
}

func (a *application) server() (func() error, func() error) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", a.handlePageRequest)
	mux.HandleFunc("GET /{page}", a.handlePageRequest)

	mux.HandleFunc("GET /api/pages/{page}/content/{$}", a.handlePageContentRequest)

	if !a.Config.Theme.DisablePicker {
		mux.HandleFunc("POST /api/set-theme/{key}", a.handleThemeChangeRequest)
	}

	mux.HandleFunc("/api/widgets/{widget}/{path...}", a.handleWidgetRequest)
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if a.RequiresAuth {
		mux.HandleFunc("GET /login", a.handleLoginPageRequest)
		mux.HandleFunc("GET /logout", a.handleLogoutRequest)
		mux.HandleFunc("POST /api/authenticate", a.handleAuthenticationAttempt)

		// OIDC routes
		if len(a.oidcProviders) > 0 {
			mux.HandleFunc("GET /api/oidc/login/{provider}", a.handleOIDCLogin)
			mux.HandleFunc("GET /api/oidc/callback/{provider}", a.handleOIDCCallback)
		}
	}

	mux.Handle(
		fmt.Sprintf("GET /static/%s/{path...}", staticFSHash),
		http.StripPrefix(
			"/static/"+staticFSHash,
			fileServerWithCache(http.FS(staticFS), STATIC_ASSETS_CACHE_DURATION),
		),
	)

	assetCacheControlValue := fmt.Sprintf(
		"public, max-age=%d",
		int(STATIC_ASSETS_CACHE_DURATION.Seconds()),
	)

	mux.HandleFunc(fmt.Sprintf("GET /static/%s/css/bundle.css", staticFSHash), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", assetCacheControlValue)
		w.Header().Add("Content-Type", "text/css; charset=utf-8")
		w.Write(bundledCSSContents)
	})

	mux.HandleFunc("GET /manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", assetCacheControlValue)
		w.Header().Add("Content-Type", "application/json")
		w.Write(a.parsedManifest)
	})

	var absAssetsPath string
	if a.Config.Server.AssetsPath != "" {
		absAssetsPath, _ = filepath.Abs(a.Config.Server.AssetsPath)
		assetsFS := fileServerWithCache(http.Dir(a.Config.Server.AssetsPath), 2*time.Hour)
		mux.Handle("/assets/{path...}", http.StripPrefix("/assets/", assetsFS))
	}

	server := http.Server{
		Addr:    fmt.Sprintf("%s:%d", a.Config.Server.Host, a.Config.Server.Port),
		Handler: mux,
	}

	start := func() error {
		log.Printf("Starting server on %s:%d (base-url: \"%s\", assets-path: \"%s\")\n",
			a.Config.Server.Host,
			a.Config.Server.Port,
			a.Config.Server.BaseURL,
			absAssetsPath,
		)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}

		return nil
	}

	stop := func() error {
		return server.Close()
	}

	return start, stop
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/didip/tollbooth_echo"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
)

//To make global db access possible
//Could be implemented with closures
var db2 *gorm.DB
var db4 *gorm.DB

type Product struct {
	gorm.Model
	UID                   string
	NameA                 string
	NameB                 string
	Comment               string
	BtcBetrag             string
	BtcAdressA            string
	BtcAdressAausgezahlt  bool `gorm:"default:false"`
	BtcAdressEscrow       string
	BtcAdressEscrowFunded bool `gorm:"default:false"`
	URLPanel              string
	URLB                  string
	URLBFrei              string
	URLBFreiGenerated     bool `gorm:"default:false"`
	TradeReleasedB        bool `gorm:"default:false"`
	TradeEscaledB         bool `gorm:"default:false"`
}

//Todo is astruct to hold data
type Todo struct {
	UserPanel        string
	UserPanels       string
	Tradestatus      string
	TradeStatusColor string
	Empfname         string
	Empfadresse      string
	Zahlpf           string
	Ubfrei           string
	Ubfrei2          string
}

//TodoPageData is a struc that helps
type TodoPageData struct {
	Todos []Todo
	Empty string
}

type Template struct {
	templates *template.Template
}

type Settings struct {
	gorm.Model
	AdminPass          string
	AdminUser          string
	BlockchainUser     string
	BlockchainPassword string
	Multi              float64
}

func HashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), 4)
	return string(bytes)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//validates btc adress
func validateBTCa(tx string) bool {
	url := "http://codacoin.com/api/public.php?request=validate&address=" + tx
	response, _ := http.Get(url)
	defer response.Body.Close()
	c, _ := ioutil.ReadAll(response.Body)
	t := strings.TrimSpace(string(c))
	if t == "Valid" {
		return true
	}
	return false

}

//hashthis reuturns hash as string
func hashthis(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	b := h.Sum(nil)
	return hex.EncodeToString(b)
}

//returns new generated BTC adress
func getNewAdressBTC(label string, UID string, pwd string) string {
	response, err := http.Get("http://localhost:3000/merchant/" + UID +
		"/new_address?password=" + pwd + "&label=" + label)
	if err != nil {
		return "False"
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "False"
	}
	value := gjson.Get(string(contents), "address")
	return value.String()
}

//returns converted satoshi to btc of adress
func getBalanceBTC(adress string, UID string, pwd string) string {
	response, err := http.Get("http://localhost:3000/merchant/" + UID +
		"/address_balance?password=" + pwd + "&address=" + adress)
	if err != nil {
		return "False"
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "False"
	}
	value := gjson.Get(string(contents), "balance")
	bf, _ := strconv.ParseFloat(value.String(), 64)
	bff := 0.00000001 * bf
	bfff := strconv.FormatFloat(bff, 'f', 8, 64)
	return bfff
}

//sends satoshi to btc adress
func payAdressBTC(UID string, pwd string, outAdr string, amount string) string {
	bf, _ := strconv.ParseFloat(amount, 64)
	bff := int(bf * 100000000)
	bfff := strconv.Itoa(bff)
	url := "http://localhost:3000/merchant/" + UID + "/payment?password=" + pwd + "&to=" + outAdr + "&amount=" + bfff
	response, err := http.Get(url)
	if err != nil {
		return "False"
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "False"
	}
	suc := gjson.Get(string(contents), "success").Bool()
	if suc == true {
		return "True"
	}
	return "False"
}

//Render executes the template and returns it
func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func InDex(c echo.Context) error {
	return c.Render(http.StatusOK, "forms.html", map[string]interface{}{})
}

func GenIndex(c echo.Context) error {
	//map to render
	fview := map[string]interface{}{}
	withouterror := true

	//parsing of betrag
	formValueBetrag := c.FormValue("betrag")
	if formValueBetrag == "" || len(formValueBetrag) > 50 {
		fview["FORM1_WARN"] = "This field must be filled in."
		fview["FORM1_WARN_d"] = "is-danger"
		fview["FORM1_WARN_ca"] = "fas fa-exclamation-triangle"
		withouterror = false
	}
	betrag, err := strconv.ParseFloat(formValueBetrag, 64)
	if err != nil || betrag < 0.00001 {
		fview["FORM1_WARN"] = "Incorrect amount!"
		fview["FORM1_WARN_d"] = "is-danger"
		fview["FORM1_WARN_ca"] = "fas fa-exclamation-triangle"
		withouterror = false
	} else {
		fview["FORM1_WARN_ca"] = "fas fa-check"
		fview["FORM1_WARN_d"] = "is-success"
		fview["FORM1_WARN_d_v"] = formValueBetrag
	}

	//parsing of address
	formValueAdress := c.FormValue("adress")
	if formValueAdress == "" || len(formValueAdress) > 40 {
		fview["FORM2_WARN"] = "Please enter a Bitcoin address!"
		fview["FORM2_WARN_d"] = "is-danger"
		fview["FORM2_WARN_ca"] = "fas fa-exclamation-triangle"
		withouterror = false
	}
	if m, _ := regexp.MatchString("^([13][a-km-zA-HJ-NP-Z1-9]{25,34})", formValueAdress); !m {
		fview["FORM2_WARN"] = "Not a valid address!"
		fview["FORM2_WARN_d"] = "is-danger"
		fview["FORM2_WARN_ca"] = "fas fa-exclamation-triangle"
		withouterror = false
	} else {
		if validateBTCa(formValueAdress) != true {
			fview["FORM2_WARN"] = "Not a valid address!"
			fview["FORM2_WARN_d"] = "is-danger"
			fview["FORM2_WARN_ca"] = "fas fa-exclamation-triangle"
			withouterror = false
		} else {
			fview["FORM2_WARN_ca"] = "fas fa-check"
			fview["FORM2_WARN_d"] = "is-success"
			fview["FORM2_WARN_d_v"] = formValueAdress
		}
	}

	//parsing of empf
	formValueEmpf := c.FormValue("empf")
	if formValueEmpf == "" || len(formValueEmpf) > 100 || formValueEmpf == "Diddy" {
		fview["FORM3_WARN"] = "Creditor is missing!"
		fview["FORM3_WARN_d"] = "is-danger"
		fview["FORM3_WARN_ca"] = "fas fa-exclamation-triangle"
		withouterror = false
	} else {
		fview["FORM3_WARN_ca"] = "fas fa-check"
		fview["FORM3_WARN_d"] = "is-success"
		fview["FORM3_WARN_d_v"] = formValueEmpf

	}
	//parsing of zahl
	formValueZahl := c.FormValue("zahl")
	if formValueZahl == "" || len(formValueZahl) > 100 || formValueZahl == "Diddy" {
		fview["FORM4_WARN"] = "Debtor missing!"
		fview["FORM4_WARN_d"] = "is-danger"
		fview["FORM4_WARN_ca"] = "fas fa-exclamation-triangle"
		withouterror = false
	} else {
		fview["FORM4_WARN_ca"] = "fas fa-check"
		fview["FORM4_WARN_d"] = "is-success"
		fview["FORM4_WARN_d_v"] = formValueZahl
	}

	//parsing of com
	formValueCom := c.FormValue("comment")
	if formValueCom == "" || len(formValueCom) > 1000 || len(formValueCom) < 10 {
		fview["FORM5_WARN"] = "Please revise conditions!"
		fview["FORM5_WARN_d]"] = "is-danger"
		withouterror = false
	} else {
		fview["FORM5_WARN_d"] = "is-success"
		fview["FORM5_WARN_d_v"] = formValueCom
	}
	if withouterror == false {
		return c.Render(http.StatusOK, "forms.html", fview)
	}
	fview2 := map[string]interface{}{}
	fview2["BETRAG"] = formValueBetrag
	fview2["ADRESS"] = formValueAdress
	fview2["EMPF"] = formValueEmpf
	fview2["ZAHL"] = formValueZahl
	fview2["CO"] = formValueCom
	return c.Render(http.StatusOK, "sum.html", fview2)
}

func GenFinal(c echo.Context) error {
	b := c.FormValue("betrag")
	a := c.FormValue("adress")
	e := c.FormValue("empf")
	z := c.FormValue("zahl")
	co := c.FormValue("co")

	//this should make it faster
	c1 := make(chan string, 1)
	c3 := make(chan string, 1)
	go func() {
		unid := xid.New().String()
		c1 <- unid
		c1 <- hashthis(unid)
	}()
	go func() {
		c3 <- hashthis(xid.New().String())
	}()

	unid2 := <-c1
	panelid := <-c1
	u2 := <-c3
	bf, _ := strconv.ParseFloat(b, 64)
	user := Settings{}
	db4.First(&user)
	bff := bf * user.Multi
	bfff := strconv.FormatFloat(bff, 'f', 8, 64)
	thbtcad := getNewAdressBTC(unid2, user.BlockchainUser, user.BlockchainPassword)
	if thbtcad == "False" {
		return c.String(http.StatusOK, "Error: Could not generate address.")
	}
	db2.Create(&Product{UID: unid2, NameA: e, NameB: z, Comment: co,
		BtcBetrag: bfff, BtcAdressA: a, URLPanel: panelid, URLB: u2, BtcAdressEscrow: thbtcad})
	r := c.Request()
	currentURL := c.Scheme() + "://" + r.Host
	fview := map[string]interface{}{}
	fview["TRANSURL"] = currentURL + "/trans/" + panelid
	fview["ZAHLURL"] = currentURL + "/ub/" + u2
	return c.Render(http.StatusOK, "final.html", fview)
}

func transPanel(c echo.Context) error {
	fview := map[string]interface{}{}
	// User ID from path `users/:id`
	id := c.Param("id")
	// Read
	var product Product
	db2.Where("url_panel = ?", id).First(&product)
	if len(product.URLPanel) < 10 {
		fview["MESS"] = "URL not found!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if product.TradeReleasedB == true && product.BtcAdressEscrowFunded == true {
		fview["MESS"] = "The escrow has already been finalised!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}

	fview["BETRAG"] = product.BtcBetrag
	fview["TREUAD"] = product.BtcAdressEscrow
	if product.BtcAdressEscrowFunded == false {
		user := Settings{}
		db4.First(&user)

		//ba := getBalanceBTC(string(product.BtcAdressEscrow), user.AdminUser, user.BlockchainPassword)
		ba := getBalanceBTC(product.BtcAdressEscrow, user.BlockchainUser, user.BlockchainPassword)
		if ba != "False" {
			fmt.Println(product.BtcAdressEscrow, ba)
			if ba >= product.BtcBetrag {
				db2.Model(&product).Update("BtcAdressEscrowFunded", true)
			}
		}
	}
	if product.BtcAdressEscrowFunded == true {
		fview["TREUADSTAT"] = "Funded"
		fview["TREUADSTAT_f"] = "green"
	} else {
		fview["TREUADSTAT"] = "Unfunded"
		fview["TREUADSTAT_f"] = "red"
	}
	fview["STATTRANS"] = "Open"
	fview["STATTRANS_f"] = "yellow"
	if product.TradeReleasedB == true {
		fview["STATTRANS"] = "Released"
		fview["STATTRANS_f"] = "green"
	}
	if product.TradeEscaledB == true {
		fview["STATTRANS"] = "Escalated"
		fview["STATTRANS_f"] = "red"
	}
	if product.URLBFreiGenerated == true {
		fview["ZAHLGEN"] = "Yes"
		fview["ZAHLGEN_f"] = "green"
	} else {
		fview["ZAHLGEN"] = "No"
		fview["ZAHLGEN_f"] = "red"
	}
	fview["EMPF"] = product.NameA
	fview["ZAHL"] = product.NameB
	fview["CO"] = product.Comment
	return c.Render(http.StatusOK, "trans.html", fview)
}

func userbPanel(c echo.Context) error {
	fview := map[string]interface{}{}
	// User ID from path `users/:id`
	id := c.Param("id")
	// Read
	var product Product
	db2.Where("url_b = ?", id).First(&product)
	if len(product.URLB) < 10 {
		fview["MESS"] = "URL not found!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if product.URLBFreiGenerated == true {
		fview["MESS"] = "URL has already been used!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	fview["CURL"] = id
	return c.Render(http.StatusOK, "userb.html", fview)

}

func userbPanelGen(c echo.Context) error {
	fview := map[string]interface{}{}
	b := c.FormValue("curl")
	var product Product
	db2.Where("url_b = ?", b).First(&product)
	if len(product.URLB) < 10 {
		fview["MESS"] = "URL not found!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if product.URLBFreiGenerated == true {
		fview["MESS"] = "URL has already been used!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	flink := hashthis(xid.New().String())
	r := c.Request()
	currentURL := c.Scheme() + "://" + r.Host // r.URL.pathy
	fview["TRANSURL"] = currentURL + "/ub/release/" + flink
	db2.Model(&product).Update("URLBFrei", flink)
	db2.Model(&product).Update("URLBFreiGenerated", true)
	return c.Render(http.StatusOK, "userbf.html", fview)
}

func userbPanelRelease(c echo.Context) error {
	fview := map[string]interface{}{}
	// User ID from path `users/:id`
	id := c.Param("id")
	// Read
	var product Product
	db2.Where("url_b_frei = ?", id).First(&product)
	if len(product.URLBFrei) < 10 {
		fview["MESS"] = "URL not found!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if product.TradeReleasedB == true {
		fview["MESS"] = "Escrow has already been released!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	fview["CURL"] = id
	return c.Render(http.StatusOK, "ff.html", fview)

}

func userbPanelReleaseFinal(c echo.Context) error {
	fview := map[string]interface{}{}
	id := c.FormValue("curl")
	fmt.Println("dsfdf")
	var product Product
	db2.Where("url_b_frei = ?", id).First(&product)
	if len(product.URLBFrei) < 10 {
		fview["MESS"] = "URL not found!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if product.TradeReleasedB == true {
		fview["MESS"] = "Escrow has already been released!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if product.BtcAdressEscrowFunded == false && c.FormValue("es") == "false" {
		fview["MESS"] = "Escrow cannot be released if no money has been deposited yet!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if product.BtcAdressEscrowFunded == false && c.FormValue("es") == "true" {
		fview["MESS"] = "Escrow cannot be escalated if no money has been deposited yet!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	be := c.FormValue("be")
	if be == "true" {
		user := Settings{}
		db4.First(&user)
		//b := payAdressBTC(user.BlockchainUser, user.BlockchainPassword, product.BtcAdressA, product.BtcBetrag)
		fmt.Println(user.BlockchainUser, user.BlockchainPassword, product.BtcAdressA, product.BtcBetrag)
		b := "True"
		if b == "True" {
			db2.Model(&product).Update("BtcAdressAausgezahlt", true)
			fview["MESS"] = "Thank you very much, the escrow has been released."
			db2.Model(&product).Update("TradeReleasedB", true)
			return c.Render(http.StatusOK, "mess.html", fview)
		}
		fview["MESS"] = "Can not be paid out please contact the admin or try again!"
		return c.Render(http.StatusOK, "mess.html", fview)

	}
	es := c.FormValue("es")
	if es == "true" {
		db2.Model(&product).Update("TradeEscaledB", true)
		fview["MESS"] = "The Escrow has been escalated!"
		return c.Render(http.StatusOK, "mess.html", fview)

	}
	fview["MESS"] = "Error"
	return c.Render(http.StatusOK, "mess.html", fview)

}

func adminuserbPanelReleaseFinal(c echo.Context) error {
	fview := map[string]interface{}{}
	id := c.Param("id")
	var product Product
	db2.Where("url_b_frei = ?", id).First(&product)
	if len(product.URLBFrei) < 10 {
		fview["MESS"] = "URL not found!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if product.TradeReleasedB == true {
		fview["MESS"] = "Escrow has already been released!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	fview["MESS"] = "The escrow has been terminated."
	db2.Model(&product).Update("TradeReleasedB", true)
	db2.Model(&product).Update("BtcAdressEscrowFunded", true)
	return c.Render(http.StatusOK, "mess.html", fview)

}

func adminPanel(c echo.Context) error {
	r := c.Request()
	currentURL := c.Scheme() + "://" + r.Host // r.URL.pathy
	p := []Product{}
	db2.Where("trade_escaled_b = ?", true).Find(&p)
	s := []Todo{}
	for _, v := range p {
		if v.TradeReleasedB == false {
			tro := "Escalated"
			trof := "red"
			item1 := Todo{UserPanel: currentURL + "/trans/" + v.URLPanel, UserPanels: v.URLPanel[:15], Tradestatus: tro, TradeStatusColor: trof,
				Empfname: v.NameA, Empfadresse: v.BtcAdressA, Ubfrei2: currentURL + "/admin/tb/" + v.URLBFrei,
				Zahlpf: v.NameB, Ubfrei: currentURL + "/ub/release/" + v.URLBFrei}
			s = append(s, item1)
		}
	}
	var m string
	if len(s) < 1 {
		m = "No escalated escrow pending."
	}
	data := TodoPageData{
		Empty: m,
		Todos: s,
	}
	fmt.Println(data)
	return c.Render(http.StatusOK, "admin.html", data)
}

func adminPanelSettings(c echo.Context) error {
	fview := map[string]interface{}{}
	user := Settings{}
	db4.First(&user)
	fview["BlockchainUser"] = user.BlockchainUser
	fview["BlockchainPassword"] = user.BlockchainPassword
	fview["Multi"] = user.Multi
	return c.Render(http.StatusOK, "settings.html", fview)

}

func adminPanelSettingsChange(c echo.Context) error {
	fview := map[string]interface{}{}
	u := c.FormValue("uname")
	p := c.FormValue("pwd")
	bu := c.FormValue("buname")
	bp := c.FormValue("bpwd")
	mul := c.FormValue("multi")
	if len(u) > 0 && len(p) > 0 {
		user := Settings{}
		db4.First(&user)
		user.AdminUser = HashPassword(u)
		user.AdminPass = HashPassword(p)
		db4.Save(&user)
		fview["MESS"] = "The data has been updated!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if len(bu) > 0 && len(bp) > 0 {
		user := Settings{}
		db4.First(&user)
		user.BlockchainUser = bu
		user.BlockchainPassword = bp
		db4.Save(&user)
		fview["MESS"] = "The data has been updated!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	if len(mul) > 0 {
		user := Settings{}
		db4.First(&user)
		mul2, _ := strconv.ParseFloat(mul, 64)
		user.Multi = mul2
		db4.Save(&user)
		fview["MESS"] = "The data has been updated!"
		return c.Render(http.StatusOK, "mess.html", fview)
	}
	return c.Render(http.StatusOK, "settings.html", fview)

}

func main() {
	db, err := gorm.Open("sqlite3", "escrow.db")
	db2 = db
	if err != nil {
		panic("failed to connect database")
	}
	// Migrate the schema
	db2.AutoMigrate(&Product{})
	defer db.Close()

	db3, err := gorm.Open("sqlite3", "settings.db")
	db4 = db3
	if err != nil {
		panic("failed to connect database")
	}
	// Migrate the schema
	db3.AutoMigrate(&Settings{})
	ss := Settings{AdminUser: HashPassword("Admin"), AdminPass: HashPassword("Admin"),
		BlockchainUser:     "Please enter UID",
		BlockchainPassword: "Please enter your password", Multi: 0.5}
	db3.Create(&ss)
	defer db3.Close()

	t := &Template{
		templates: template.Must(template.ParseGlob("static/*.html")),
	}

	// Create a request limitier to prevent flooding.
	lmt := tollbooth.NewLimiter(3, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	lmtAdmin := tollbooth.NewLimiter(2, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})

	// Set a custom message.
	lmt.SetMessage("You have reached maximum request limit.")
	lmtAdmin.SetMessage("You have reached maximum request limit.")

	e := echo.New()

	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.BodyLimit("1M"))
	e.Use(middleware.Secure())
	e.Use(middleware.Gzip())
	e.Static("/", "assets")

	e.Renderer = t //register templates t

	e.GET("/", InDex, tollbooth_echo.LimitHandler(lmt))
	e.POST("/gen", GenIndex, tollbooth_echo.LimitHandler(lmt))
	e.POST("/gen/final", GenFinal, tollbooth_echo.LimitHandler(lmt))
	e.GET("/trans/:id", transPanel, tollbooth_echo.LimitHandler(lmt))
	e.GET("/ub/:id", userbPanel, tollbooth_echo.LimitHandler(lmt))
	e.POST("/ub/gen", userbPanelGen, tollbooth_echo.LimitHandler(lmt))
	e.GET("/ub/release/:id", userbPanelRelease, tollbooth_echo.LimitHandler(lmt))
	e.POST("/ub/release/final", userbPanelReleaseFinal, tollbooth_echo.LimitHandler(lmt))

	// Group level middleware for Admin Panel
	g := e.Group("/admin", tollbooth_echo.LimitHandler(lmtAdmin))
	g.Use(middleware.RemoveTrailingSlash())
	g.Use(middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
		user := Settings{}
		db4.First(&user)
		if CheckPasswordHash(username, user.AdminUser) && CheckPasswordHash(password, user.AdminPass) {
			return true, nil
		}
		return false, nil
	}))

	g.GET("", adminPanel)
	g.GET("/settings", adminPanelSettings)
	g.POST("/settings/change", adminPanelSettingsChange)
	g.GET("/tb/:id", adminuserbPanelReleaseFinal)

	e.Start(":80") //Change here the port of the webapp
}

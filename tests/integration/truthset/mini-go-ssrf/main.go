// Mini Gin SSRF corpus — intentionally vulnerable.
// Never deploy this code.

package main

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// VULN: SSRF — URL parameter passed directly to http.Get without validation.
	r.GET("/fetch", FetchURL)
	r.POST("/webhook", TriggerWebhook)

	r.Run(":8080")
}

// FetchURL fetches an arbitrary URL supplied by the user — SSRF.
func FetchURL(c *gin.Context) {
	// BUG: attacker can supply url=http://169.254.169.254/latest/meta-data/
	url := c.Query("url")
	resp, err := http.Get(url) // nosemgrep — intentionally vulnerable
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	c.Data(200, "text/plain", body)
}

// TriggerWebhook makes a POST to a user-supplied endpoint — SSRF.
func TriggerWebhook(c *gin.Context) {
	var req struct {
		CallbackURL string `json:"callback_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// BUG: no allowlist check on callback_url.
	resp, err := http.Post(req.CallbackURL, "application/json", nil)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	c.JSON(200, gin.H{"status": resp.Status})
}

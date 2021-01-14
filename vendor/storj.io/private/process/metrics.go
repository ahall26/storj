// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package process

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"

	monkit "github.com/spacemonkeygo/monkit/v3"
	"github.com/spacemonkeygo/monkit/v3/environment"
	"github.com/zeebo/admission/v3/admproto"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"storj.io/common/identity"
	"storj.io/common/telemetry"
	"storj.io/private/cfgstruct"
	"storj.io/private/version"
)

var (
	metricInterval       = flag.Duration("metrics.interval", telemetry.DefaultInterval, "how frequently to send up telemetry")
	metricCollector      = flag.String("metrics.addr", flagDefault("", "collectora.storj.io:9000"), "address(es) to send telemetry to (comma-separated)")
	metricApp            = flag.String("metrics.app", filepath.Base(os.Args[0]), "application name for telemetry identification")
	metricAppSuffix      = flag.String("metrics.app-suffix", flagDefault("-dev", "-release"), "application suffix")
	metricInstancePrefix = flag.String("metrics.instance-prefix", "", "instance id prefix")
)

const (
	maxInstanceLength = 52
)

var (
	hardcodedAppName string
	clients          []*telemetry.Client
)

// SetHardcodedApplicationName configures telemetry to use the given application
// name, followed by -dev/-release depending on build settings, instead of
// os.Args[0]. Disables configuration of metrics.app and metrics.app-suffix.
func SetHardcodedApplicationName(name string) {
	hardcodedAppName = name
}

func flagDefault(dev, release string) string {
	if cfgstruct.DefaultsType() == "release" {
		return release
	}
	return dev
}

// InitMetrics initializes telemetry reporting. Makes a telemetry.Client and calls
// its Run() method in a goroutine.
func InitMetrics(ctx context.Context, log *zap.Logger, r *monkit.Registry, instanceID string) (err error) {
	if r == nil {
		r = monkit.Default
	}
	environment.Register(r)
	r.ScopeNamed("env").Chain(monkit.StatSourceFunc(version.Build.Stats))

	if *metricCollector == "" || *metricInterval == 0 {
		log.Debug("Telemetry disabled")
		return nil
	}

	if instanceID == "" {
		instanceID = telemetry.DefaultInstanceID()
	}
	instanceID = *metricInstancePrefix + instanceID
	if len(instanceID) > maxInstanceLength {
		instanceID = instanceID[:maxInstanceLength]
	}

	log.Info("Telemetry enabled", zap.String("instance ID", instanceID))

	appName := hardcodedAppName
	if appName != "" {
		appName += flagDefault("-dev", "-release")
	} else {
		appName = *metricApp + *metricAppSuffix
	}

	for _, address := range strings.Split(*metricCollector, ",") {
		c, err := telemetry.NewClient(address, telemetry.ClientOpts{
			Interval:      *metricInterval,
			Application:   appName,
			Instance:      instanceID,
			Registry:      r,
			FloatEncoding: admproto.Float32Encoding,
		})
		if err != nil {
			return err
		}
		clients = append(clients, c)
		go c.Run(ctx)
	}
	return nil
}

// InitMetricsWithCertPath initializes telemetry reporting, using the node ID
// corresponding to the given certificate as the telemetry instance ID.
func InitMetricsWithCertPath(ctx context.Context, log *zap.Logger, r *monkit.Registry, certPath string) error {
	var metricsID string
	nodeID, err := identity.NodeIDFromCertPath(certPath)
	if err != nil {
		log.Error("Could not read identity for telemetry setup", zap.Error(err))
		metricsID = "" // InitMetrics() will fill in a default value
	} else {
		metricsID = nodeID.String()
	}
	return InitMetrics(ctx, log, r, metricsID)
}

// InitMetricsWithHostname initializes telemetry reporting, using the hostname as the telemetry instance ID.
func InitMetricsWithHostname(ctx context.Context, log *zap.Logger, r *monkit.Registry) error {
	var metricsID string
	hostname, err := os.Hostname()
	if err != nil {
		log.Error("Could not read hostname for telemetry setup", zap.Error(err))
		metricsID = "" // InitMetrics() will fill in a default value
	} else {
		metricsID = strings.ReplaceAll(hostname, ".", "_")
	}
	return InitMetrics(ctx, log, r, metricsID)
}

// Report triggers each telemetry client to send data to its collection endpoint.
func Report(ctx context.Context) error {
	var group errgroup.Group
	for _, c := range clients {
		c := c
		group.Go(func() error {
			return c.Report(ctx)
		})
	}
	return group.Wait()
}

package mitm

import (
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type timeFunc func() time.Time

func timeNow() time.Time {
	return time.Now().In(time.FixedZone("+08", 8*60*60))
}

// setupBatsignal enables the prometheus metrics which display the bat insignia
// on the time series graph
func setupBatsignal() {
	promauto.NewUntypedFunc(prometheus.UntypedOpts{
		Name: "batsignal_top",
		Help: "Top of the batsignal",
	}, batsignalTop(timeNow))
	promauto.NewUntypedFunc(prometheus.UntypedOpts{
		Name: "batsignal_bottom",
		Help: "Bottom of the batsignal",
	}, batsignalBottom(timeNow))
}

// Taking the time returned by tf as an x value zeroed to midday, calculates
// the positive y value of the Batman function.
// https://www.pacifict.com/Examples/Batman/
func batsignalTop(tf timeFunc) func() float64 {
	return func() float64 {
		now := tf()
		switch x := float64(now.Hour()) + float64(now.Minute())/60 - 12; {
		case x > -7 && x < -3:
			fallthrough
		case x > 3 && x < 7:
			return math.Sqrt(1-math.Pow(x/7, 2)) * 3 // nolint: staticcheck
		case x >= -3 && x < -1:
			fallthrough
		case x > 1 && x <= 3:
			return 6*math.Sqrt(10)/7 - 0.5*math.Abs(x) + 1.5 -
				(3*math.Sqrt(10)/7)*math.Sqrt(4-math.Pow(math.Abs(x)-1, 2)) // nolint: staticcheck
		case x >= -1 && x < -0.75:
			fallthrough
		case x > 0.75 && x <= 1:
			return 9 - 8*math.Abs(x)
		case x >= -0.75 && x < -0.5:
			fallthrough
		case x > 0.5 && x <= 0.75:
			return 3*math.Abs(x) + 0.75
		case x >= -0.5 && x <= 0.5:
			return 2.25
		default:
			return 0
		}
	}
}

// Taking the time returned by tf as an x value zeroed to midday, calculates
// the negative y value of the Batman function.
// https://www.pacifict.com/Examples/Batman/
func batsignalBottom(tf timeFunc) func() float64 {
	return func() float64 {
		now := tf()
		switch x := float64(now.Hour()) + float64(now.Minute())/60 - 12; {
		case x > -7 && x < -4:
			fallthrough
		case x > 4 && x < 7:
			return -math.Sqrt(1-math.Pow(x/7, 2)) * 3 // nolint: staticcheck
		case x >= -4 && x <= 4:
			return math.Abs(x/2) - (3*math.Sqrt(33)-7)/112*(x*x) - 3 +
				math.Sqrt(1-math.Pow(math.Abs(math.Abs(x)-2)-1, 2)) // nolint: staticcheck
		default:
			return 0
		}
	}
}

// batsignal takes data assumed to be an outbound packet. If it is a metrics
// packet, it mutates the metrics values of the data in order to draw the
// Batman function on the SEMS portal plot.
// On any kind of error, it returns the original data.
func batsignal(metrics *OutboundMeterMetricsPacket) ([]byte, error) {
	metrics.PowerGenerationWatts = int32(1000 * batsignalTop(timeNow)())
	metrics.PowerExportWatts = int32(1000 * batsignalBottom(timeNow)())
	return metrics.MarshalBinary()
}

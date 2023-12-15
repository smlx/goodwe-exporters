package mitm

import (
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// define inverter metrics
	inverterVoltageInputDCDecivolts = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_input_voltage_dc_decivolts",
		Help: "Input DC voltage to inverter.",
	}, labelNames)
	inverterCurrentInputDCDeciamps = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_input_current_dc_deciamps",
		Help: "Input DC current to inverter.",
	}, labelNames)
	inverterVoltageOutputACDecivolts = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_output_voltage_ac_decivolts",
		Help: "Output AC voltage from inverter.",
	}, labelNames)
	inverterCurrentOutputACDeciamps = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_output_current_ac_deciamps",
		Help: "Output AC current from inverter.",
	}, labelNames)
	inverterFrequencyOutputACCentihertz = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_output_frequency_ac_centihertz",
		Help: "Output AC frequency from inverter.",
	}, labelNames)
	inverterPowerOutputWatts = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_power_output_watts",
		Help: "Power output from inverter.",
	}, labelNames)
	inverterInternalTemperatureDecidegreesCelsius = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_internal_temperature_decidegrees_celsius",
		Help: "Internal temperature of inverter.",
	}, labelNames)
	inverterEnergyOutputHectowattHoursToday = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_energy_output_hectowatt_hours_day",
		Help: "Cumulative energy output today.",
	}, labelNames)
	inverterEnergyOutputHectowattHoursTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_energy_output_hectowatt_hours_total",
		Help: "Cumulative energy output total.",
	}, labelNames)
	inverterUptimeHoursTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_uptime_hours_total",
		Help: "Inverter total operation time.",
	}, labelNames)
	inverterRSSIPercent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_rssi_percent",
		Help: "Inverter WLAN received signal strength indicator.",
	}, labelNames)
	// exporter internal metrics
	inverterTimeSyncPacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "inverter_time_sync_packets_total",
		Help: "Count of outbound time sync packets.",
	}, labelNames)
	inverterMetricsPacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "inverter_metrics_packets_total",
		Help: "Count of outbound metrics packets.",
	}, labelNames)
	// unknown values
	inverterUnknownInt0 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_0",
	}, labelNames)
	inverterUnknownInt1 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_1",
	}, labelNames)
	inverterUnknownInt2 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_2",
	}, labelNames)
	inverterUnknownInt3 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_3",
	}, labelNames)
	inverterUnknownInt4 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_4",
	}, labelNames)
	inverterUnknownInt5 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_5",
	}, labelNames)
	inverterUnknownInt7 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_7",
	}, labelNames)
	inverterUnknownInt8 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_8",
	}, labelNames)
	inverterUnknownInt9 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_9",
	}, labelNames)
	inverterUnknownInt10 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_10",
	}, labelNames)
	inverterUnknownInt11 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_11",
	}, labelNames)
	inverterUnknownInt12 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_12",
	}, labelNames)
	inverterUnknownInt13 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_13",
	}, labelNames)
	inverterUnknownInt14 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_14",
	}, labelNames)
	inverterUnknownInt15 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_15",
	}, labelNames)
	inverterUnknownInt16 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_16",
	}, labelNames)
	inverterUnknownInt17 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_17",
	}, labelNames)
	inverterUnknownInt18 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_18",
	}, labelNames)
	inverterUnknownInt19 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_19",
	}, labelNames)
	inverterUnknownInt20 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_20",
	}, labelNames)
	inverterUnknownInt21 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_21",
	}, labelNames)
	inverterUnknownInt22 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_22",
	}, labelNames)
	inverterUnknownInt23 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_23",
	}, labelNames)
	inverterUnknownInt24 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_24",
	}, labelNames)
	inverterUnknownInt25 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_25",
	}, labelNames)
	inverterUnknownInt26 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_26",
	}, labelNames)
	inverterUnknownInt27 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_27",
	}, labelNames)
	inverterUnknownInt28 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_28",
	}, labelNames)
	inverterUnknownInt29 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_29",
	}, labelNames)
	inverterUnknownInt30 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_30",
	}, labelNames)
	inverterUnknownInt31 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_31",
	}, labelNames)
	inverterUnknownInt32 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_32",
	}, labelNames)
	inverterUnknownInt33 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_33",
	}, labelNames)
	inverterUnknownInt34 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_34",
	}, labelNames)
	inverterUnknownInt35 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_35",
	}, labelNames)
	inverterUnknownInt36 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_36",
	}, labelNames)
	inverterUnknownInt37 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_37",
	}, labelNames)
	inverterUnknownInt38 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_38",
	}, labelNames)
	inverterUnknownInt39 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_39",
	}, labelNames)
	inverterUnknownInt40 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_40",
	}, labelNames)
	inverterUnknownInt41 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_41",
	}, labelNames)
	inverterUnknownInt42 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_42",
	}, labelNames)
	inverterUnknownInt43 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_43",
	}, labelNames)
	inverterUnknownInt44 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_44",
	}, labelNames)
	inverterUnknownInt45 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_45",
	}, labelNames)
	inverterUnknownInt46 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_46",
	}, labelNames)
	inverterUnknownInt47 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_47",
	}, labelNames)
	inverterUnknownInt48 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_48",
	}, labelNames)
	inverterUnknownInt49 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_49",
	}, labelNames)
	inverterUnknownInt50 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_50",
	}, labelNames)
	inverterUnknownInt51 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "inverter_unknown_int_51",
	}, labelNames)
)

// handleInverterMetrics0Packet handles metrics packet envelope and ciphertext.
func handleInverterMetrics0Packet(
	data []byte,
	log *slog.Logger,
) error {
	var metrics OutboundInverterMetrics0Packet
	err := metrics.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("couldn't unmarshal metrics: %v", err)
	}
	di, ok := deviceInfo[metrics.DeviceID]
	if !ok {
		return fmt.Errorf("unknown device ID: %v", metrics.DeviceID)
	}
	log.Debug("outbound metrics",
		slog.String("device", di[0]),
		slog.String("model", di[1]),
		slog.String("serial", string(metrics.DeviceSerial[:])))
	labels := prometheus.Labels{
		"device": di[0],
		"model":  di[1],
		"serial": string(metrics.DeviceSerial[:]),
	}
	// record metrics
	inverterVoltageInputDCDecivolts.With(labels).Set(
		float64(metrics.VoltageInputDCDecivolts))
	inverterCurrentInputDCDeciamps.With(labels).Set(
		float64(metrics.CurrentInputDCDeciamps))
	inverterVoltageOutputACDecivolts.With(labels).Set(
		float64(metrics.VoltageOutputACDecivolts))
	inverterCurrentOutputACDeciamps.With(labels).Set(
		float64(metrics.CurrentOutputACDeciamps))
	inverterFrequencyOutputACCentihertz.With(labels).Set(
		float64(metrics.FrequencyOutputACCentihertz))
	inverterPowerOutputWatts.With(labels).Set(
		float64(metrics.PowerOutputWatts))
	inverterInternalTemperatureDecidegreesCelsius.With(labels).Set(
		float64(metrics.InternalTemperatureDecidegreesCelsius))
	inverterEnergyOutputHectowattHoursToday.With(labels).Set(
		float64(metrics.EnergyOutputHectowattHoursToday))
	inverterEnergyOutputHectowattHoursTotal.With(labels).Set(
		float64(metrics.EnergyOutputHectowattHoursTotal))
	inverterUptimeHoursTotal.With(labels).Set(
		float64(metrics.UptimeHoursTotal))
	inverterRSSIPercent.With(labels).Set(
		float64(metrics.RSSIPercent))
	// record internal metrics
	inverterMetricsPacketsTotal.With(labels).Inc()
	// record unknown values
	inverterUnknownInt0.With(labels).Set(float64(metrics.UnknownInt0))
	inverterUnknownInt1.With(labels).Set(float64(metrics.UnknownInt1))
	inverterUnknownInt2.With(labels).Set(float64(metrics.UnknownInt2))
	inverterUnknownInt3.With(labels).Set(float64(metrics.UnknownInt3))
	inverterUnknownInt4.With(labels).Set(float64(metrics.UnknownInt4))
	inverterUnknownInt5.With(labels).Set(float64(metrics.UnknownInt5))
	inverterUnknownInt7.With(labels).Set(float64(metrics.UnknownInt7))
	inverterUnknownInt8.With(labels).Set(float64(metrics.UnknownInt8))
	inverterUnknownInt9.With(labels).Set(float64(metrics.UnknownInt9))
	inverterUnknownInt10.With(labels).Set(float64(metrics.UnknownInt10))
	inverterUnknownInt11.With(labels).Set(float64(metrics.UnknownInt11))
	inverterUnknownInt12.With(labels).Set(float64(metrics.UnknownInt12))
	inverterUnknownInt13.With(labels).Set(float64(metrics.UnknownInt13))
	inverterUnknownInt14.With(labels).Set(float64(metrics.UnknownInt14))
	inverterUnknownInt15.With(labels).Set(float64(metrics.UnknownInt15))
	inverterUnknownInt16.With(labels).Set(float64(metrics.UnknownInt16))
	inverterUnknownInt17.With(labels).Set(float64(metrics.UnknownInt17))
	inverterUnknownInt18.With(labels).Set(float64(metrics.UnknownInt18))
	inverterUnknownInt19.With(labels).Set(float64(metrics.UnknownInt19))
	inverterUnknownInt20.With(labels).Set(float64(metrics.UnknownInt20))
	inverterUnknownInt21.With(labels).Set(float64(metrics.UnknownInt21))
	inverterUnknownInt22.With(labels).Set(float64(metrics.UnknownInt22))
	inverterUnknownInt23.With(labels).Set(float64(metrics.UnknownInt23))
	inverterUnknownInt24.With(labels).Set(float64(metrics.UnknownInt24))
	inverterUnknownInt25.With(labels).Set(float64(metrics.UnknownInt25))
	inverterUnknownInt26.With(labels).Set(float64(metrics.UnknownInt26))
	inverterUnknownInt27.With(labels).Set(float64(metrics.UnknownInt27))
	inverterUnknownInt28.With(labels).Set(float64(metrics.UnknownInt28))
	inverterUnknownInt29.With(labels).Set(float64(metrics.UnknownInt29))
	inverterUnknownInt30.With(labels).Set(float64(metrics.UnknownInt30))
	inverterUnknownInt31.With(labels).Set(float64(metrics.UnknownInt31))
	inverterUnknownInt32.With(labels).Set(float64(metrics.UnknownInt32))
	inverterUnknownInt33.With(labels).Set(float64(metrics.UnknownInt33))
	inverterUnknownInt34.With(labels).Set(float64(metrics.UnknownInt34))
	inverterUnknownInt35.With(labels).Set(float64(metrics.UnknownInt35))
	inverterUnknownInt36.With(labels).Set(float64(metrics.UnknownInt36))
	inverterUnknownInt37.With(labels).Set(float64(metrics.UnknownInt37))
	inverterUnknownInt38.With(labels).Set(float64(metrics.UnknownInt38))
	inverterUnknownInt39.With(labels).Set(float64(metrics.UnknownInt39))
	inverterUnknownInt40.With(labels).Set(float64(metrics.UnknownInt40))
	inverterUnknownInt41.With(labels).Set(float64(metrics.UnknownInt41))
	inverterUnknownInt42.With(labels).Set(float64(metrics.UnknownInt42))
	inverterUnknownInt43.With(labels).Set(float64(metrics.UnknownInt43))
	inverterUnknownInt44.With(labels).Set(float64(metrics.UnknownInt44))
	inverterUnknownInt45.With(labels).Set(float64(metrics.UnknownInt45))
	inverterUnknownInt46.With(labels).Set(float64(metrics.UnknownInt46))
	inverterUnknownInt47.With(labels).Set(float64(metrics.UnknownInt47))
	inverterUnknownInt48.With(labels).Set(float64(metrics.UnknownInt48))
	inverterUnknownInt49.With(labels).Set(float64(metrics.UnknownInt49))
	inverterUnknownInt50.With(labels).Set(float64(metrics.UnknownInt50))
	inverterUnknownInt51.With(labels).Set(float64(metrics.UnknownInt51))
	return nil
}

// handleInverterMetrics1Packet handles metrics packet envelope and ciphertext.
func handleInverterMetrics1Packet(
	data []byte,
	log *slog.Logger,
) error {
	var metrics OutboundInverterMetrics1Packet
	err := metrics.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("couldn't unmarshal metrics: %v", err)
	}
	di, ok := deviceInfo[metrics.DeviceID]
	if !ok {
		return fmt.Errorf("unknown device ID: %v", metrics.DeviceID)
	}
	log.Debug("outbound metrics",
		slog.String("device", di[0]),
		slog.String("model", di[1]),
		slog.String("serial", string(metrics.DeviceSerial[:])))
	labels := prometheus.Labels{
		"device": di[0],
		"model":  di[1],
		"serial": string(metrics.DeviceSerial[:]),
	}
	// record metrics
	inverterVoltageInputDCDecivolts.With(labels).Set(
		float64(metrics.VoltageInputDCDecivolts))
	inverterCurrentInputDCDeciamps.With(labels).Set(
		float64(metrics.CurrentInputDCDeciamps))
	inverterVoltageOutputACDecivolts.With(labels).Set(
		float64(metrics.VoltageOutputACDecivolts))
	inverterCurrentOutputACDeciamps.With(labels).Set(
		float64(metrics.CurrentOutputACDeciamps))
	inverterFrequencyOutputACCentihertz.With(labels).Set(
		float64(metrics.FrequencyOutputACCentihertz))
	inverterPowerOutputWatts.With(labels).Set(
		float64(metrics.PowerOutputWatts))
	inverterEnergyOutputHectowattHoursToday.With(labels).Set(
		float64(metrics.EnergyOutputHectowattHoursToday))
	inverterEnergyOutputHectowattHoursTotal.With(labels).Set(
		float64(metrics.EnergyOutputHectowattHoursTotal))
	inverterUptimeHoursTotal.With(labels).Set(
		float64(metrics.UptimeHoursTotal))
	inverterRSSIPercent.With(labels).Set(
		float64(metrics.RSSIPercent))
	// record internal metrics
	inverterMetricsPacketsTotal.With(labels).Inc()
	return nil
}

// handleInverterTimeSyncPacket handles time sync request packets.
func handleInverterTimeSyncPacket(
	data []byte,
	log *slog.Logger,
) error {
	var timeSync OutboundInverterTimeSyncPacket
	err := timeSync.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("couldn't unmarshal metrics: %v", err)
	}
	di, ok := deviceInfo[timeSync.DeviceID]
	if !ok {
		return fmt.Errorf("unknown device ID: %v", timeSync.DeviceID)
	}
	log.Debug("outbound metrics",
		slog.String("device", di[0]),
		slog.String("model", di[1]),
		slog.String("serial", string(timeSync.DeviceSerial[:])))
	inverterTimeSyncPacketsTotal.With(prometheus.Labels{
		"device": di[0],
		"model":  di[1],
		"serial": string(timeSync.DeviceSerial[:]),
	}).Inc()
	return nil
}

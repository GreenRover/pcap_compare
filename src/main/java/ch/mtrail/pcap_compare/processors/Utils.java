package ch.mtrail.pcap_compare.processors;

import java.text.NumberFormat;
import java.util.Locale;

public class Utils {
	public static NumberFormat getNumberFormatter() {
		Locale locale = new Locale("de", "CH");
		return NumberFormat.getInstance(locale);
	}
}

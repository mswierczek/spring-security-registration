package org.baeldung.service;

import com.google.common.base.Strings;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import org.apache.commons.collections4.CollectionUtils;
import org.baeldung.persistence.dao.DeviceMetadataRepository;
import org.baeldung.persistence.model.DeviceMetadata;
import org.baeldung.persistence.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import ua_parser.Client;
import ua_parser.Parser;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import static java.util.Objects.nonNull;

@Component
public class DeviceService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DeviceService.class);

    private static final String UNKNOWN = "UNKNOWN";

    private final String from;

    private final DatabaseReader databaseReader;

    private final DeviceMetadataRepository deviceMetadataRepository;

    private final JavaMailSender mailSender;

    private final MessageSource messages;

    private final Parser parser;

    private final boolean sendNewLoginNotification;

    private final List<String> unknownLocationIpAdresses;

    public DeviceService(@Value("#{'${device-service.unknown-location-ip-adresses}'.split(',')}") List<String> unknownLocationIpAdresses,
                         @Value("${support.email}") String from,
                         @Value("${device-service.send-new-login-notification}") boolean sendNewLoginNotification,
                         DeviceMetadataRepository deviceMetadataRepository,
                         DatabaseReader databaseReader,
                         Parser parser,
                         JavaMailSender mailSender,
                         MessageSource messages) {
        this.unknownLocationIpAdresses = unknownLocationIpAdresses;
        this.from = from;
        this.sendNewLoginNotification = sendNewLoginNotification;
        this.deviceMetadataRepository = deviceMetadataRepository;
        this.databaseReader = databaseReader;
        this.parser = parser;
        this.mailSender = mailSender;
        this.messages = messages;
    }

    public void verifyDevice(User user, HttpServletRequest request) throws IOException, GeoIp2Exception {

        String ip = extractIp(request);
        String location = getIpLocation(ip);

        String deviceDetails = getDeviceDetails(request.getHeader("user-agent"));

        DeviceMetadata existingDevice = findExistingDevice(user.getId(), deviceDetails, location);

        if (Objects.isNull(existingDevice)) {
            unknownDeviceNotification(deviceDetails, location, ip, user.getEmail(), request.getLocale());

            DeviceMetadata deviceMetadata = new DeviceMetadata();
            deviceMetadata.setUserId(user.getId());
            deviceMetadata.setLocation(location);
            deviceMetadata.setDeviceDetails(deviceDetails);
            deviceMetadata.setLastLoggedIn(new Date());
            deviceMetadataRepository.save(deviceMetadata);
        } else {
            existingDevice.setLastLoggedIn(new Date());
            deviceMetadataRepository.save(existingDevice);
        }

    }

    private String extractIp(HttpServletRequest request) {
        String clientIp;
        String clientXForwardedForIp = request.getHeader("x-forwarded-for");
        if (nonNull(clientXForwardedForIp)) {
            clientIp = parseXForwardedHeader(clientXForwardedForIp);
        } else {
            clientIp = request.getRemoteAddr();
        }

        return clientIp;
    }

    private String parseXForwardedHeader(String header) {
        return header.split(" *, *")[0];
    }

    private String getDeviceDetails(String userAgent) {
        String deviceDetails = UNKNOWN;

        Client client = parser.parse(userAgent);
        if (Objects.nonNull(client)) {
            deviceDetails = client.userAgent.family + " " + client.userAgent.major + "." + client.userAgent.minor +
                    " - " + client.os.family + " " + client.os.major + "." + client.os.minor;
        }

        return deviceDetails;
    }

    private String getIpLocation(String ip) throws IOException, GeoIp2Exception {
        String location = UNKNOWN;
        boolean isIpWithUnknownLocation = CollectionUtils.isNotEmpty(unknownLocationIpAdresses) && unknownLocationIpAdresses.contains(ip);
        if (!isIpWithUnknownLocation) {
            InetAddress ipAddress = InetAddress.getByName(ip);
            CityResponse cityResponse = databaseReader.city(ipAddress);
            if (Objects.nonNull(cityResponse) &&
                Objects.nonNull(cityResponse.getCity()) &&
                !Strings.isNullOrEmpty(cityResponse.getCity().getName())) {
                location = cityResponse.getCity().getName();
            }
        }
        return location;
    }

    private DeviceMetadata findExistingDevice(Long userId, String deviceDetails, String location) {

        List<DeviceMetadata> knownDevices = deviceMetadataRepository.findByUserId(userId);

        for (DeviceMetadata existingDevice : knownDevices) {
            if (existingDevice.getDeviceDetails().equals(deviceDetails) &&
                    existingDevice.getLocation().equals(location)) {
                return existingDevice;
            }
        }

        return null;
    }

    private void unknownDeviceNotification(String deviceDetails, String location, String ip, String email, Locale locale) {
        if (!sendNewLoginNotification) {
            LOGGER.info("Sending email notification on unknown device detection is off");
            return;
        }

        final String subject = "New Login Notification";
        final SimpleMailMessage notification = new SimpleMailMessage();
        notification.setTo(email);
        notification.setSubject(subject);

        String text = messages
                .getMessage("message.login.notification.deviceDetails", null, locale) +
                " " + deviceDetails +
                "\n" +
                messages
                        .getMessage("message.login.notification.location", null, locale) +
                " " + location +
                "\n" +
                messages
                        .getMessage("message.login.notification.ip", null, locale) +
                " " + ip;

        notification.setText(text);
        notification.setFrom(from);

        mailSender.send(notification);
    }

}

import { useState, useEffect, useMemo, useRef } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Circle, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

import { api } from '../services/api';
import styles from './ThreatInfrastructureMap.module.css';

/**
 * Controller helper to manage center-on-threat and fit-radius actions
 */
function MapController({ center, zoom, centerCounter, fitCounter, radiusMeters }) {
  const map = useMap();

  // Invalidate map size on initial mount to ensure tiles render fully
  useEffect(() => {
    if (!map) return;
    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 200);
    return () => clearTimeout(timer);
  }, [map]);

  // Center on threat
  useEffect(() => {
    if (!map || !center || centerCounter === 0) return;
    map.flyTo(center, zoom, { duration: 1.0 });
  }, [map, center, zoom, centerCounter]);

  // Fit bounds to radius
  useEffect(() => {
    if (!map || !center || fitCounter === 0) return;
    if (radiusMeters && radiusMeters > 0) {
      const latDelta = radiusMeters / 111320;
      const cosLat = Math.cos((center[0] * Math.PI) / 180) || 1;
      const lngDelta = radiusMeters / (111320 * cosLat);
      const bounds = [
        [center[0] - latDelta, center[1] - lngDelta],
        [center[0] + latDelta, center[1] + lngDelta],
      ];
      map.fitBounds(bounds, { padding: [35, 35], maxZoom: 13 });
    } else {
      map.flyTo(center, zoom, { duration: 1.0 });
    }
  }, [map, center, zoom, fitCounter, radiusMeters]);

  return null;
}

export default function ThreatInfrastructureMap({
  location = null,
  scanId = null,
  height = '420px',
  compact = false,
  theme = 'default',
}) {
  const [fetchedLocation, setFetchedLocation] = useState(null);
  const [loading, setLoading] = useState(Boolean(!location && scanId));
  const [error, setError] = useState(null);
  const [centerCounter, setCenterCounter] = useState(0);
  const [fitCounter, setFitCounter] = useState(0);
  const markerRef = useRef(null);

  const isGuardian = theme === 'guardian';

  // Fetch threat location if scanId is provided and location prop is not
  useEffect(() => {
    let isMounted = true;

    if (!location && scanId) {
      Promise.resolve().then(async () => {
        if (!isMounted) return;
        setLoading(true);
        setError(null);
        try {
          const res = await api.getThreatLocations(scanId);
          if (!isMounted) return;
          const locs = res?.locations || [];
          // Pick the first location with valid coordinates and SUCCESS lookup
          const validLoc = locs.find(
            (l) => l.latitude != null && l.longitude != null && l.lookup_status === 'SUCCESS'
          ) || locs[0] || null;
          setFetchedLocation(validLoc);
        } catch (err) {
          if (!isMounted) return;
          console.warn('Threat location fetch note:', err.message);
          setError('Threat location could not be loaded. The security scan result is still available.');
        } finally {
          if (isMounted) setLoading(false);
        }
      });
    }

    return () => {
      isMounted = false;
    };
  }, [location, scanId]);

  // Determine active location object
  const activeLocation = useMemo(() => {
    if (location) {
      if (Array.isArray(location)) {
        return location.find(
          (l) => l.latitude != null && l.longitude != null && l.lookup_status === 'SUCCESS'
        ) || location[0] || null;
      }
      return location;
    }
    return fetchedLocation;
  }, [location, fetchedLocation]);

  // SVG Security Shield Threat Marker Icon
  const threatIcon = useMemo(() => {
    return L.divIcon({
      className: styles.threatMarkerPin,
      html: `
        <div class="${styles.markerPulseRing}"></div>
        <div class="${styles.markerCoreDot}">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <circle cx="12" cy="16" r="0.8" fill="currentColor"/>
          </svg>
        </div>
      `,
      iconSize: [36, 36],
      iconAnchor: [18, 18],
      popupAnchor: [0, -18],
    });
  }, []);

  // Loading state
  if (loading) {
    return (
      <div className={`${styles.stateBox} ${styles.loadingBox}`}>
        <div className={styles.spinner}></div>
        <span>Loading threat infrastructure location…</span>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className={`${styles.stateBox} ${styles.errorBox}`}>
        <span>⚠ {error}</span>
      </div>
    );
  }

  // No location or invalid coordinates
  const hasCoordinates =
    activeLocation &&
    activeLocation.latitude != null &&
    activeLocation.longitude != null &&
    (!activeLocation.lookup_status || activeLocation.lookup_status === 'SUCCESS' || activeLocation.available);

  if (!hasCoordinates) {
    return (
      <div className={`${styles.stateBox} ${styles.unavailableBox}`}>
        <span>ℹ Threat infrastructure location is unavailable for this record.</span>
      </div>
    );
  }

  const {
    domain,
    ip_address,
    city,
    region,
    country,
    latitude,
    longitude,
    accuracy_radius,
    isp,
    organization,
    asn,
    location_source,
  } = activeLocation;

  const centerPos = [Number(latitude), Number(longitude)];
  const radiusMeters = accuracy_radius != null && Number(accuracy_radius) > 0
    ? Number(accuracy_radius) * 1000
    : null;

  const locationSummary = [city, region, country].filter(Boolean).join(', ') || 'Unknown Network Region';
  const networkSummary = [isp, organization].filter(Boolean).join(' / ') || 'Network Provider Unspecified';

  return (
    <div className={`${styles.mapContainerCard} ${isGuardian ? styles.mapContainerCardGuardian : ''}`}>
      {/* Header Bar */}
      <div className={`${styles.headerRow} ${isGuardian ? styles.headerRowGuardian : ''}`}>
        <div className={styles.titleArea}>
          <span className={styles.shieldIcon}>🌐</span>
          <span className={`${styles.titleText} ${isGuardian ? styles.titleTextGuardian : ''}`}>
            Threat Infrastructure Location
          </span>
          <span className={styles.statusBadge}>
            APPROXIMATE IP LOCATION
          </span>
        </div>

        <div className={styles.controlsGroup}>
          <button
            type="button"
            className={`${styles.mapButton} ${isGuardian ? styles.mapButtonGuardian : ''}`}
            onClick={() => setCenterCounter((c) => c + 1)}
            title="Recenter map on threat infrastructure"
          >
            🎯 Center on Threat
          </button>
          {radiusMeters && (
            <button
              type="button"
              className={`${styles.mapButton} ${isGuardian ? styles.mapButtonGuardian : ''}`}
              onClick={() => setFitCounter((c) => c + 1)}
              title="Fit map view to accuracy radius bounds"
            >
              ⤢ Fit Radius
            </button>
          )}
        </div>
      </div>

      {/* Map Host Canvas */}
      <div className={styles.leafletHostWrapper} style={{ height }}>
        <MapContainer
          center={centerPos}
          zoom={11}
          scrollWheelZoom={false}
          style={{ width: '100%', height: '100%' }}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            maxZoom={18}
          />

          {/* Accuracy Radius Circle if available */}
          {radiusMeters && (
            <Circle
              center={centerPos}
              radius={radiusMeters}
              pathOptions={{
                color: isGuardian ? '#14b8a6' : '#ef4444',
                fillColor: isGuardian ? '#14b8a6' : '#ef4444',
                fillOpacity: 0.14,
                weight: 1.5,
                dashArray: '5, 5',
              }}
            />
          )}

          {/* Threat Infrastructure Marker */}
          <Marker
            ref={markerRef}
            position={centerPos}
            icon={threatIcon}
          >
            <Popup>
              <div className={styles.popupContent}>
                <div className={styles.popupTitle}>
                  <span>🚨</span> Threat Infrastructure
                </div>
                {domain && (
                  <div className={styles.popupRow}>
                    <span className={styles.popupLabel}>Domain: </span>
                    <span className={styles.popupValue}>{domain}</span>
                  </div>
                )}
                {ip_address && (
                  <div className={styles.popupRow}>
                    <span className={styles.popupLabel}>IP Address: </span>
                    <span className={styles.popupValue}>{ip_address}</span>
                  </div>
                )}
                <div className={styles.popupRow}>
                  <span className={styles.popupLabel}>Location: </span>
                  <span className={styles.popupValue}>{locationSummary}</span>
                </div>
                {isp && (
                  <div className={styles.popupRow}>
                    <span className={styles.popupLabel}>ISP: </span>
                    <span className={styles.popupValue}>{isp}</span>
                  </div>
                )}
                {organization && (
                  <div className={styles.popupRow}>
                    <span className={styles.popupLabel}>Organization: </span>
                    <span className={styles.popupValue}>{organization}</span>
                  </div>
                )}
                {asn && (
                  <div className={styles.popupRow}>
                    <span className={styles.popupLabel}>ASN: </span>
                    <span className={styles.popupValue}>{asn}</span>
                  </div>
                )}
                <div className={styles.popupRow}>
                  <span className={styles.popupLabel}>Location Source: </span>
                  <span className={styles.popupValue}>{location_source || 'IP-API'}</span>
                </div>
              </div>
            </Popup>
          </Marker>

          <MapController
            center={centerPos}
            zoom={11}
            centerCounter={centerCounter}
            fitCounter={fitCounter}
            radiusMeters={radiusMeters}
          />
        </MapContainer>
      </div>

      {/* Details Grid */}
      {!compact && (
        <div className={`${styles.infoGrid} ${isGuardian ? styles.infoGridGuardian : ''}`}>
          <div className={styles.infoItem}>
            <span className={`${styles.infoItemLabel} ${isGuardian ? styles.infoItemLabelGuardian : ''}`}>
              Detected Near
            </span>
            <span className={`${styles.infoItemValue} ${isGuardian ? styles.infoItemValueGuardian : ''}`}>
              {locationSummary}
            </span>
            <span className={styles.infoItemSub}>
              {latitude.toFixed(4)}°, {longitude.toFixed(4)}°
            </span>
          </div>

          <div className={styles.infoItem}>
            <span className={`${styles.infoItemLabel} ${isGuardian ? styles.infoItemLabelGuardian : ''}`}>
              Public IP Address
            </span>
            <span className={`${styles.infoItemValue} ${isGuardian ? styles.infoItemValueGuardian : ''}`}>
              {ip_address || 'Unresolved'}
            </span>
            {domain && <span className={styles.infoItemSub}>{domain}</span>}
          </div>

          <div className={styles.infoItem}>
            <span className={`${styles.infoItemLabel} ${isGuardian ? styles.infoItemLabelGuardian : ''}`}>
              Network Infrastructure
            </span>
            <span className={`${styles.infoItemValue} ${isGuardian ? styles.infoItemValueGuardian : ''}`}>
              {networkSummary}
            </span>
            {asn && <span className={styles.infoItemSub}>Autonomous System: {asn}</span>}
          </div>

          <div className={styles.infoItem}>
            <span className={`${styles.infoItemLabel} ${isGuardian ? styles.infoItemLabelGuardian : ''}`}>
              Accuracy Radius
            </span>
            <span className={`${styles.infoItemValue} ${isGuardian ? styles.infoItemValueGuardian : ''}`}>
              {radiusMeters ? `~${accuracy_radius} km` : 'Accuracy radius unavailable.'}
            </span>
            <span className={styles.infoItemSub}>
              Source: {location_source || 'IP-API'}
            </span>
          </div>
        </div>
      )}

      {/* Strict Accuracy & Legal Disclaimer */}
      <div className={`${styles.disclaimerBox} ${isGuardian ? styles.disclaimerBoxGuardian : ''}`}>
        <span className={styles.disclaimerIcon}>ℹ</span>
        <span>
          Approximate threat infrastructure location based on the public IP associated with the suspicious destination. This may represent hosting, CDN, VPN, proxy, or ISP infrastructure and does not identify the physical location of an individual.
        </span>
      </div>
    </div>
  );
}

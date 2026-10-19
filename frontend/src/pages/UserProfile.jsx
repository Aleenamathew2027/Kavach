import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import UserLayout from '../components/UserLayout';
import styles from './UserProfile.module.css';

const NAME_REGEX = /^[a-zA-Z\s.'-]+$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function UserProfile() {
  const navigate = useNavigate();
  const [userProfile, setUserProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [bannerMsg, setBannerMsg] = useState({ text: '', type: '' });

  // Edit Profile Modal state
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState({ full_name: '', email: '' });
  const [editErrors, setEditErrors] = useState({});
  const [editLoading, setEditLoading] = useState(false);

  // Change Password Modal state
  const [pwdOpen, setPwdOpen] = useState(false);
  const [pwdForm, setPwdForm] = useState({ current_password: '', new_password: '', confirm_password: '' });
  const [pwdErrors, setPwdErrors] = useState({});
  const [pwdLoading, setPwdLoading] = useState(false);

  useEffect(() => {
    async function loadProfile() {
      setLoading(true);
      try {
        const data = await api.getMe();
        setUserProfile(data);
        setEditForm({ full_name: data.full_name, email: data.email });
      } catch (err) {
        console.error('Failed to load profile:', err);
      } finally {
        setLoading(false);
      }
    }
    loadProfile();
  }, []);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const showBanner = (text, type = 'success') => {
    setBannerMsg({ text, type });
    setTimeout(() => setBannerMsg({ text: '', type: '' }), 4000);
  };

  /* ── Edit Profile Handler ── */
  const handleEditSubmit = async (e) => {
    e.preventDefault();
    const errors = {};

    const nameTrimmed = editForm.full_name.trim();
    if (!nameTrimmed) {
      errors.full_name = 'Full name is required.';
    } else if (nameTrimmed.length < 2) {
      errors.full_name = 'Full name must be at least 2 characters long.';
    } else if (!NAME_REGEX.test(nameTrimmed)) {
      errors.full_name = 'Full name must contain only letters and spaces (no numbers or symbols like @, #, $, !).';
    }

    const emailTrimmed = editForm.email.trim();
    if (!emailTrimmed) {
      errors.email = 'Email address is required.';
    } else if (!EMAIL_REGEX.test(emailTrimmed)) {
      errors.email = 'Please enter a valid email address.';
    }

    if (Object.keys(errors).length > 0) {
      setEditErrors(errors);
      return;
    }

    setEditLoading(true);
    setEditErrors({});

    try {
      const updated = await api.updateProfile({
        full_name: nameTrimmed,
        email: emailTrimmed.toLowerCase(),
      });
      setUserProfile(updated);
      setEditOpen(false);
      showBanner('Profile updated successfully.', 'success');
    } catch (err) {
      setEditErrors({ general: err.message || 'Failed to update profile. Please try again.' });
    } finally {
      setEditLoading(false);
    }
  };

  /* ── Change Password Handler ── */
  const handlePwdSubmit = async (e) => {
    e.preventDefault();
    const errors = {};

    if (!pwdForm.current_password) {
      errors.current_password = 'Current password is required.';
    }
    if (!pwdForm.new_password) {
      errors.new_password = 'New password is required.';
    } else if (pwdForm.new_password.length < 6) {
      errors.new_password = 'New password must be at least 6 characters long.';
    }
    if (!pwdForm.confirm_password) {
      errors.confirm_password = 'Password confirmation is required.';
    } else if (pwdForm.new_password !== pwdForm.confirm_password) {
      errors.confirm_password = 'New password and confirmation do not match.';
    }

    if (Object.keys(errors).length > 0) {
      setPwdErrors(errors);
      return;
    }

    setPwdLoading(true);
    setPwdErrors({});

    try {
      await api.changePassword({
        current_password: pwdForm.current_password,
        new_password: pwdForm.new_password,
        confirm_password: pwdForm.confirm_password,
      });
      setPwdOpen(false);
      setPwdForm({ current_password: '', new_password: '', confirm_password: '' });
      showBanner('Password changed successfully.', 'success');
    } catch (err) {
      setPwdErrors({ general: err.message || 'Failed to change password.' });
    } finally {
      setPwdLoading(false);
    }
  };

  return (
    <UserLayout
      eyebrow="ACCOUNT SECURITY"
      title="MY PROFILE & PREFERENCES"
      subtitle="Manage your personal credentials, digital identity, and platform security settings."
    >
      <div className={styles.profileWrapper}>

        {bannerMsg.text && (
          <div className={bannerMsg.type === 'success' ? styles.bannerSuccess : styles.bannerError}>
            {bannerMsg.type === 'success' ? '✓ ' : '⚠ '}
            {bannerMsg.text}
          </div>
        )}

        {/* ── PROFILE CARD ── */}
        <section className={styles.profileCard}>
          <div className={styles.avatarHeader}>
            <div className={styles.bigAvatar}>
              {userProfile?.full_name ? userProfile.full_name.charAt(0).toUpperCase() : 'U'}
            </div>
            <div>
              <div className={styles.avatarName}>{userProfile?.full_name || 'Loading…'}</div>
              <div className={styles.avatarEmail}>{userProfile?.email || 'Loading…'}</div>
            </div>
          </div>

          <div className={styles.fieldsGrid}>
            <div className={styles.fieldBlock}>
              <span className={styles.fieldLabel}>FULL NAME</span>
              <span className={styles.fieldValue}>{userProfile?.full_name || '—'}</span>
            </div>

            <div className={styles.fieldBlock}>
              <span className={styles.fieldLabel}>EMAIL ADDRESS</span>
              <span className={styles.fieldValue}>{userProfile?.email || '—'}</span>
            </div>

            <div className={styles.fieldBlock}>
              <span className={styles.fieldLabel}>ROLE</span>
              <span className={styles.fieldValue}>{userProfile?.role?.toUpperCase() || 'USER'}</span>
            </div>

            <div className={styles.fieldBlock}>
              <span className={styles.fieldLabel}>ACCOUNT CREATED</span>
              <span className={styles.fieldValue}>12 August 2026</span>
            </div>
          </div>

          <div className={styles.actionButtons}>
            <button
              className={styles.primaryBtn}
              onClick={() => {
                setEditForm({ full_name: userProfile?.full_name || '', email: userProfile?.email || '' });
                setEditErrors({});
                setEditOpen(true);
              }}
            >
              EDIT PROFILE
            </button>
            <button
              className={styles.outlineBtn}
              onClick={() => {
                setPwdForm({ current_password: '', new_password: '', confirm_password: '' });
                setPwdErrors({});
                setPwdOpen(true);
              }}
            >
              CHANGE PASSWORD
            </button>
            <button
              className={styles.outlineBtn}
              style={{ color: '#dc2626', borderColor: '#fca5a5' }}
              onClick={handleLogout}
            >
              LOGOUT
            </button>
          </div>
        </section>
      </div>

      {/* ── EDIT PROFILE MODAL ── */}
      {editOpen && (
        <div className={styles.modalOverlay} onClick={() => setEditOpen(false)}>
          <div className={styles.modalBox} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>EDIT PROFILE</h2>
              <button className={styles.closeBtn} onClick={() => setEditOpen(false)}>✕</button>
            </div>

            {editErrors.general && (
              <div className={styles.bannerError}>{editErrors.general}</div>
            )}

            <form className={styles.form} onSubmit={handleEditSubmit} noValidate>
              <div className={styles.formGroup}>
                <label className={styles.formLabel}>Full Name</label>
                <input
                  type="text"
                  className={styles.formInput}
                  value={editForm.full_name}
                  onChange={(e) => setEditForm({ ...editForm, full_name: e.target.value })}
                  placeholder="e.g. Aleena Mathew"
                />
                {editErrors.full_name && <span className={styles.formError}>{editErrors.full_name}</span>}
              </div>

              <div className={styles.formGroup}>
                <label className={styles.formLabel}>Email Address</label>
                <input
                  type="email"
                  className={styles.formInput}
                  value={editForm.email}
                  onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                  placeholder="e.g. user@example.com"
                />
                {editErrors.email && <span className={styles.formError}>{editErrors.email}</span>}
              </div>

              <div style={{ display: 'flex', gap: '12px', marginTop: '10px' }}>
                <button type="submit" className={styles.primaryBtn} disabled={editLoading}>
                  {editLoading ? 'SAVING…' : 'SAVE CHANGES'}
                </button>
                <button type="button" className={styles.outlineBtn} onClick={() => setEditOpen(false)}>
                  CANCEL
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── CHANGE PASSWORD MODAL ── */}
      {pwdOpen && (
        <div className={styles.modalOverlay} onClick={() => setPwdOpen(false)}>
          <div className={styles.modalBox} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>CHANGE PASSWORD</h2>
              <button className={styles.closeBtn} onClick={() => setPwdOpen(false)}>✕</button>
            </div>

            {pwdErrors.general && (
              <div className={styles.bannerError}>{pwdErrors.general}</div>
            )}

            <form className={styles.form} onSubmit={handlePwdSubmit} noValidate>
              <div className={styles.formGroup}>
                <label className={styles.formLabel}>Current Password</label>
                <input
                  type="password"
                  className={styles.formInput}
                  value={pwdForm.current_password}
                  onChange={(e) => setPwdForm({ ...pwdForm, current_password: e.target.value })}
                  placeholder="Enter current password"
                />
                {pwdErrors.current_password && <span className={styles.formError}>{pwdErrors.current_password}</span>}
              </div>

              <div className={styles.formGroup}>
                <label className={styles.formLabel}>New Password (Min. 6 Characters)</label>
                <input
                  type="password"
                  className={styles.formInput}
                  value={pwdForm.new_password}
                  onChange={(e) => setPwdForm({ ...pwdForm, new_password: e.target.value })}
                  placeholder="Enter new password"
                />
                {pwdErrors.new_password && <span className={styles.formError}>{pwdErrors.new_password}</span>}
              </div>

              <div className={styles.formGroup}>
                <label className={styles.formLabel}>Confirm New Password</label>
                <input
                  type="password"
                  className={styles.formInput}
                  value={pwdForm.confirm_password}
                  onChange={(e) => setPwdForm({ ...pwdForm, confirm_password: e.target.value })}
                  placeholder="Confirm new password"
                />
                {pwdErrors.confirm_password && <span className={styles.formError}>{pwdErrors.confirm_password}</span>}
              </div>

              <div style={{ display: 'flex', gap: '12px', marginTop: '10px' }}>
                <button type="submit" className={styles.primaryBtn} disabled={pwdLoading}>
                  {pwdLoading ? 'UPDATING…' : 'UPDATE PASSWORD'}
                </button>
                <button type="button" className={styles.outlineBtn} onClick={() => setPwdOpen(false)}>
                  CANCEL
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </UserLayout>
  );
}

-- Canonical initial PostgreSQL schema for License Facade Service 0.1.8.

BEGIN;

--
-- PostgreSQL database dump
--


-- Dumped from database version 16.13
-- Dumped by pg_dump version 16.13

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

-- Name: lfs_reject_custom_licence_audit_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lfs_reject_custom_licence_audit_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            RAISE EXCEPTION 'custom_licence_audit_events is append-only';
        END;
        $$;


--
-- Name: lfs_reject_federation_change_events_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lfs_reject_federation_change_events_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            RAISE EXCEPTION 'federation_change_events is append-only';
        END;
        $$;


--
-- Name: lfs_reject_published_record_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lfs_reject_published_record_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            IF OLD.published_at IS NOT NULL AND (
                NEW.payload IS DISTINCT FROM OLD.payload OR
                NEW.payload_digest_sha256 <> OLD.payload_digest_sha256 OR
                NEW.canonical_id <> OLD.canonical_id OR
                NEW.authority_node_id <> OLD.authority_node_id OR
                NEW.local_id <> OLD.local_id OR
                NEW.version <> OLD.version OR
                NEW.published_at IS DISTINCT FROM OLD.published_at
            ) THEN
                RAISE EXCEPTION 'Published record content and identity are immutable';
            END IF;
            RETURN NEW;
        END;
        $$;


--
-- Name: lfs_reject_record_identifier_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lfs_reject_record_identifier_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            IF OLD.published_at IS NOT NULL AND (
                NEW.authority_node_id <> OLD.authority_node_id OR
                NEW.local_id <> OLD.local_id OR
                NEW.version <> OLD.version OR
                NEW.resolving_uuid <> OLD.resolving_uuid
            ) THEN
                RAISE EXCEPTION 'Published record identifiers are immutable';
            END IF;
            RETURN NEW;
        END;
        $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: custom_licence_aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_licence_aliases (
    id uuid NOT NULL,
    custom_licence_id uuid NOT NULL,
    alias_type character varying(32) NOT NULL,
    alias character varying(512) NOT NULL,
    normalized_alias character varying(512) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_custom_licence_aliases_alias_nonblank CHECK ((char_length(btrim((alias)::text)) > 0)),
    CONSTRAINT ck_custom_licence_aliases_normalized_alias_nonblank CHECK ((char_length(btrim((normalized_alias)::text)) > 0)),
    CONSTRAINT ck_custom_licence_aliases_type CHECK (((alias_type)::text = ANY ((ARRAY['requested_id'::character varying, 'canonical_id'::character varying, 'resolving_uuid'::character varying, 'resolving_uri'::character varying, 'legacy'::character varying])::text[])))
);


--
-- Name: custom_licence_audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_licence_audit_events (
    id uuid NOT NULL,
    custom_licence_id uuid NOT NULL,
    event_type character varying(64) NOT NULL,
    actor_role character varying(64) NOT NULL,
    actor_identifier text,
    before_state jsonb,
    after_state jsonb,
    source character varying(128),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_custom_licence_audit_actor_role_nonblank CHECK ((char_length(btrim((actor_role)::text)) > 0)),
    CONSTRAINT ck_custom_licence_audit_event_type_nonblank CHECK ((char_length(btrim((event_type)::text)) > 0))
);


--
-- Name: custom_licence_federation_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_licence_federation_outbox (
    id uuid NOT NULL,
    custom_licence_id uuid NOT NULL,
    operation character varying(32) DEFAULT 'upsert'::character varying NOT NULL,
    status character varying(32) DEFAULT 'pending'::character varying NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_owner character varying(128),
    lease_expires_at timestamp with time zone,
    last_error_class character varying(128),
    last_error_at timestamp with time zone,
    federation_record_id uuid,
    federation_event_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    published_at timestamp with time zone,
    CONSTRAINT ck_custom_licence_federation_outbox_attempt_count_nonneg CHECK ((attempt_count >= 0)),
    CONSTRAINT ck_custom_licence_federation_outbox_error_fields_consistent CHECK (((last_error_class IS NULL) = (last_error_at IS NULL))),
    CONSTRAINT ck_custom_licence_federation_outbox_lease_fields_consistent CHECK (((lease_owner IS NULL) = (lease_expires_at IS NULL))),
    CONSTRAINT ck_custom_licence_federation_outbox_operation CHECK (((operation)::text = 'upsert'::text)),
    CONSTRAINT ck_custom_licence_federation_outbox_processing_requires_owner CHECK ((((status)::text = 'processing'::text) = (lease_owner IS NOT NULL))),
    CONSTRAINT ck_custom_licence_federation_outbox_published_at_iff_published CHECK (((published_at IS NULL) OR ((status)::text = 'published'::text))),
    CONSTRAINT ck_custom_licence_federation_outbox_published_requires_linkage CHECK ((((status)::text <> 'published'::text) OR ((federation_record_id IS NOT NULL) AND (federation_event_id IS NOT NULL) AND (published_at IS NOT NULL)))),
    CONSTRAINT ck_custom_licence_federation_outbox_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'published'::character varying, 'retryable_failed'::character varying, 'permanently_failed'::character varying])::text[])))
);


--
-- Name: custom_licences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_licences (
    id uuid NOT NULL,
    authority_id character varying(128) NOT NULL,
    requested_license_id character varying(256) NOT NULL,
    version character varying(128) NOT NULL,
    canonical_id character varying(512) NOT NULL,
    resolving_uuid uuid NOT NULL,
    public_scope character varying(32) NOT NULL,
    federation_status character varying(32) DEFAULT 'not_published'::character varying NOT NULL,
    spdx_submission_status character varying(32) DEFAULT 'not_requested'::character varying NOT NULL,
    lifecycle_status character varying(32) DEFAULT 'registered'::character varying NOT NULL,
    name character varying(512) NOT NULL,
    summary text,
    description text,
    license_text text NOT NULL,
    normalized_text_digest character varying(128) NOT NULL,
    spdx_jsonld jsonb NOT NULL,
    creator_role character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deprecated_at timestamp with time zone,
    withdrawn_at timestamp with time zone,
    tombstoned_at timestamp with time zone,
    CONSTRAINT ck_custom_licences_authority_id_nonblank CHECK ((char_length(btrim((authority_id)::text)) > 0)),
    CONSTRAINT ck_custom_licences_canonical_id_nonblank CHECK ((char_length(btrim((canonical_id)::text)) > 0)),
    CONSTRAINT ck_custom_licences_creator_role_nonblank_trimmed CHECK (((char_length(btrim((creator_role)::text)) > 0) AND ((creator_role)::text = btrim((creator_role)::text)))),
    CONSTRAINT ck_custom_licences_digest_format CHECK (((normalized_text_digest)::text ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT ck_custom_licences_digest_length CHECK ((char_length(btrim((normalized_text_digest)::text)) = 64)),
    CONSTRAINT ck_custom_licences_federation_status CHECK (((federation_status)::text = ANY ((ARRAY['not_published'::character varying, 'pending'::character varying, 'published'::character varying, 'publication_failed'::character varying, 'deprecated'::character varying, 'tombstoned'::character varying])::text[]))),
    CONSTRAINT ck_custom_licences_license_text_nonblank CHECK ((char_length(btrim(license_text)) > 0)),
    CONSTRAINT ck_custom_licences_lifecycle_status CHECK (((lifecycle_status)::text = ANY ((ARRAY['registered'::character varying, 'deprecated'::character varying, 'withdrawn'::character varying, 'tombstoned'::character varying])::text[]))),
    CONSTRAINT ck_custom_licences_name_nonblank CHECK ((char_length(btrim((name)::text)) > 0)),
    CONSTRAINT ck_custom_licences_public_scope CHECK (((public_scope)::text = ANY ((ARRAY['local'::character varying, 'federated'::character varying, 'spdx-submission'::character varying])::text[]))),
    CONSTRAINT ck_custom_licences_requested_license_id_nonblank CHECK ((char_length(btrim((requested_license_id)::text)) > 0)),
    CONSTRAINT ck_custom_licences_spdx_submission_status CHECK (((spdx_submission_status)::text = ANY ((ARRAY['not_requested'::character varying, 'ready_for_review'::character varying])::text[]))),
    CONSTRAINT ck_custom_licences_version_nonblank CHECK ((char_length(btrim((version)::text)) > 0))
);


--
-- Name: federation_change_event_sequence; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.federation_change_event_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: federation_change_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_change_events (
    id uuid NOT NULL,
    event_sequence bigint DEFAULT nextval('public.federation_change_event_sequence'::regclass) NOT NULL,
    event_type character varying(64) NOT NULL,
    authority_node_id character varying(128) NOT NULL,
    record_id uuid,
    event_payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    event_digest_sha256 character varying(128) NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    operation character varying(32) DEFAULT 'upsert'::character varying NOT NULL,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    payload_schema_version character varying(16) DEFAULT '1'::character varying NOT NULL,
    signed_payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    signed_payload_digest_sha256 character varying(128) DEFAULT ''::character varying NOT NULL,
    signature_base64url character varying(512) DEFAULT ''::character varying NOT NULL,
    signature_kid character varying(128) DEFAULT ''::character varying NOT NULL,
    signature_alg character varying(32) DEFAULT 'EdDSA'::character varying NOT NULL,
    provenance_type character varying(32) DEFAULT 'publication'::character varying NOT NULL,
    backfill_created_at timestamp with time zone,
    CONSTRAINT ck_federation_change_events_operation CHECK (((operation)::text = ANY ((ARRAY['upsert'::character varying, 'deprecate'::character varying, 'tombstone'::character varying])::text[]))),
    CONSTRAINT ck_federation_change_events_signature_alg CHECK (((signature_alg)::text = 'EdDSA'::text))
);


--
-- Name: federation_conflict_decision_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_conflict_decision_events (
    id uuid NOT NULL,
    conflict_id uuid NOT NULL,
    expected_version integer NOT NULL,
    version integer NOT NULL,
    decision_type character varying(32) NOT NULL,
    decision_effectiveness character varying(32) NOT NULL,
    actor_role character varying(32) NOT NULL,
    actor_identifier character varying(256),
    rationale text,
    before_state jsonb NOT NULL,
    after_state jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: federation_conflicts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_conflicts (
    id uuid NOT NULL,
    record_key character varying(512) NOT NULL,
    local_record_id uuid,
    remote_peer_id uuid,
    remote_record_ref character varying(512),
    reason text NOT NULL,
    status character varying(32) DEFAULT 'open'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone
);


--
-- Name: federation_inbound_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_inbound_events (
    id uuid NOT NULL,
    source_peer_id uuid NOT NULL,
    authority_node_id character varying(128) NOT NULL,
    remote_event_id uuid NOT NULL,
    remote_event_position bigint NOT NULL,
    remote_operation character varying(32) NOT NULL,
    signed_payload jsonb NOT NULL,
    signed_payload_digest_sha256 character varying(128) NOT NULL,
    signature_kid character varying(128) NOT NULL,
    signature_alg character varying(32) NOT NULL,
    signature_base64url character varying(512) NOT NULL,
    generated_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone NOT NULL,
    processing_status character varying(32) NOT NULL,
    record_canonical_id character varying(512) NOT NULL,
    record_payload_digest_sha256 character varying(128) NOT NULL,
    error_code character varying(128),
    error_detail text
);


--
-- Name: federation_node_identity_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_node_identity_state (
    id integer DEFAULT 1 NOT NULL,
    node_id character varying(128) NOT NULL,
    public_base_url character varying(1024) NOT NULL,
    node_name character varying(256) NOT NULL,
    operator_name character varying(256) NOT NULL,
    config_fingerprint character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_federation_node_identity_singleton CHECK ((id = 1))
);


--
-- Name: federation_peer_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_peer_audit_log (
    id uuid NOT NULL,
    peer_id uuid NOT NULL,
    action character varying(64) NOT NULL,
    actor character varying(128) NOT NULL,
    details jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: federation_peer_cursors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_peer_cursors (
    id uuid NOT NULL,
    peer_id uuid NOT NULL,
    cursor character varying(512),
    synced_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_remote_position bigint
);


--
-- Name: federation_peer_signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_peer_signing_keys (
    id uuid NOT NULL,
    peer_id uuid NOT NULL,
    kid character varying(128) NOT NULL,
    alg character varying(32) NOT NULL,
    kty character varying(16) NOT NULL,
    crv character varying(32) NOT NULL,
    x character varying(1024) NOT NULL,
    key_fingerprint character varying(128) NOT NULL,
    key_status character varying(32) DEFAULT 'active'::character varying NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    approved_by character varying(128),
    approved_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_federation_peer_signing_keys_alg CHECK (((alg)::text = 'EdDSA'::text)),
    CONSTRAINT ck_federation_peer_signing_keys_crv CHECK (((crv)::text = 'Ed25519'::text)),
    CONSTRAINT ck_federation_peer_signing_keys_kty CHECK (((kty)::text = 'OKP'::text)),
    CONSTRAINT ck_federation_peer_signing_keys_status CHECK (((key_status)::text = ANY ((ARRAY['active'::character varying, 'retired'::character varying, 'revoked'::character varying])::text[])))
);


--
-- Name: federation_rdf_graph_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_rdf_graph_state (
    graph_uri character varying(2048) NOT NULL,
    graph_kind character varying(64) NOT NULL,
    record_id uuid,
    authority_node_id character varying(128),
    source_peer_id uuid,
    expected_generation bigint DEFAULT '0'::bigint NOT NULL,
    expected_digest_sha256 character varying(128),
    current_generation bigint DEFAULT '0'::bigint NOT NULL,
    current_digest_sha256 character varying(128),
    status character varying(32) DEFAULT 'pending'::character varying NOT NULL,
    last_success_at timestamp with time zone,
    last_attempt_at timestamp with time zone,
    last_error_code character varying(128),
    last_error_detail text,
    owned_by_service boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    active_lease_job_id uuid,
    active_lease_by character varying(128),
    active_lease_until timestamp with time zone
);


--
-- Name: federation_rdf_outbox_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_rdf_outbox_jobs (
    id uuid NOT NULL,
    dedupe_key character varying(512) NOT NULL,
    job_type character varying(64) NOT NULL,
    status character varying(32) DEFAULT 'pending'::character varying NOT NULL,
    record_id uuid,
    authority_node_id character varying(128),
    source_peer_id uuid,
    graph_uri character varying(2048) NOT NULL,
    expected_generation bigint NOT NULL,
    expected_digest_sha256 character varying(128) NOT NULL,
    payload_json jsonb NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    leased_until timestamp with time zone,
    leased_by character varying(128),
    next_attempt_at timestamp with time zone,
    last_error_code character varying(128),
    last_error_detail text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    dead_lettered_at timestamp with time zone,
    CONSTRAINT ck_federation_rdf_outbox_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'succeeded'::character varying, 'retryable_failed'::character varying, 'dead_lettered'::character varying, 'superseded'::character varying])::text[])))
);


--
-- Name: federation_record_aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_record_aliases (
    id uuid NOT NULL,
    record_id uuid NOT NULL,
    alias character varying(512) NOT NULL,
    alias_type character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: federation_record_provenance; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_record_provenance (
    id uuid NOT NULL,
    record_id uuid NOT NULL,
    source_node_id character varying(128),
    source_uri character varying(2048),
    source_digest_sha256 character varying(128),
    provenance_type character varying(64) NOT NULL,
    imported_at timestamp with time zone,
    asserted_at timestamp with time zone NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: federation_record_representations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_record_representations (
    id uuid NOT NULL,
    record_id uuid NOT NULL,
    representation_type character varying(64) NOT NULL,
    media_type character varying(128) NOT NULL,
    profile_uri character varying(1024),
    vocabulary_uri character varying(1024),
    href character varying(2048),
    content text,
    content_digest_sha256 character varying(128),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: federation_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_records (
    id uuid NOT NULL,
    authority_node_id character varying(128) NOT NULL,
    local_id character varying(256) NOT NULL,
    version character varying(128) NOT NULL,
    canonical_id character varying(512) NOT NULL,
    resolving_uuid uuid NOT NULL,
    is_authoritative boolean DEFAULT false NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    payload_digest_sha256 character varying(128) NOT NULL,
    published_at timestamp with time zone,
    imported_from_peer_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    lifecycle_state character varying(32) DEFAULT 'published'::character varying NOT NULL,
    source_record_url character varying(2048),
    source_event_id uuid,
    source_event_position bigint,
    source_signature_kid character varying(128),
    source_signed_payload_digest_sha256 character varying(128),
    verification_status character varying(32),
    last_verified_at timestamp with time zone,
    materialized_generation bigint DEFAULT '0'::bigint NOT NULL
);


--
-- Name: federation_resolution_aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_resolution_aliases (
    id uuid NOT NULL,
    normalized_identifier character varying(1024) NOT NULL,
    alias_value character varying(2048) NOT NULL,
    alias_kind character varying(64) NOT NULL,
    record_id uuid NOT NULL,
    authority_node_id character varying(128),
    source_peer_id uuid,
    is_authoritative boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: federation_resolution_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_resolution_audit_log (
    id uuid NOT NULL,
    subject_type character varying(64) NOT NULL,
    subject_id character varying(256) NOT NULL,
    action character varying(64) NOT NULL,
    actor_role character varying(32) NOT NULL,
    actor_identifier character varying(256),
    rationale text,
    before_state jsonb NOT NULL,
    after_state jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: federation_resolution_conflicts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_resolution_conflicts (
    id uuid NOT NULL,
    normalized_identifier character varying(1024) NOT NULL,
    conflict_type character varying(64) NOT NULL,
    status character varying(32) DEFAULT 'open'::character varying NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    decision_effectiveness character varying(32),
    candidate_summary jsonb NOT NULL,
    resolved_record_id uuid,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    resolved_at timestamp with time zone,
    reopened_at timestamp with time zone
);


--
-- Name: federation_signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_signing_keys (
    id uuid NOT NULL,
    kid character varying(128) NOT NULL,
    alg character varying(32) NOT NULL,
    kty character varying(16) NOT NULL,
    crv character varying(32) NOT NULL,
    x character varying(1024) NOT NULL,
    is_active boolean DEFAULT false NOT NULL,
    status character varying(32) DEFAULT 'active'::character varying NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_federation_signing_keys_alg CHECK (((alg)::text = 'EdDSA'::text)),
    CONSTRAINT ck_federation_signing_keys_crv CHECK (((crv)::text = 'Ed25519'::text)),
    CONSTRAINT ck_federation_signing_keys_kty CHECK (((kty)::text = 'OKP'::text))
);


--
-- Name: federation_sync_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_sync_attempts (
    id uuid NOT NULL,
    peer_id uuid NOT NULL,
    started_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    status character varying(32) NOT NULL,
    error_code character varying(128),
    error_detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    trigger_type character varying(32) DEFAULT 'manual'::character varying NOT NULL,
    pages_processed integer DEFAULT 0 NOT NULL,
    events_processed integer DEFAULT 0 NOT NULL,
    cursor_before character varying(1024),
    cursor_after character varying(1024)
);


--
-- Name: federation_trusted_peers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_trusted_peers (
    id uuid NOT NULL,
    peer_node_id character varying(128) NOT NULL,
    base_url character varying(1024) NOT NULL,
    jwks_url character varying(1024) NOT NULL,
    peer_name character varying(256) NOT NULL,
    operator_name character varying(256),
    trust_status character varying(32) DEFAULT 'trusted'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    sync_enabled boolean DEFAULT true NOT NULL,
    allow_private_network boolean DEFAULT false NOT NULL,
    allowed_hostnames text,
    allowed_cidrs text,
    enrollment_mode character varying(32) DEFAULT 'strict'::character varying NOT NULL,
    expected_key_fingerprint character varying(128),
    expected_key_kid character varying(128),
    last_sync_attempt_at timestamp with time zone,
    last_sync_success_at timestamp with time zone,
    last_sync_status character varying(32),
    last_sync_error_code character varying(128),
    last_sync_error_detail text,
    archived_at timestamp with time zone
);


--
-- Name: custom_licence_aliases custom_licence_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_aliases
    ADD CONSTRAINT custom_licence_aliases_pkey PRIMARY KEY (id);


--
-- Name: custom_licence_audit_events custom_licence_audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_audit_events
    ADD CONSTRAINT custom_licence_audit_events_pkey PRIMARY KEY (id);


--
-- Name: custom_licence_federation_outbox custom_licence_federation_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_federation_outbox
    ADD CONSTRAINT custom_licence_federation_outbox_pkey PRIMARY KEY (id);


--
-- Name: custom_licences custom_licences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licences
    ADD CONSTRAINT custom_licences_pkey PRIMARY KEY (id);


--
-- Name: federation_change_events federation_change_events_event_sequence_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_change_events
    ADD CONSTRAINT federation_change_events_event_sequence_key UNIQUE (event_sequence);


--
-- Name: federation_change_events federation_change_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_change_events
    ADD CONSTRAINT federation_change_events_pkey PRIMARY KEY (id);


--
-- Name: federation_conflict_decision_events federation_conflict_decision_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_conflict_decision_events
    ADD CONSTRAINT federation_conflict_decision_events_pkey PRIMARY KEY (id);


--
-- Name: federation_conflicts federation_conflicts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_conflicts
    ADD CONSTRAINT federation_conflicts_pkey PRIMARY KEY (id);


--
-- Name: federation_inbound_events federation_inbound_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_events
    ADD CONSTRAINT federation_inbound_events_pkey PRIMARY KEY (id);


--
-- Name: federation_node_identity_state federation_node_identity_state_node_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_node_identity_state
    ADD CONSTRAINT federation_node_identity_state_node_id_key UNIQUE (node_id);


--
-- Name: federation_node_identity_state federation_node_identity_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_node_identity_state
    ADD CONSTRAINT federation_node_identity_state_pkey PRIMARY KEY (id);


--
-- Name: federation_peer_audit_log federation_peer_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_audit_log
    ADD CONSTRAINT federation_peer_audit_log_pkey PRIMARY KEY (id);


--
-- Name: federation_peer_cursors federation_peer_cursors_peer_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_cursors
    ADD CONSTRAINT federation_peer_cursors_peer_id_key UNIQUE (peer_id);


--
-- Name: federation_peer_cursors federation_peer_cursors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_cursors
    ADD CONSTRAINT federation_peer_cursors_pkey PRIMARY KEY (id);


--
-- Name: federation_peer_signing_keys federation_peer_signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_signing_keys
    ADD CONSTRAINT federation_peer_signing_keys_pkey PRIMARY KEY (id);


--
-- Name: federation_rdf_graph_state federation_rdf_graph_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_rdf_graph_state
    ADD CONSTRAINT federation_rdf_graph_state_pkey PRIMARY KEY (graph_uri);


--
-- Name: federation_rdf_outbox_jobs federation_rdf_outbox_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_rdf_outbox_jobs
    ADD CONSTRAINT federation_rdf_outbox_jobs_pkey PRIMARY KEY (id);


--
-- Name: federation_record_aliases federation_record_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_record_aliases
    ADD CONSTRAINT federation_record_aliases_pkey PRIMARY KEY (id);


--
-- Name: federation_record_provenance federation_record_provenance_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_record_provenance
    ADD CONSTRAINT federation_record_provenance_pkey PRIMARY KEY (id);


--
-- Name: federation_record_representations federation_record_representations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_record_representations
    ADD CONSTRAINT federation_record_representations_pkey PRIMARY KEY (id);


--
-- Name: federation_records federation_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_records
    ADD CONSTRAINT federation_records_pkey PRIMARY KEY (id);


--
-- Name: federation_records federation_records_resolving_uuid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_records
    ADD CONSTRAINT federation_records_resolving_uuid_key UNIQUE (resolving_uuid);


--
-- Name: federation_resolution_aliases federation_resolution_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_resolution_aliases
    ADD CONSTRAINT federation_resolution_aliases_pkey PRIMARY KEY (id);


--
-- Name: federation_resolution_audit_log federation_resolution_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_resolution_audit_log
    ADD CONSTRAINT federation_resolution_audit_log_pkey PRIMARY KEY (id);


--
-- Name: federation_resolution_conflicts federation_resolution_conflicts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_resolution_conflicts
    ADD CONSTRAINT federation_resolution_conflicts_pkey PRIMARY KEY (id);


--
-- Name: federation_signing_keys federation_signing_keys_kid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_signing_keys
    ADD CONSTRAINT federation_signing_keys_kid_key UNIQUE (kid);


--
-- Name: federation_signing_keys federation_signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_signing_keys
    ADD CONSTRAINT federation_signing_keys_pkey PRIMARY KEY (id);


--
-- Name: federation_sync_attempts federation_sync_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_sync_attempts
    ADD CONSTRAINT federation_sync_attempts_pkey PRIMARY KEY (id);


--
-- Name: federation_trusted_peers federation_trusted_peers_peer_node_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_trusted_peers
    ADD CONSTRAINT federation_trusted_peers_peer_node_id_key UNIQUE (peer_node_id);


--
-- Name: federation_trusted_peers federation_trusted_peers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_trusted_peers
    ADD CONSTRAINT federation_trusted_peers_pkey PRIMARY KEY (id);


--
-- Name: custom_licence_aliases uq_custom_licence_aliases_normalized_alias; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_aliases
    ADD CONSTRAINT uq_custom_licence_aliases_normalized_alias UNIQUE (normalized_alias);


--
-- Name: custom_licence_federation_outbox uq_custom_licence_federation_outbox_licence_operation; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_federation_outbox
    ADD CONSTRAINT uq_custom_licence_federation_outbox_licence_operation UNIQUE (custom_licence_id, operation);


--
-- Name: custom_licences uq_custom_licences_authority_requested_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licences
    ADD CONSTRAINT uq_custom_licences_authority_requested_version UNIQUE (authority_id, requested_license_id, version);


--
-- Name: custom_licences uq_custom_licences_canonical_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licences
    ADD CONSTRAINT uq_custom_licences_canonical_id UNIQUE (canonical_id);


--
-- Name: custom_licences uq_custom_licences_resolving_uuid; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licences
    ADD CONSTRAINT uq_custom_licences_resolving_uuid UNIQUE (resolving_uuid);


--
-- Name: federation_change_events uq_federation_change_events_authority_sequence; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_change_events
    ADD CONSTRAINT uq_federation_change_events_authority_sequence UNIQUE (authority_node_id, event_sequence);


--
-- Name: federation_conflict_decision_events uq_federation_conflict_decisions_conflict_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_conflict_decision_events
    ADD CONSTRAINT uq_federation_conflict_decisions_conflict_version UNIQUE (conflict_id, version);


--
-- Name: federation_inbound_events uq_federation_inbound_events_authority_event_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_events
    ADD CONSTRAINT uq_federation_inbound_events_authority_event_id UNIQUE (authority_node_id, remote_event_id);


--
-- Name: federation_inbound_events uq_federation_inbound_events_authority_event_position; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_events
    ADD CONSTRAINT uq_federation_inbound_events_authority_event_position UNIQUE (authority_node_id, remote_event_position);


--
-- Name: federation_inbound_events uq_federation_inbound_events_peer_digest; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_events
    ADD CONSTRAINT uq_federation_inbound_events_peer_digest UNIQUE (source_peer_id, signed_payload_digest_sha256);


--
-- Name: federation_peer_signing_keys uq_federation_peer_signing_keys_peer_kid; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_signing_keys
    ADD CONSTRAINT uq_federation_peer_signing_keys_peer_kid UNIQUE (peer_id, kid);


--
-- Name: federation_rdf_outbox_jobs uq_federation_rdf_outbox_jobs_dedupe_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_rdf_outbox_jobs
    ADD CONSTRAINT uq_federation_rdf_outbox_jobs_dedupe_key UNIQUE (dedupe_key);


--
-- Name: federation_record_aliases uq_federation_record_alias; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_record_aliases
    ADD CONSTRAINT uq_federation_record_alias UNIQUE (alias);


--
-- Name: federation_records uq_federation_record_authority_local_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_records
    ADD CONSTRAINT uq_federation_record_authority_local_version UNIQUE (authority_node_id, local_id, version);


--
-- Name: federation_records uq_federation_record_canonical_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_records
    ADD CONSTRAINT uq_federation_record_canonical_id UNIQUE (canonical_id);


--
-- Name: federation_record_representations uq_federation_representation_kind; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_record_representations
    ADD CONSTRAINT uq_federation_representation_kind UNIQUE (record_id, representation_type, media_type);


--
-- Name: federation_resolution_aliases uq_federation_resolution_alias; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_resolution_aliases
    ADD CONSTRAINT uq_federation_resolution_alias UNIQUE (normalized_identifier, record_id, alias_kind);


--
-- Name: federation_resolution_conflicts uq_federation_resolution_conflicts_normalized_identifier; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_resolution_conflicts
    ADD CONSTRAINT uq_federation_resolution_conflicts_normalized_identifier UNIQUE (normalized_identifier);


--
-- Name: ix_custom_licence_aliases_custom_licence_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_custom_licence_aliases_custom_licence_type ON public.custom_licence_aliases USING btree (custom_licence_id, alias_type);


--
-- Name: ix_custom_licence_audit_events_licence_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_custom_licence_audit_events_licence_created ON public.custom_licence_audit_events USING btree (custom_licence_id, created_at);


--
-- Name: ix_custom_licence_federation_outbox_custom_licence_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_custom_licence_federation_outbox_custom_licence_id ON public.custom_licence_federation_outbox USING btree (custom_licence_id);


--
-- Name: ix_custom_licence_federation_outbox_status_available_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_custom_licence_federation_outbox_status_available_at ON public.custom_licence_federation_outbox USING btree (status, available_at);


--
-- Name: ix_custom_licence_federation_outbox_status_lease_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_custom_licence_federation_outbox_status_lease_expires_at ON public.custom_licence_federation_outbox USING btree (status, lease_expires_at);


--
-- Name: ix_custom_licences_authority_requested; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_custom_licences_authority_requested ON public.custom_licences USING btree (authority_id, requested_license_id);


--
-- Name: ix_custom_licences_lifecycle_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_custom_licences_lifecycle_status ON public.custom_licences USING btree (lifecycle_status);


--
-- Name: ix_custom_licences_scope_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_custom_licences_scope_status ON public.custom_licences USING btree (public_scope, federation_status, spdx_submission_status);


--
-- Name: ix_federation_change_events_occurred_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_change_events_occurred_at ON public.federation_change_events USING btree (occurred_at);


--
-- Name: ix_federation_conflict_decisions_conflict_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_conflict_decisions_conflict_version ON public.federation_conflict_decision_events USING btree (conflict_id, version);


--
-- Name: ix_federation_conflicts_record_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_conflicts_record_key ON public.federation_conflicts USING btree (record_key);


--
-- Name: ix_federation_inbound_events_peer_position; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_inbound_events_peer_position ON public.federation_inbound_events USING btree (source_peer_id, remote_event_position);


--
-- Name: ix_federation_provenance_record_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_provenance_record_id ON public.federation_record_provenance USING btree (record_id);


--
-- Name: ix_federation_rdf_outbox_graph_uri; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_rdf_outbox_graph_uri ON public.federation_rdf_outbox_jobs USING btree (graph_uri);


--
-- Name: ix_federation_rdf_outbox_record_generation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_rdf_outbox_record_generation ON public.federation_rdf_outbox_jobs USING btree (record_id, expected_generation);


--
-- Name: ix_federation_rdf_outbox_status_next_attempt; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_rdf_outbox_status_next_attempt ON public.federation_rdf_outbox_jobs USING btree (status, next_attempt_at);


--
-- Name: ix_federation_record_aliases_record_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_record_aliases_record_id ON public.federation_record_aliases USING btree (record_id);


--
-- Name: ix_federation_records_authority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_records_authority ON public.federation_records USING btree (authority_node_id);


--
-- Name: ix_federation_records_canonical_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_records_canonical_id ON public.federation_records USING btree (canonical_id);


--
-- Name: ix_federation_records_imported_peer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_records_imported_peer ON public.federation_records USING btree (imported_from_peer_id);


--
-- Name: ix_federation_representations_record_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_representations_record_id ON public.federation_record_representations USING btree (record_id);


--
-- Name: ix_federation_resolution_aliases_normalized_identifier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_resolution_aliases_normalized_identifier ON public.federation_resolution_aliases USING btree (normalized_identifier);


--
-- Name: ix_federation_resolution_conflicts_normalized_identifier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_resolution_conflicts_normalized_identifier ON public.federation_resolution_conflicts USING btree (normalized_identifier);


--
-- Name: ix_federation_sync_attempts_peer_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_sync_attempts_peer_started ON public.federation_sync_attempts USING btree (peer_id, started_at);


--
-- Name: uix_custom_licence_federation_outbox_federation_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uix_custom_licence_federation_outbox_federation_event_id ON public.custom_licence_federation_outbox USING btree (federation_event_id) WHERE (federation_event_id IS NOT NULL);


--
-- Name: uix_custom_licence_federation_outbox_federation_record_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uix_custom_licence_federation_outbox_federation_record_id ON public.custom_licence_federation_outbox USING btree (federation_record_id) WHERE (federation_record_id IS NOT NULL);


--
-- Name: uq_federation_signing_keys_single_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_federation_signing_keys_single_active ON public.federation_signing_keys USING btree (is_active) WHERE (is_active = true);


--
-- Name: custom_licence_audit_events trg_custom_licence_audit_events_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_custom_licence_audit_events_no_delete BEFORE DELETE ON public.custom_licence_audit_events FOR EACH ROW EXECUTE FUNCTION public.lfs_reject_custom_licence_audit_mutation();


--
-- Name: custom_licence_audit_events trg_custom_licence_audit_events_no_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_custom_licence_audit_events_no_update BEFORE UPDATE ON public.custom_licence_audit_events FOR EACH ROW EXECUTE FUNCTION public.lfs_reject_custom_licence_audit_mutation();


--
-- Name: federation_change_events trg_federation_change_events_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_federation_change_events_no_delete BEFORE DELETE ON public.federation_change_events FOR EACH ROW EXECUTE FUNCTION public.lfs_reject_federation_change_events_mutation();


--
-- Name: federation_change_events trg_federation_change_events_no_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_federation_change_events_no_update BEFORE UPDATE ON public.federation_change_events FOR EACH ROW EXECUTE FUNCTION public.lfs_reject_federation_change_events_mutation();


--
-- Name: federation_records trg_federation_records_immutable_published_content; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_federation_records_immutable_published_content BEFORE UPDATE ON public.federation_records FOR EACH ROW EXECUTE FUNCTION public.lfs_reject_published_record_mutation();


--
-- Name: federation_records trg_federation_records_immutable_published_identifier; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_federation_records_immutable_published_identifier BEFORE UPDATE ON public.federation_records FOR EACH ROW EXECUTE FUNCTION public.lfs_reject_record_identifier_mutation();


--
-- Name: custom_licence_aliases custom_licence_aliases_custom_licence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_aliases
    ADD CONSTRAINT custom_licence_aliases_custom_licence_id_fkey FOREIGN KEY (custom_licence_id) REFERENCES public.custom_licences(id) ON DELETE RESTRICT;


--
-- Name: custom_licence_audit_events custom_licence_audit_events_custom_licence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_audit_events
    ADD CONSTRAINT custom_licence_audit_events_custom_licence_id_fkey FOREIGN KEY (custom_licence_id) REFERENCES public.custom_licences(id) ON DELETE RESTRICT;


--
-- Name: custom_licence_federation_outbox custom_licence_federation_outbox_custom_licence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_federation_outbox
    ADD CONSTRAINT custom_licence_federation_outbox_custom_licence_id_fkey FOREIGN KEY (custom_licence_id) REFERENCES public.custom_licences(id) ON DELETE RESTRICT;


--
-- Name: custom_licence_federation_outbox custom_licence_federation_outbox_federation_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_federation_outbox
    ADD CONSTRAINT custom_licence_federation_outbox_federation_event_id_fkey FOREIGN KEY (federation_event_id) REFERENCES public.federation_change_events(id) ON DELETE RESTRICT;


--
-- Name: custom_licence_federation_outbox custom_licence_federation_outbox_federation_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_licence_federation_outbox
    ADD CONSTRAINT custom_licence_federation_outbox_federation_record_id_fkey FOREIGN KEY (federation_record_id) REFERENCES public.federation_records(id) ON DELETE RESTRICT;


--
-- Name: federation_change_events federation_change_events_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_change_events
    ADD CONSTRAINT federation_change_events_record_id_fkey FOREIGN KEY (record_id) REFERENCES public.federation_records(id) ON DELETE SET NULL;


--
-- Name: federation_conflict_decision_events federation_conflict_decision_events_conflict_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_conflict_decision_events
    ADD CONSTRAINT federation_conflict_decision_events_conflict_id_fkey FOREIGN KEY (conflict_id) REFERENCES public.federation_resolution_conflicts(id) ON DELETE CASCADE;


--
-- Name: federation_conflicts federation_conflicts_local_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_conflicts
    ADD CONSTRAINT federation_conflicts_local_record_id_fkey FOREIGN KEY (local_record_id) REFERENCES public.federation_records(id) ON DELETE SET NULL;


--
-- Name: federation_conflicts federation_conflicts_remote_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_conflicts
    ADD CONSTRAINT federation_conflicts_remote_peer_id_fkey FOREIGN KEY (remote_peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE SET NULL;


--
-- Name: federation_inbound_events federation_inbound_events_source_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_events
    ADD CONSTRAINT federation_inbound_events_source_peer_id_fkey FOREIGN KEY (source_peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE CASCADE;


--
-- Name: federation_peer_audit_log federation_peer_audit_log_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_audit_log
    ADD CONSTRAINT federation_peer_audit_log_peer_id_fkey FOREIGN KEY (peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE CASCADE;


--
-- Name: federation_peer_cursors federation_peer_cursors_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_cursors
    ADD CONSTRAINT federation_peer_cursors_peer_id_fkey FOREIGN KEY (peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE CASCADE;


--
-- Name: federation_peer_signing_keys federation_peer_signing_keys_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_signing_keys
    ADD CONSTRAINT federation_peer_signing_keys_peer_id_fkey FOREIGN KEY (peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE CASCADE;


--
-- Name: federation_rdf_graph_state federation_rdf_graph_state_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_rdf_graph_state
    ADD CONSTRAINT federation_rdf_graph_state_record_id_fkey FOREIGN KEY (record_id) REFERENCES public.federation_records(id) ON DELETE CASCADE;


--
-- Name: federation_rdf_graph_state federation_rdf_graph_state_source_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_rdf_graph_state
    ADD CONSTRAINT federation_rdf_graph_state_source_peer_id_fkey FOREIGN KEY (source_peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE SET NULL;


--
-- Name: federation_rdf_outbox_jobs federation_rdf_outbox_jobs_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_rdf_outbox_jobs
    ADD CONSTRAINT federation_rdf_outbox_jobs_record_id_fkey FOREIGN KEY (record_id) REFERENCES public.federation_records(id) ON DELETE CASCADE;


--
-- Name: federation_rdf_outbox_jobs federation_rdf_outbox_jobs_source_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_rdf_outbox_jobs
    ADD CONSTRAINT federation_rdf_outbox_jobs_source_peer_id_fkey FOREIGN KEY (source_peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE SET NULL;


--
-- Name: federation_record_aliases federation_record_aliases_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_record_aliases
    ADD CONSTRAINT federation_record_aliases_record_id_fkey FOREIGN KEY (record_id) REFERENCES public.federation_records(id) ON DELETE CASCADE;


--
-- Name: federation_record_provenance federation_record_provenance_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_record_provenance
    ADD CONSTRAINT federation_record_provenance_record_id_fkey FOREIGN KEY (record_id) REFERENCES public.federation_records(id) ON DELETE CASCADE;


--
-- Name: federation_record_representations federation_record_representations_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_record_representations
    ADD CONSTRAINT federation_record_representations_record_id_fkey FOREIGN KEY (record_id) REFERENCES public.federation_records(id) ON DELETE CASCADE;


--
-- Name: federation_records federation_records_imported_from_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_records
    ADD CONSTRAINT federation_records_imported_from_peer_id_fkey FOREIGN KEY (imported_from_peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE SET NULL;


--
-- Name: federation_resolution_aliases federation_resolution_aliases_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_resolution_aliases
    ADD CONSTRAINT federation_resolution_aliases_record_id_fkey FOREIGN KEY (record_id) REFERENCES public.federation_records(id) ON DELETE CASCADE;


--
-- Name: federation_resolution_aliases federation_resolution_aliases_source_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_resolution_aliases
    ADD CONSTRAINT federation_resolution_aliases_source_peer_id_fkey FOREIGN KEY (source_peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE SET NULL;


--
-- Name: federation_resolution_conflicts federation_resolution_conflicts_resolved_record_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_resolution_conflicts
    ADD CONSTRAINT federation_resolution_conflicts_resolved_record_id_fkey FOREIGN KEY (resolved_record_id) REFERENCES public.federation_records(id) ON DELETE SET NULL;


--
-- Name: federation_sync_attempts federation_sync_attempts_peer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_sync_attempts
    ADD CONSTRAINT federation_sync_attempts_peer_id_fkey FOREIGN KEY (peer_id) REFERENCES public.federation_trusted_peers(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--



COMMIT;

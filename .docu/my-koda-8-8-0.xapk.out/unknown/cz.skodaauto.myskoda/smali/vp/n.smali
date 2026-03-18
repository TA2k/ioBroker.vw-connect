.class public final Lvp/n;
.super Lvp/u3;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final j:[Ljava/lang/String;

.field public static final k:[Ljava/lang/String;

.field public static final l:[Ljava/lang/String;

.field public static final m:[Ljava/lang/String;

.field public static final n:[Ljava/lang/String;

.field public static final o:[Ljava/lang/String;

.field public static final p:[Ljava/lang/String;

.field public static final q:[Ljava/lang/String;

.field public static final r:[Ljava/lang/String;

.field public static final s:[Ljava/lang/String;

.field public static final t:[Ljava/lang/String;


# instance fields
.field public final h:Lvp/m;

.field public final i:Lg1/i3;


# direct methods
.method static constructor <clinit>()V
    .locals 95

    .line 1
    const-string v10, "current_session_count"

    .line 2
    .line 3
    const-string v11, "ALTER TABLE events ADD COLUMN current_session_count INTEGER;"

    .line 4
    .line 5
    const-string v0, "last_bundled_timestamp"

    .line 6
    .line 7
    const-string v1, "ALTER TABLE events ADD COLUMN last_bundled_timestamp INTEGER;"

    .line 8
    .line 9
    const-string v2, "last_bundled_day"

    .line 10
    .line 11
    const-string v3, "ALTER TABLE events ADD COLUMN last_bundled_day INTEGER;"

    .line 12
    .line 13
    const-string v4, "last_sampled_complex_event_id"

    .line 14
    .line 15
    const-string v5, "ALTER TABLE events ADD COLUMN last_sampled_complex_event_id INTEGER;"

    .line 16
    .line 17
    const-string v6, "last_sampling_rate"

    .line 18
    .line 19
    const-string v7, "ALTER TABLE events ADD COLUMN last_sampling_rate INTEGER;"

    .line 20
    .line 21
    const-string v8, "last_exempt_from_sampling"

    .line 22
    .line 23
    const-string v9, "ALTER TABLE events ADD COLUMN last_exempt_from_sampling INTEGER;"

    .line 24
    .line 25
    filled-new-array/range {v0 .. v11}, [Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lvp/n;->j:[Ljava/lang/String;

    .line 30
    .line 31
    const-string v0, "last_upload_timestamp"

    .line 32
    .line 33
    const-string v1, "ALTER TABLE upload_queue ADD COLUMN last_upload_timestamp INTEGER;"

    .line 34
    .line 35
    const-string v2, "associated_row_id"

    .line 36
    .line 37
    const-string v3, "ALTER TABLE upload_queue ADD COLUMN associated_row_id INTEGER;"

    .line 38
    .line 39
    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sput-object v0, Lvp/n;->k:[Ljava/lang/String;

    .line 44
    .line 45
    const-string v0, "origin"

    .line 46
    .line 47
    const-string v1, "ALTER TABLE user_attributes ADD COLUMN origin TEXT;"

    .line 48
    .line 49
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Lvp/n;->l:[Ljava/lang/String;

    .line 54
    .line 55
    const-string v93, "gmp_version_for_remote_config"

    .line 56
    .line 57
    const-string v94, "ALTER TABLE apps ADD COLUMN gmp_version_for_remote_config INTEGER;"

    .line 58
    .line 59
    const-string v1, "app_version"

    .line 60
    .line 61
    const-string v2, "ALTER TABLE apps ADD COLUMN app_version TEXT;"

    .line 62
    .line 63
    const-string v3, "app_store"

    .line 64
    .line 65
    const-string v4, "ALTER TABLE apps ADD COLUMN app_store TEXT;"

    .line 66
    .line 67
    const-string v5, "gmp_version"

    .line 68
    .line 69
    const-string v6, "ALTER TABLE apps ADD COLUMN gmp_version INTEGER;"

    .line 70
    .line 71
    const-string v7, "dev_cert_hash"

    .line 72
    .line 73
    const-string v8, "ALTER TABLE apps ADD COLUMN dev_cert_hash INTEGER;"

    .line 74
    .line 75
    const-string v9, "measurement_enabled"

    .line 76
    .line 77
    const-string v10, "ALTER TABLE apps ADD COLUMN measurement_enabled INTEGER;"

    .line 78
    .line 79
    const-string v11, "last_bundle_start_timestamp"

    .line 80
    .line 81
    const-string v12, "ALTER TABLE apps ADD COLUMN last_bundle_start_timestamp INTEGER;"

    .line 82
    .line 83
    const-string v13, "day"

    .line 84
    .line 85
    const-string v14, "ALTER TABLE apps ADD COLUMN day INTEGER;"

    .line 86
    .line 87
    const-string v15, "daily_public_events_count"

    .line 88
    .line 89
    const-string v16, "ALTER TABLE apps ADD COLUMN daily_public_events_count INTEGER;"

    .line 90
    .line 91
    const-string v17, "daily_events_count"

    .line 92
    .line 93
    const-string v18, "ALTER TABLE apps ADD COLUMN daily_events_count INTEGER;"

    .line 94
    .line 95
    const-string v19, "daily_conversions_count"

    .line 96
    .line 97
    const-string v20, "ALTER TABLE apps ADD COLUMN daily_conversions_count INTEGER;"

    .line 98
    .line 99
    const-string v21, "remote_config"

    .line 100
    .line 101
    const-string v22, "ALTER TABLE apps ADD COLUMN remote_config BLOB;"

    .line 102
    .line 103
    const-string v23, "config_fetched_time"

    .line 104
    .line 105
    const-string v24, "ALTER TABLE apps ADD COLUMN config_fetched_time INTEGER;"

    .line 106
    .line 107
    const-string v25, "failed_config_fetch_time"

    .line 108
    .line 109
    const-string v26, "ALTER TABLE apps ADD COLUMN failed_config_fetch_time INTEGER;"

    .line 110
    .line 111
    const-string v27, "app_version_int"

    .line 112
    .line 113
    const-string v28, "ALTER TABLE apps ADD COLUMN app_version_int INTEGER;"

    .line 114
    .line 115
    const-string v29, "firebase_instance_id"

    .line 116
    .line 117
    const-string v30, "ALTER TABLE apps ADD COLUMN firebase_instance_id TEXT;"

    .line 118
    .line 119
    const-string v31, "daily_error_events_count"

    .line 120
    .line 121
    const-string v32, "ALTER TABLE apps ADD COLUMN daily_error_events_count INTEGER;"

    .line 122
    .line 123
    const-string v33, "daily_realtime_events_count"

    .line 124
    .line 125
    const-string v34, "ALTER TABLE apps ADD COLUMN daily_realtime_events_count INTEGER;"

    .line 126
    .line 127
    const-string v35, "health_monitor_sample"

    .line 128
    .line 129
    const-string v36, "ALTER TABLE apps ADD COLUMN health_monitor_sample TEXT;"

    .line 130
    .line 131
    const-string v37, "android_id"

    .line 132
    .line 133
    const-string v38, "ALTER TABLE apps ADD COLUMN android_id INTEGER;"

    .line 134
    .line 135
    const-string v39, "adid_reporting_enabled"

    .line 136
    .line 137
    const-string v40, "ALTER TABLE apps ADD COLUMN adid_reporting_enabled INTEGER;"

    .line 138
    .line 139
    const-string v41, "ssaid_reporting_enabled"

    .line 140
    .line 141
    const-string v42, "ALTER TABLE apps ADD COLUMN ssaid_reporting_enabled INTEGER;"

    .line 142
    .line 143
    const-string v43, "admob_app_id"

    .line 144
    .line 145
    const-string v44, "ALTER TABLE apps ADD COLUMN admob_app_id TEXT;"

    .line 146
    .line 147
    const-string v45, "linked_admob_app_id"

    .line 148
    .line 149
    const-string v46, "ALTER TABLE apps ADD COLUMN linked_admob_app_id TEXT;"

    .line 150
    .line 151
    const-string v47, "dynamite_version"

    .line 152
    .line 153
    const-string v48, "ALTER TABLE apps ADD COLUMN dynamite_version INTEGER;"

    .line 154
    .line 155
    const-string v49, "safelisted_events"

    .line 156
    .line 157
    const-string v50, "ALTER TABLE apps ADD COLUMN safelisted_events TEXT;"

    .line 158
    .line 159
    const-string v51, "ga_app_id"

    .line 160
    .line 161
    const-string v52, "ALTER TABLE apps ADD COLUMN ga_app_id TEXT;"

    .line 162
    .line 163
    const-string v53, "config_last_modified_time"

    .line 164
    .line 165
    const-string v54, "ALTER TABLE apps ADD COLUMN config_last_modified_time TEXT;"

    .line 166
    .line 167
    const-string v55, "e_tag"

    .line 168
    .line 169
    const-string v56, "ALTER TABLE apps ADD COLUMN e_tag TEXT;"

    .line 170
    .line 171
    const-string v57, "session_stitching_token"

    .line 172
    .line 173
    const-string v58, "ALTER TABLE apps ADD COLUMN session_stitching_token TEXT;"

    .line 174
    .line 175
    const-string v59, "sgtm_upload_enabled"

    .line 176
    .line 177
    const-string v60, "ALTER TABLE apps ADD COLUMN sgtm_upload_enabled INTEGER;"

    .line 178
    .line 179
    const-string v61, "target_os_version"

    .line 180
    .line 181
    const-string v62, "ALTER TABLE apps ADD COLUMN target_os_version INTEGER;"

    .line 182
    .line 183
    const-string v63, "session_stitching_token_hash"

    .line 184
    .line 185
    const-string v64, "ALTER TABLE apps ADD COLUMN session_stitching_token_hash INTEGER;"

    .line 186
    .line 187
    const-string v65, "ad_services_version"

    .line 188
    .line 189
    const-string v66, "ALTER TABLE apps ADD COLUMN ad_services_version INTEGER;"

    .line 190
    .line 191
    const-string v67, "unmatched_first_open_without_ad_id"

    .line 192
    .line 193
    const-string v68, "ALTER TABLE apps ADD COLUMN unmatched_first_open_without_ad_id INTEGER;"

    .line 194
    .line 195
    const-string v69, "npa_metadata_value"

    .line 196
    .line 197
    const-string v70, "ALTER TABLE apps ADD COLUMN npa_metadata_value INTEGER;"

    .line 198
    .line 199
    const-string v71, "attribution_eligibility_status"

    .line 200
    .line 201
    const-string v72, "ALTER TABLE apps ADD COLUMN attribution_eligibility_status INTEGER;"

    .line 202
    .line 203
    const-string v73, "sgtm_preview_key"

    .line 204
    .line 205
    const-string v74, "ALTER TABLE apps ADD COLUMN sgtm_preview_key TEXT;"

    .line 206
    .line 207
    const-string v75, "dma_consent_state"

    .line 208
    .line 209
    const-string v76, "ALTER TABLE apps ADD COLUMN dma_consent_state INTEGER;"

    .line 210
    .line 211
    const-string v77, "daily_realtime_dcu_count"

    .line 212
    .line 213
    const-string v78, "ALTER TABLE apps ADD COLUMN daily_realtime_dcu_count INTEGER;"

    .line 214
    .line 215
    const-string v79, "bundle_delivery_index"

    .line 216
    .line 217
    const-string v80, "ALTER TABLE apps ADD COLUMN bundle_delivery_index INTEGER;"

    .line 218
    .line 219
    const-string v81, "serialized_npa_metadata"

    .line 220
    .line 221
    const-string v82, "ALTER TABLE apps ADD COLUMN serialized_npa_metadata TEXT;"

    .line 222
    .line 223
    const-string v83, "unmatched_pfo"

    .line 224
    .line 225
    const-string v84, "ALTER TABLE apps ADD COLUMN unmatched_pfo INTEGER;"

    .line 226
    .line 227
    const-string v85, "unmatched_uwa"

    .line 228
    .line 229
    const-string v86, "ALTER TABLE apps ADD COLUMN unmatched_uwa INTEGER;"

    .line 230
    .line 231
    const-string v87, "ad_campaign_info"

    .line 232
    .line 233
    const-string v88, "ALTER TABLE apps ADD COLUMN ad_campaign_info BLOB;"

    .line 234
    .line 235
    const-string v89, "daily_registered_triggers_count"

    .line 236
    .line 237
    const-string v90, "ALTER TABLE apps ADD COLUMN daily_registered_triggers_count INTEGER;"

    .line 238
    .line 239
    const-string v91, "client_upload_eligibility"

    .line 240
    .line 241
    const-string v92, "ALTER TABLE apps ADD COLUMN client_upload_eligibility INTEGER;"

    .line 242
    .line 243
    filled-new-array/range {v1 .. v94}, [Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    sput-object v0, Lvp/n;->m:[Ljava/lang/String;

    .line 248
    .line 249
    const-string v0, "realtime"

    .line 250
    .line 251
    const-string v1, "ALTER TABLE raw_events ADD COLUMN realtime INTEGER;"

    .line 252
    .line 253
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v0

    .line 257
    sput-object v0, Lvp/n;->n:[Ljava/lang/String;

    .line 258
    .line 259
    const-string v0, "retry_count"

    .line 260
    .line 261
    const-string v1, "ALTER TABLE queue ADD COLUMN retry_count INTEGER;"

    .line 262
    .line 263
    const-string v2, "has_realtime"

    .line 264
    .line 265
    const-string v3, "ALTER TABLE queue ADD COLUMN has_realtime INTEGER;"

    .line 266
    .line 267
    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    sput-object v0, Lvp/n;->o:[Ljava/lang/String;

    .line 272
    .line 273
    const-string v0, "ALTER TABLE event_filters ADD COLUMN session_scoped BOOLEAN;"

    .line 274
    .line 275
    const-string v1, "session_scoped"

    .line 276
    .line 277
    filled-new-array {v1, v0}, [Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object v0

    .line 281
    sput-object v0, Lvp/n;->p:[Ljava/lang/String;

    .line 282
    .line 283
    const-string v0, "ALTER TABLE property_filters ADD COLUMN session_scoped BOOLEAN;"

    .line 284
    .line 285
    filled-new-array {v1, v0}, [Ljava/lang/String;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    sput-object v0, Lvp/n;->q:[Ljava/lang/String;

    .line 290
    .line 291
    const-string v0, "previous_install_count"

    .line 292
    .line 293
    const-string v1, "ALTER TABLE app2 ADD COLUMN previous_install_count INTEGER;"

    .line 294
    .line 295
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    sput-object v0, Lvp/n;->r:[Ljava/lang/String;

    .line 300
    .line 301
    const-string v5, "storage_consent_at_bundling"

    .line 302
    .line 303
    const-string v6, "ALTER TABLE consent_settings ADD COLUMN storage_consent_at_bundling TEXT;"

    .line 304
    .line 305
    const-string v1, "consent_source"

    .line 306
    .line 307
    const-string v2, "ALTER TABLE consent_settings ADD COLUMN consent_source INTEGER;"

    .line 308
    .line 309
    const-string v3, "dma_consent_settings"

    .line 310
    .line 311
    const-string v4, "ALTER TABLE consent_settings ADD COLUMN dma_consent_settings TEXT;"

    .line 312
    .line 313
    filled-new-array/range {v1 .. v6}, [Ljava/lang/String;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    sput-object v0, Lvp/n;->s:[Ljava/lang/String;

    .line 318
    .line 319
    const-string v0, "idempotent"

    .line 320
    .line 321
    const-string v1, "CREATE INDEX IF NOT EXISTS trigger_uris_index ON trigger_uris (app_id);"

    .line 322
    .line 323
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    sput-object v0, Lvp/n;->t:[Ljava/lang/String;

    .line 328
    .line 329
    return-void
.end method

.method public constructor <init>(Lvp/z3;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lvp/u3;-><init>(Lvp/z3;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Lg1/i3;

    .line 5
    .line 6
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvp/g1;

    .line 9
    .line 10
    iget-object v0, v0, Lvp/g1;->n:Lto/a;

    .line 11
    .line 12
    invoke-direct {p1, v0}, Lg1/i3;-><init>(Lto/a;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lvp/n;->i:Lg1/i3;

    .line 16
    .line 17
    iget-object p1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Lvp/g1;

    .line 20
    .line 21
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    new-instance p1, Lvp/m;

    .line 25
    .line 26
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Lvp/g1;

    .line 29
    .line 30
    iget-object v0, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 31
    .line 32
    invoke-direct {p1, p0, v0}, Lvp/m;-><init>(Lvp/n;Landroid/content/Context;)V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lvp/n;->h:Lvp/m;

    .line 36
    .line 37
    return-void
.end method

.method public static final D0(Ljava/util/List;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-string p0, ""

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    const-string v0, ", "

    .line 11
    .line 12
    invoke-static {v0, p0}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string v0, " AND (upload_type IN ("

    .line 17
    .line 18
    const-string v1, "))"

    .line 19
    .line 20
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public static final J0(Landroid/content/ContentValues;Ljava/lang/Object;)V
    .locals 2

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    instance-of v1, p1, Ljava/lang/String;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    check-cast p1, Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {p0, v0, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    instance-of v1, p1, Ljava/lang/Long;

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    check-cast p1, Ljava/lang/Long;

    .line 24
    .line 25
    invoke-virtual {p0, v0, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_1
    instance-of v1, p1, Ljava/lang/Double;

    .line 30
    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    check-cast p1, Ljava/lang/Double;

    .line 34
    .line 35
    invoke-virtual {p0, v0, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Double;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 40
    .line 41
    const-string p1, "Invalid value type"

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0
.end method


# virtual methods
.method public final A0(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 8
    .line 9
    .line 10
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const-string v1, "app_id=?"

    .line 15
    .line 16
    filled-new-array {p2}, [Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual {v0, p1, v1, v2}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :catch_0
    move-exception p1

    .line 25
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lvp/g1;

    .line 28
    .line 29
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 30
    .line 31
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 35
    .line 36
    invoke-static {p2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    const-string v0, "Error deleting snapshot. appId"

    .line 41
    .line 42
    invoke-virtual {p0, p2, p1, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public final B0(Ljava/lang/String;J[BLjava/lang/String;Ljava/lang/String;IIJJJ)Lvp/a4;
    .locals 16

    .line 1
    move-object/from16 v0, p6

    .line 2
    .line 3
    move/from16 v13, p8

    .line 4
    .line 5
    move-object/from16 v1, p0

    .line 6
    .line 7
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    move-object v14, v1

    .line 10
    check-cast v14, Lvp/g1;

    .line 11
    .line 12
    invoke-static/range {p5 .. p5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/4 v15, 0x0

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    iget-object v0, v14, Lvp/g1;->i:Lvp/p0;

    .line 20
    .line 21
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, v0, Lvp/p0;->q:Lvp/n0;

    .line 25
    .line 26
    const-string v1, "Upload uri is null or empty. Destination is unknown. Dropping batch. "

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-object v15

    .line 32
    :cond_0
    :try_start_0
    invoke-static {}, Lcom/google/android/gms/internal/measurement/h3;->w()Lcom/google/android/gms/internal/measurement/g3;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    move-object/from16 v2, p4

    .line 37
    .line 38
    invoke-static {v1, v2}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    check-cast v1, Lcom/google/android/gms/internal/measurement/g3;

    .line 43
    .line 44
    invoke-static {}, Lvp/q2;->values()[Lvp/q2;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    array-length v3, v2

    .line 49
    const/4 v4, 0x0

    .line 50
    move v5, v4

    .line 51
    :goto_0
    if-ge v5, v3, :cond_2

    .line 52
    .line 53
    aget-object v6, v2, v5

    .line 54
    .line 55
    iget v7, v6, Lvp/q2;->d:I

    .line 56
    .line 57
    move/from16 v8, p7

    .line 58
    .line 59
    if-ne v7, v8, :cond_1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    add-int/lit8 v5, v5, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    sget-object v6, Lvp/q2;->j:Lvp/q2;

    .line 66
    .line 67
    :goto_1
    sget-object v2, Lvp/q2;->f:Lvp/q2;

    .line 68
    .line 69
    if-eq v6, v2, :cond_4

    .line 70
    .line 71
    sget-object v2, Lvp/q2;->i:Lvp/q2;

    .line 72
    .line 73
    if-eq v6, v2, :cond_4

    .line 74
    .line 75
    if-lez v13, :cond_4

    .line 76
    .line 77
    new-instance v2, Ljava/util/ArrayList;

    .line 78
    .line 79
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 80
    .line 81
    .line 82
    iget-object v3, v1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 83
    .line 84
    check-cast v3, Lcom/google/android/gms/internal/measurement/h3;

    .line 85
    .line 86
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/h3;->p()Ljava/util/List;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-static {v3}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    if-eqz v5, :cond_3

    .line 103
    .line 104
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    check-cast v5, Lcom/google/android/gms/internal/measurement/j3;

    .line 109
    .line 110
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/l5;->i()Lcom/google/android/gms/internal/measurement/k5;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    check-cast v5, Lcom/google/android/gms/internal/measurement/i3;

    .line 115
    .line 116
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 117
    .line 118
    .line 119
    iget-object v7, v5, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 120
    .line 121
    check-cast v7, Lcom/google/android/gms/internal/measurement/j3;

    .line 122
    .line 123
    invoke-virtual {v7, v13}, Lcom/google/android/gms/internal/measurement/j3;->T0(I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    check-cast v5, Lcom/google/android/gms/internal/measurement/j3;

    .line 131
    .line 132
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    goto :goto_2

    .line 136
    :catch_0
    move-exception v0

    .line 137
    goto :goto_5

    .line 138
    :cond_3
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 139
    .line 140
    .line 141
    iget-object v3, v1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 142
    .line 143
    check-cast v3, Lcom/google/android/gms/internal/measurement/h3;

    .line 144
    .line 145
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/h3;->B()V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 149
    .line 150
    .line 151
    iget-object v3, v1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 152
    .line 153
    check-cast v3, Lcom/google/android/gms/internal/measurement/h3;

    .line 154
    .line 155
    invoke-virtual {v3, v2}, Lcom/google/android/gms/internal/measurement/h3;->A(Ljava/util/ArrayList;)V

    .line 156
    .line 157
    .line 158
    :cond_4
    new-instance v5, Ljava/util/HashMap;

    .line 159
    .line 160
    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 161
    .line 162
    .line 163
    if-eqz v0, :cond_7

    .line 164
    .line 165
    const-string v2, "\r\n"

    .line 166
    .line 167
    invoke-virtual {v0, v2}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    array-length v2, v0

    .line 172
    move v3, v4

    .line 173
    :goto_3
    if-ge v3, v2, :cond_7

    .line 174
    .line 175
    aget-object v7, v0, v3

    .line 176
    .line 177
    invoke-virtual {v7}, Ljava/lang/String;->isEmpty()Z

    .line 178
    .line 179
    .line 180
    move-result v8

    .line 181
    if-eqz v8, :cond_5

    .line 182
    .line 183
    goto :goto_4

    .line 184
    :cond_5
    const-string v8, "="

    .line 185
    .line 186
    const/4 v9, 0x2

    .line 187
    invoke-virtual {v7, v8, v9}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v8

    .line 191
    array-length v10, v8

    .line 192
    if-eq v10, v9, :cond_6

    .line 193
    .line 194
    iget-object v0, v14, Lvp/g1;->i:Lvp/p0;

    .line 195
    .line 196
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 197
    .line 198
    .line 199
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 200
    .line 201
    const-string v2, "Invalid upload header: "

    .line 202
    .line 203
    invoke-virtual {v0, v7, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    goto :goto_4

    .line 207
    :cond_6
    aget-object v7, v8, v4

    .line 208
    .line 209
    const/4 v9, 0x1

    .line 210
    aget-object v8, v8, v9

    .line 211
    .line 212
    invoke-virtual {v5, v7, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    add-int/lit8 v3, v3, 0x1

    .line 216
    .line 217
    goto :goto_3

    .line 218
    :cond_7
    :goto_4
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    move-object v3, v0

    .line 223
    check-cast v3, Lcom/google/android/gms/internal/measurement/h3;

    .line 224
    .line 225
    new-instance v0, Lvp/a4;

    .line 226
    .line 227
    move-wide/from16 v1, p2

    .line 228
    .line 229
    move-object/from16 v4, p5

    .line 230
    .line 231
    move-wide/from16 v7, p9

    .line 232
    .line 233
    move-wide/from16 v9, p11

    .line 234
    .line 235
    move-wide/from16 v11, p13

    .line 236
    .line 237
    invoke-direct/range {v0 .. v13}, Lvp/a4;-><init>(JLcom/google/android/gms/internal/measurement/h3;Ljava/lang/String;Ljava/util/HashMap;Lvp/q2;JJJI)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 238
    .line 239
    .line 240
    return-object v0

    .line 241
    :goto_5
    iget-object v1, v14, Lvp/g1;->i:Lvp/p0;

    .line 242
    .line 243
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 244
    .line 245
    .line 246
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 247
    .line 248
    const-string v2, "Failed to queued MeasurementBatch from upload_queue. appId"

    .line 249
    .line 250
    move-object/from16 v3, p1

    .line 251
    .line 252
    invoke-virtual {v1, v3, v0, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    return-object v15
.end method

.method public final C0()Ljava/lang/String;
    .locals 7

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    iget-object p0, p0, Lvp/g1;->n:Lto/a;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    sget-object p0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 15
    .line 16
    sget-object p0, Lvp/z;->S:Lvp/y;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {p0, v2}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Ljava/lang/Long;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    new-instance v3, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v4, "(upload_type = 1 AND ABS(creation_timestamp - "

    .line 31
    .line 32
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v3, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string v4, ") > "

    .line 39
    .line 40
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string p0, ")"

    .line 47
    .line 48
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    sget-object v5, Lvp/z;->R:Lvp/y;

    .line 56
    .line 57
    invoke-virtual {v5, v2}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    check-cast v2, Ljava/lang/Long;

    .line 62
    .line 63
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 64
    .line 65
    .line 66
    move-result-wide v5

    .line 67
    const-string v2, "(upload_type != 1 AND ABS(creation_timestamp - "

    .line 68
    .line 69
    invoke-static {v0, v1, v2, v4}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-static {v5, v6, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    new-instance v4, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    add-int/lit8 v1, v1, 0x5

    .line 88
    .line 89
    add-int/2addr v1, v2

    .line 90
    add-int/lit8 v1, v1, 0x1

    .line 91
    .line 92
    invoke-direct {v4, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 93
    .line 94
    .line 95
    const-string v1, "("

    .line 96
    .line 97
    const-string v2, " OR "

    .line 98
    .line 99
    invoke-static {v4, v1, v3, v2, v0}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    return-object p0
.end method

.method public final E0(Ljava/lang/String;Lvp/s1;)V
    .locals 2

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lvp/n;->t0(Ljava/lang/String;)Lvp/s1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p0, p1, v0}, Lvp/n;->v0(Ljava/lang/String;Lvp/s1;)V

    .line 15
    .line 16
    .line 17
    new-instance v0, Landroid/content/ContentValues;

    .line 18
    .line 19
    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 20
    .line 21
    .line 22
    const-string v1, "app_id"

    .line 23
    .line 24
    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const-string p1, "storage_consent_at_bundling"

    .line 28
    .line 29
    invoke-virtual {p2}, Lvp/s1;->g()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    invoke-virtual {v0, p1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, v0}, Lvp/n;->x0(Landroid/content/ContentValues;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public final F0(Ljava/lang/String;)Lvp/s1;
    .locals 1

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 8
    .line 9
    .line 10
    filled-new-array {p1}, [Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-string v0, "select storage_consent_at_bundling from consent_settings where app_id=? limit 1;"

    .line 15
    .line 16
    invoke-virtual {p0, v0, p1}, Lvp/n;->w0(Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/16 p1, 0x64

    .line 21
    .line 22
    invoke-static {p1, p0}, Lvp/s1;->c(ILjava/lang/String;)Lvp/s1;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public final G0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lvp/r;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "events"

    .line 4
    .line 5
    invoke-virtual/range {p2 .. p2}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    move-object/from16 v4, p1

    .line 10
    .line 11
    invoke-virtual {v0, v1, v4, v2}, Lvp/n;->y0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lvp/r;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lvp/g1;

    .line 20
    .line 21
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 22
    .line 23
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 27
    .line 28
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iget-object v0, v0, Lvp/g1;->m:Lvp/k0;

    .line 33
    .line 34
    move-object/from16 v3, p3

    .line 35
    .line 36
    invoke-virtual {v0, v3}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    const-string v3, "Event aggregate wasn\'t created during raw event logging. appId, event"

    .line 41
    .line 42
    invoke-virtual {v1, v2, v0, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    new-instance v3, Lvp/r;

    .line 46
    .line 47
    invoke-virtual/range {p2 .. p2}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    invoke-virtual/range {p2 .. p2}, Lcom/google/android/gms/internal/measurement/b3;->u()J

    .line 52
    .line 53
    .line 54
    move-result-wide v12

    .line 55
    const/16 v18, 0x0

    .line 56
    .line 57
    const/16 v19, 0x0

    .line 58
    .line 59
    const-wide/16 v6, 0x1

    .line 60
    .line 61
    const-wide/16 v8, 0x1

    .line 62
    .line 63
    const-wide/16 v10, 0x1

    .line 64
    .line 65
    const-wide/16 v14, 0x0

    .line 66
    .line 67
    const/16 v16, 0x0

    .line 68
    .line 69
    const/16 v17, 0x0

    .line 70
    .line 71
    invoke-direct/range {v3 .. v19}, Lvp/r;-><init>(Ljava/lang/String;Ljava/lang/String;JJJJJLjava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Boolean;)V

    .line 72
    .line 73
    .line 74
    return-object v3

    .line 75
    :cond_0
    iget-wide v2, v1, Lvp/r;->e:J

    .line 76
    .line 77
    const-wide/16 v4, 0x1

    .line 78
    .line 79
    add-long v13, v2, v4

    .line 80
    .line 81
    iget-wide v2, v1, Lvp/r;->d:J

    .line 82
    .line 83
    add-long v11, v2, v4

    .line 84
    .line 85
    iget-wide v2, v1, Lvp/r;->c:J

    .line 86
    .line 87
    add-long v9, v2, v4

    .line 88
    .line 89
    new-instance v6, Lvp/r;

    .line 90
    .line 91
    iget-object v7, v1, Lvp/r;->a:Ljava/lang/String;

    .line 92
    .line 93
    iget-object v8, v1, Lvp/r;->b:Ljava/lang/String;

    .line 94
    .line 95
    iget-wide v2, v1, Lvp/r;->f:J

    .line 96
    .line 97
    iget-wide v4, v1, Lvp/r;->g:J

    .line 98
    .line 99
    iget-object v0, v1, Lvp/r;->h:Ljava/lang/Long;

    .line 100
    .line 101
    iget-object v15, v1, Lvp/r;->i:Ljava/lang/Long;

    .line 102
    .line 103
    move-object/from16 v19, v0

    .line 104
    .line 105
    iget-object v0, v1, Lvp/r;->j:Ljava/lang/Long;

    .line 106
    .line 107
    iget-object v1, v1, Lvp/r;->k:Ljava/lang/Boolean;

    .line 108
    .line 109
    move-object/from16 v21, v0

    .line 110
    .line 111
    move-object/from16 v22, v1

    .line 112
    .line 113
    move-wide/from16 v17, v4

    .line 114
    .line 115
    move-object/from16 v20, v15

    .line 116
    .line 117
    move-wide v15, v2

    .line 118
    invoke-direct/range {v6 .. v22}, Lvp/r;-><init>(Ljava/lang/String;Ljava/lang/String;JJJJJLjava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Boolean;)V

    .line 119
    .line 120
    .line 121
    return-object v6
.end method

.method public final H0()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    iget-object p0, p0, Lvp/g1;->d:Landroid/content/Context;

    .line 6
    .line 7
    const-string v0, "google_app_measurement.db"

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p0}, Ljava/io/File;->exists()Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final I0(Ljava/lang/String;JJLgb/d;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p6

    .line 4
    .line 5
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lvp/g1;

    .line 8
    .line 9
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 13
    .line 14
    .line 15
    const-string v3, " order by rowid limit 1;"

    .line 16
    .line 17
    const-string v4, "select metadata_fingerprint from raw_events where app_id = ?"

    .line 18
    .line 19
    const-string v5, "app_id in (select app_id from apps where config_fetched_time >= ?) order by rowid limit 1;"

    .line 20
    .line 21
    const-string v6, "select app_id, metadata_fingerprint from raw_events where "

    .line 22
    .line 23
    const/4 v7, 0x0

    .line 24
    :try_start_0
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 25
    .line 26
    .line 27
    move-result-object v8

    .line 28
    invoke-static/range {p1 .. p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 29
    .line 30
    .line 31
    move-result v9
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 32
    const/4 v10, 0x1

    .line 33
    const-string v11, ""

    .line 34
    .line 35
    const/4 v12, 0x0

    .line 36
    const-wide/16 v13, -0x1

    .line 37
    .line 38
    if-eqz v9, :cond_3

    .line 39
    .line 40
    cmp-long v3, p4, v13

    .line 41
    .line 42
    if-eqz v3, :cond_0

    .line 43
    .line 44
    :try_start_1
    invoke-static/range {p4 .. p5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    invoke-static/range {p2 .. p3}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v9

    .line 52
    filled-new-array {v4, v9}, [Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    goto :goto_0

    .line 57
    :catch_0
    move-exception v0

    .line 58
    move-object/from16 v9, p1

    .line 59
    .line 60
    goto/16 :goto_c

    .line 61
    .line 62
    :cond_0
    invoke-static/range {p2 .. p3}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    filled-new-array {v4}, [Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    :goto_0
    if-eqz v3, :cond_1

    .line 71
    .line 72
    const-string v11, "rowid <= ? and "

    .line 73
    .line 74
    :cond_1
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    add-int/lit16 v3, v3, 0x94

    .line 79
    .line 80
    new-instance v9, Ljava/lang/StringBuilder;

    .line 81
    .line 82
    invoke-direct {v9, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v9, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    invoke-virtual {v8, v3, v4}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 99
    .line 100
    .line 101
    move-result-object v3
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 102
    :try_start_2
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    if-nez v4, :cond_2

    .line 107
    .line 108
    goto/16 :goto_e

    .line 109
    .line 110
    :cond_2
    invoke-interface {v3, v12}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v4
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 114
    :try_start_3
    invoke-interface {v3, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v5

    .line 118
    invoke-interface {v3}, Landroid/database/Cursor;->close()V
    :try_end_3
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 119
    .line 120
    .line 121
    goto :goto_5

    .line 122
    :catchall_0
    move-exception v0

    .line 123
    goto :goto_2

    .line 124
    :catch_1
    move-exception v0

    .line 125
    :goto_1
    move-object v7, v3

    .line 126
    goto/16 :goto_d

    .line 127
    .line 128
    :catch_2
    move-exception v0

    .line 129
    goto :goto_3

    .line 130
    :goto_2
    move-object v7, v3

    .line 131
    goto/16 :goto_f

    .line 132
    .line 133
    :goto_3
    move-object/from16 v4, p1

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_3
    cmp-long v5, p4, v13

    .line 137
    .line 138
    if-eqz v5, :cond_4

    .line 139
    .line 140
    :try_start_4
    invoke-static/range {p4 .. p5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v6
    :try_end_4
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 144
    move-object/from16 v9, p1

    .line 145
    .line 146
    :try_start_5
    filled-new-array {v9, v6}, [Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v6

    .line 150
    goto :goto_4

    .line 151
    :catch_3
    move-exception v0

    .line 152
    goto/16 :goto_c

    .line 153
    .line 154
    :cond_4
    move-object/from16 v9, p1

    .line 155
    .line 156
    filled-new-array {v9}, [Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v6

    .line 160
    :goto_4
    if-eqz v5, :cond_5

    .line 161
    .line 162
    const-string v11, " and rowid <= ?"

    .line 163
    .line 164
    :cond_5
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 165
    .line 166
    .line 167
    move-result v5

    .line 168
    add-int/lit8 v5, v5, 0x54

    .line 169
    .line 170
    new-instance v15, Ljava/lang/StringBuilder;

    .line 171
    .line 172
    invoke-direct {v15, v5}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v15, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    invoke-virtual {v15, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-virtual {v15, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    invoke-virtual {v15}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    invoke-virtual {v8, v3, v6}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 189
    .line 190
    .line 191
    move-result-object v3
    :try_end_5
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_5 .. :try_end_5} :catch_3
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 192
    :try_start_6
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 193
    .line 194
    .line 195
    move-result v4

    .line 196
    if-nez v4, :cond_6

    .line 197
    .line 198
    goto/16 :goto_e

    .line 199
    .line 200
    :cond_6
    invoke-interface {v3, v12}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v5

    .line 204
    invoke-interface {v3}, Landroid/database/Cursor;->close()V
    :try_end_6
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_6 .. :try_end_6} :catch_7
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 205
    .line 206
    .line 207
    move-object v4, v9

    .line 208
    :goto_5
    :try_start_7
    const-string v9, "raw_events_metadata"

    .line 209
    .line 210
    const-string v6, "metadata"

    .line 211
    .line 212
    filled-new-array {v6}, [Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v6

    .line 216
    const-string v11, "app_id = ? and metadata_fingerprint = ?"

    .line 217
    .line 218
    move v15, v12

    .line 219
    filled-new-array {v4, v5}, [Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v12

    .line 223
    move/from16 v16, v15

    .line 224
    .line 225
    const-string v15, "rowid"

    .line 226
    .line 227
    move/from16 v17, v16

    .line 228
    .line 229
    const-string v16, "2"

    .line 230
    .line 231
    move-wide/from16 v18, v13

    .line 232
    .line 233
    const/4 v13, 0x0

    .line 234
    const/4 v14, 0x0

    .line 235
    move-object v10, v6

    .line 236
    move/from16 v6, v17

    .line 237
    .line 238
    invoke-virtual/range {v8 .. v16}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 239
    .line 240
    .line 241
    move-result-object v3

    .line 242
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 243
    .line 244
    .line 245
    move-result v9

    .line 246
    if-nez v9, :cond_7

    .line 247
    .line 248
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 249
    .line 250
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 251
    .line 252
    .line 253
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 254
    .line 255
    const-string v1, "Raw event metadata record is missing. appId"

    .line 256
    .line 257
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 258
    .line 259
    .line 260
    move-result-object v5

    .line 261
    invoke-virtual {v0, v5, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    goto/16 :goto_e

    .line 265
    .line 266
    :cond_7
    invoke-interface {v3, v6}, Landroid/database/Cursor;->getBlob(I)[B

    .line 267
    .line 268
    .line 269
    move-result-object v9
    :try_end_7
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_7 .. :try_end_7} :catch_1
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 270
    :try_start_8
    invoke-static {}, Lcom/google/android/gms/internal/measurement/j3;->U()Lcom/google/android/gms/internal/measurement/i3;

    .line 271
    .line 272
    .line 273
    move-result-object v10

    .line 274
    invoke-static {v10, v9}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 275
    .line 276
    .line 277
    move-result-object v9

    .line 278
    check-cast v9, Lcom/google/android/gms/internal/measurement/i3;

    .line 279
    .line 280
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 281
    .line 282
    .line 283
    move-result-object v9

    .line 284
    check-cast v9, Lcom/google/android/gms/internal/measurement/j3;
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_6
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_8 .. :try_end_8} :catch_1
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 285
    .line 286
    :try_start_9
    invoke-interface {v3}, Landroid/database/Cursor;->moveToNext()Z

    .line 287
    .line 288
    .line 289
    move-result v10

    .line 290
    if-eqz v10, :cond_8

    .line 291
    .line 292
    iget-object v10, v2, Lvp/g1;->i:Lvp/p0;

    .line 293
    .line 294
    invoke-static {v10}, Lvp/g1;->k(Lvp/n1;)V

    .line 295
    .line 296
    .line 297
    iget-object v10, v10, Lvp/p0;->m:Lvp/n0;

    .line 298
    .line 299
    const-string v11, "Get multiple raw event metadata records, expected one. appId"

    .line 300
    .line 301
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 302
    .line 303
    .line 304
    move-result-object v12

    .line 305
    invoke-virtual {v10, v12, v11}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    :cond_8
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 309
    .line 310
    .line 311
    iput-object v9, v1, Lgb/d;->b:Ljava/lang/Object;

    .line 312
    .line 313
    iget-object v9, v2, Lvp/g1;->g:Lvp/h;

    .line 314
    .line 315
    sget-object v10, Lvp/z;->k1:Lvp/y;

    .line 316
    .line 317
    invoke-virtual {v9, v7, v10}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 318
    .line 319
    .line 320
    move-result v7
    :try_end_9
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_9 .. :try_end_9} :catch_1
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 321
    const-string v9, "app_id = ? and metadata_fingerprint = ? and rowid <= ?"

    .line 322
    .line 323
    const-string v10, "app_id = ? and metadata_fingerprint = ?"

    .line 324
    .line 325
    if-eqz v7, :cond_d

    .line 326
    .line 327
    :try_start_a
    filled-new-array {v4, v5}, [Ljava/lang/String;

    .line 328
    .line 329
    .line 330
    move-result-object v7

    .line 331
    const-string v11, "select (rowid - 1) as max_rowid from raw_events where app_id = ? and metadata_fingerprint != ? order by rowid limit 1;"

    .line 332
    .line 333
    const-wide/16 v12, -0x1

    .line 334
    .line 335
    invoke-virtual {v0, v11, v7, v12, v13}, Lvp/n;->L0(Ljava/lang/String;[Ljava/lang/String;J)J

    .line 336
    .line 337
    .line 338
    move-result-wide v14

    .line 339
    cmp-long v0, p4, v12

    .line 340
    .line 341
    if-nez v0, :cond_a

    .line 342
    .line 343
    cmp-long v0, v14, v12

    .line 344
    .line 345
    if-eqz v0, :cond_9

    .line 346
    .line 347
    move-wide v10, v12

    .line 348
    goto :goto_7

    .line 349
    :cond_9
    filled-new-array {v4, v5}, [Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    :goto_6
    move-object v12, v0

    .line 354
    move-object v11, v10

    .line 355
    goto :goto_a

    .line 356
    :cond_a
    move-wide/from16 v10, p4

    .line 357
    .line 358
    :goto_7
    cmp-long v0, v10, v12

    .line 359
    .line 360
    if-eqz v0, :cond_b

    .line 361
    .line 362
    cmp-long v7, v14, v12

    .line 363
    .line 364
    if-eqz v7, :cond_b

    .line 365
    .line 366
    invoke-static {v10, v11, v14, v15}, Ljava/lang/Math;->min(JJ)J

    .line 367
    .line 368
    .line 369
    move-result-wide v14

    .line 370
    goto :goto_8

    .line 371
    :cond_b
    if-eqz v0, :cond_c

    .line 372
    .line 373
    move-wide v14, v10

    .line 374
    :cond_c
    :goto_8
    invoke-static {v14, v15}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 375
    .line 376
    .line 377
    move-result-object v0

    .line 378
    filled-new-array {v4, v5, v0}, [Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object v0

    .line 382
    :goto_9
    move-object v12, v0

    .line 383
    move-object v11, v9

    .line 384
    goto :goto_a

    .line 385
    :cond_d
    const-wide/16 v12, -0x1

    .line 386
    .line 387
    cmp-long v0, p4, v12

    .line 388
    .line 389
    if-eqz v0, :cond_e

    .line 390
    .line 391
    invoke-static/range {p4 .. p5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    filled-new-array {v4, v5, v0}, [Ljava/lang/String;

    .line 396
    .line 397
    .line 398
    move-result-object v0

    .line 399
    goto :goto_9

    .line 400
    :cond_e
    filled-new-array {v4, v5}, [Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object v0

    .line 404
    goto :goto_6

    .line 405
    :goto_a
    const-string v9, "raw_events"

    .line 406
    .line 407
    const-string v0, "rowid"

    .line 408
    .line 409
    const-string v5, "name"

    .line 410
    .line 411
    const-string v7, "timestamp"

    .line 412
    .line 413
    const-string v10, "data"

    .line 414
    .line 415
    filled-new-array {v0, v5, v7, v10}, [Ljava/lang/String;

    .line 416
    .line 417
    .line 418
    move-result-object v10

    .line 419
    const-string v15, "rowid"

    .line 420
    .line 421
    const/16 v16, 0x0

    .line 422
    .line 423
    const/4 v13, 0x0

    .line 424
    const/4 v14, 0x0

    .line 425
    invoke-virtual/range {v8 .. v16}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 426
    .line 427
    .line 428
    move-result-object v7
    :try_end_a
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_a .. :try_end_a} :catch_1
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 429
    :try_start_b
    invoke-interface {v7}, Landroid/database/Cursor;->moveToFirst()Z

    .line 430
    .line 431
    .line 432
    move-result v0

    .line 433
    if-eqz v0, :cond_11

    .line 434
    .line 435
    :cond_f
    invoke-interface {v7, v6}, Landroid/database/Cursor;->getLong(I)J

    .line 436
    .line 437
    .line 438
    move-result-wide v8

    .line 439
    const/4 v0, 0x3

    .line 440
    invoke-interface {v7, v0}, Landroid/database/Cursor;->getBlob(I)[B

    .line 441
    .line 442
    .line 443
    move-result-object v0
    :try_end_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_b .. :try_end_b} :catch_4
    .catchall {:try_start_b .. :try_end_b} :catchall_1

    .line 444
    :try_start_c
    invoke-static {}, Lcom/google/android/gms/internal/measurement/b3;->z()Lcom/google/android/gms/internal/measurement/a3;

    .line 445
    .line 446
    .line 447
    move-result-object v3

    .line 448
    invoke-static {v3, v0}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 449
    .line 450
    .line 451
    move-result-object v0

    .line 452
    check-cast v0, Lcom/google/android/gms/internal/measurement/a3;
    :try_end_c
    .catch Ljava/io/IOException; {:try_start_c .. :try_end_c} :catch_5
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_c .. :try_end_c} :catch_4
    .catchall {:try_start_c .. :try_end_c} :catchall_1

    .line 453
    .line 454
    const/4 v3, 0x1

    .line 455
    :try_start_d
    invoke-interface {v7, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 456
    .line 457
    .line 458
    move-result-object v5

    .line 459
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 460
    .line 461
    .line 462
    iget-object v10, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 463
    .line 464
    check-cast v10, Lcom/google/android/gms/internal/measurement/b3;

    .line 465
    .line 466
    invoke-virtual {v10, v5}, Lcom/google/android/gms/internal/measurement/b3;->F(Ljava/lang/String;)V

    .line 467
    .line 468
    .line 469
    const/4 v5, 0x2

    .line 470
    invoke-interface {v7, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 471
    .line 472
    .line 473
    move-result-wide v10

    .line 474
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 475
    .line 476
    .line 477
    iget-object v5, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 478
    .line 479
    check-cast v5, Lcom/google/android/gms/internal/measurement/b3;

    .line 480
    .line 481
    invoke-virtual {v5, v10, v11}, Lcom/google/android/gms/internal/measurement/b3;->G(J)V

    .line 482
    .line 483
    .line 484
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    check-cast v0, Lcom/google/android/gms/internal/measurement/b3;

    .line 489
    .line 490
    invoke-virtual {v1, v8, v9, v0}, Lgb/d;->c(JLcom/google/android/gms/internal/measurement/b3;)Z

    .line 491
    .line 492
    .line 493
    move-result v0

    .line 494
    if-nez v0, :cond_10

    .line 495
    .line 496
    goto :goto_b

    .line 497
    :catchall_1
    move-exception v0

    .line 498
    goto :goto_f

    .line 499
    :catch_4
    move-exception v0

    .line 500
    goto :goto_d

    .line 501
    :catch_5
    move-exception v0

    .line 502
    const/4 v3, 0x1

    .line 503
    iget-object v5, v2, Lvp/g1;->i:Lvp/p0;

    .line 504
    .line 505
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 506
    .line 507
    .line 508
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 509
    .line 510
    const-string v8, "Data loss. Failed to merge raw event. appId"

    .line 511
    .line 512
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 513
    .line 514
    .line 515
    move-result-object v9

    .line 516
    invoke-virtual {v5, v9, v0, v8}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 517
    .line 518
    .line 519
    :cond_10
    invoke-interface {v7}, Landroid/database/Cursor;->moveToNext()Z

    .line 520
    .line 521
    .line 522
    move-result v0

    .line 523
    if-nez v0, :cond_f

    .line 524
    .line 525
    goto :goto_b

    .line 526
    :cond_11
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 527
    .line 528
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 529
    .line 530
    .line 531
    iget-object v0, v0, Lvp/p0;->m:Lvp/n0;

    .line 532
    .line 533
    const-string v1, "Raw event data disappeared while in transaction. appId"

    .line 534
    .line 535
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 536
    .line 537
    .line 538
    move-result-object v3

    .line 539
    invoke-virtual {v0, v3, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_d
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_d .. :try_end_d} :catch_4
    .catchall {:try_start_d .. :try_end_d} :catchall_1

    .line 540
    .line 541
    .line 542
    :goto_b
    move-object v3, v7

    .line 543
    goto :goto_e

    .line 544
    :catch_6
    move-exception v0

    .line 545
    :try_start_e
    iget-object v1, v2, Lvp/g1;->i:Lvp/p0;

    .line 546
    .line 547
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 548
    .line 549
    .line 550
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 551
    .line 552
    const-string v5, "Data loss. Failed to merge raw event metadata. appId"

    .line 553
    .line 554
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 555
    .line 556
    .line 557
    move-result-object v6

    .line 558
    invoke-virtual {v1, v6, v0, v5}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_e
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_e .. :try_end_e} :catch_1
    .catchall {:try_start_e .. :try_end_e} :catchall_0

    .line 559
    .line 560
    .line 561
    goto :goto_e

    .line 562
    :catch_7
    move-exception v0

    .line 563
    move-object v7, v3

    .line 564
    :goto_c
    move-object v4, v9

    .line 565
    :goto_d
    :try_start_f
    iget-object v1, v2, Lvp/g1;->i:Lvp/p0;

    .line 566
    .line 567
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 568
    .line 569
    .line 570
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 571
    .line 572
    const-string v2, "Data loss. Error selecting raw event. appId"

    .line 573
    .line 574
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 575
    .line 576
    .line 577
    move-result-object v3

    .line 578
    invoke-virtual {v1, v3, v0, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_1

    .line 579
    .line 580
    .line 581
    goto :goto_b

    .line 582
    :goto_e
    if-eqz v3, :cond_12

    .line 583
    .line 584
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 585
    .line 586
    .line 587
    :cond_12
    return-void

    .line 588
    :goto_f
    if-eqz v7, :cond_13

    .line 589
    .line 590
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 591
    .line 592
    .line 593
    :cond_13
    throw v0
.end method

.method public final K0(Ljava/lang/String;[Ljava/lang/String;)J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :try_start_0
    invoke-virtual {v0, p1, p2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-interface {v1}, Landroid/database/Cursor;->moveToFirst()Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-interface {v1, p2}, Landroid/database/Cursor;->getLong(I)J

    .line 18
    .line 19
    .line 20
    move-result-wide p0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 22
    .line 23
    .line 24
    return-wide p0

    .line 25
    :cond_0
    :try_start_1
    new-instance p2, Landroid/database/sqlite/SQLiteException;

    .line 26
    .line 27
    const-string v0, "Database returned empty set"

    .line 28
    .line 29
    invoke-direct {p2, v0}, Landroid/database/sqlite/SQLiteException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p2
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_0

    .line 35
    :catch_0
    move-exception p2

    .line 36
    :try_start_2
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lvp/g1;

    .line 39
    .line 40
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 41
    .line 42
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 46
    .line 47
    const-string v0, "Database error"

    .line 48
    .line 49
    invoke-virtual {p0, p1, p2, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 53
    :goto_0
    if-eqz v1, :cond_1

    .line 54
    .line 55
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 56
    .line 57
    .line 58
    :cond_1
    throw p0
.end method

.method public final L0(Ljava/lang/String;[Ljava/lang/String;J)J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :try_start_0
    invoke-virtual {v0, p1, p2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-interface {v1}, Landroid/database/Cursor;->moveToFirst()Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-interface {v1, p2}, Landroid/database/Cursor;->getLong(I)J

    .line 18
    .line 19
    .line 20
    move-result-wide p3
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    :cond_0
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 22
    .line 23
    .line 24
    return-wide p3

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto :goto_0

    .line 27
    :catch_0
    move-exception p2

    .line 28
    :try_start_1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Lvp/g1;

    .line 31
    .line 32
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 33
    .line 34
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 38
    .line 39
    const-string p3, "Database error"

    .line 40
    .line 41
    invoke-virtual {p0, p1, p2, p3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 45
    :goto_0
    if-eqz v1, :cond_1

    .line 46
    .line 47
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 48
    .line 49
    .line 50
    :cond_1
    throw p0
.end method

.method public final M0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final N0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final O0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final P0()Landroid/database/sqlite/SQLiteDatabase;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    iget-object v0, p0, Lvp/n;->h:Lvp/m;

    .line 5
    .line 6
    invoke-virtual {v0}, Lvp/m;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 7
    .line 8
    .line 9
    move-result-object p0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    return-object p0

    .line 11
    :catch_0
    move-exception v0

    .line 12
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lvp/g1;

    .line 15
    .line 16
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 17
    .line 18
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 22
    .line 23
    const-string v1, "Error opening database"

    .line 24
    .line 25
    invoke-virtual {p0, v0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v0
.end method

.method public final Q0(Ljava/lang/String;)V
    .locals 12

    .line 1
    const-string v0, "events_snapshot"

    .line 2
    .line 3
    invoke-virtual {p0, v0, p1}, Lvp/n;->A0(Ljava/lang/String;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v1, "name"

    .line 7
    .line 8
    invoke-static {v1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x0

    .line 13
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    const-string v4, "events"

    .line 18
    .line 19
    const/4 v11, 0x0

    .line 20
    new-array v5, v11, [Ljava/lang/String;

    .line 21
    .line 22
    invoke-interface {v1, v5}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    move-object v5, v1

    .line 27
    check-cast v5, [Ljava/lang/String;

    .line 28
    .line 29
    const-string v6, "app_id=?"

    .line 30
    .line 31
    filled-new-array {p1}, [Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v7

    .line 35
    const/4 v9, 0x0

    .line 36
    const/4 v10, 0x0

    .line 37
    const/4 v8, 0x0

    .line 38
    invoke-virtual/range {v3 .. v10}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-interface {v2}, Landroid/database/Cursor;->moveToFirst()Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    :cond_0
    invoke-interface {v2, v11}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    if-eqz v1, :cond_1

    .line 53
    .line 54
    const-string v3, "events"

    .line 55
    .line 56
    invoke-virtual {p0, v3, p1, v1}, Lvp/n;->y0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lvp/r;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    if-eqz v1, :cond_1

    .line 61
    .line 62
    invoke-virtual {p0, v0, v1}, Lvp/n;->z0(Ljava/lang/String;Lvp/r;)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :catchall_0
    move-exception v0

    .line 67
    move-object p0, v0

    .line 68
    goto :goto_3

    .line 69
    :catch_0
    move-exception v0

    .line 70
    goto :goto_1

    .line 71
    :cond_1
    :goto_0
    invoke-interface {v2}, Landroid/database/Cursor;->moveToNext()Z

    .line 72
    .line 73
    .line 74
    move-result v1
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 75
    if-nez v1, :cond_0

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :goto_1
    :try_start_1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p0, Lvp/g1;

    .line 81
    .line 82
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 83
    .line 84
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 85
    .line 86
    .line 87
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 88
    .line 89
    const-string v1, "Error creating snapshot. appId"

    .line 90
    .line 91
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {p0, p1, v0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 96
    .line 97
    .line 98
    :cond_2
    :goto_2
    if-eqz v2, :cond_3

    .line 99
    .line 100
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 101
    .line 102
    .line 103
    :cond_3
    return-void

    .line 104
    :goto_3
    if-eqz v2, :cond_4

    .line 105
    .line 106
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 107
    .line 108
    .line 109
    :cond_4
    throw p0
.end method

.method public final R0(Ljava/lang/String;)V
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    const-string v3, "events_snapshot"

    .line 6
    .line 7
    new-instance v0, Ljava/util/ArrayList;

    .line 8
    .line 9
    const-string v4, "lifetime_count"

    .line 10
    .line 11
    const-string v5, "name"

    .line 12
    .line 13
    filled-new-array {v5, v4}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    invoke-direct {v0, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 22
    .line 23
    .line 24
    const-string v4, "events"

    .line 25
    .line 26
    const-string v5, "_f"

    .line 27
    .line 28
    invoke-virtual {v1, v4, v2, v5}, Lvp/n;->y0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lvp/r;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    const-string v7, "_v"

    .line 33
    .line 34
    invoke-virtual {v1, v4, v2, v7}, Lvp/n;->y0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lvp/r;

    .line 35
    .line 36
    .line 37
    move-result-object v8

    .line 38
    invoke-virtual {v1, v4, v2}, Lvp/n;->A0(Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const/4 v9, 0x0

    .line 42
    const/4 v10, 0x0

    .line 43
    :try_start_0
    invoke-virtual {v1}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 44
    .line 45
    .line 46
    move-result-object v11

    .line 47
    const-string v12, "events_snapshot"

    .line 48
    .line 49
    new-array v13, v10, [Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {v0, v13}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    move-object v13, v0

    .line 56
    check-cast v13, [Ljava/lang/String;

    .line 57
    .line 58
    const-string v14, "app_id=?"

    .line 59
    .line 60
    filled-new-array {v2}, [Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v15

    .line 64
    const/16 v17, 0x0

    .line 65
    .line 66
    const/16 v18, 0x0

    .line 67
    .line 68
    const/16 v16, 0x0

    .line 69
    .line 70
    invoke-virtual/range {v11 .. v18}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 71
    .line 72
    .line 73
    move-result-object v9

    .line 74
    invoke-interface {v9}, Landroid/database/Cursor;->moveToFirst()Z

    .line 75
    .line 76
    .line 77
    move-result v0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 78
    if-nez v0, :cond_1

    .line 79
    .line 80
    invoke-interface {v9}, Landroid/database/Cursor;->close()V

    .line 81
    .line 82
    .line 83
    if-eqz v6, :cond_0

    .line 84
    .line 85
    :goto_0
    invoke-virtual {v1, v4, v6}, Lvp/n;->z0(Ljava/lang/String;Lvp/r;)V

    .line 86
    .line 87
    .line 88
    goto/16 :goto_8

    .line 89
    .line 90
    :cond_0
    if-eqz v8, :cond_8

    .line 91
    .line 92
    :goto_1
    invoke-virtual {v1, v4, v8}, Lvp/n;->z0(Ljava/lang/String;Lvp/r;)V

    .line 93
    .line 94
    .line 95
    goto/16 :goto_8

    .line 96
    .line 97
    :cond_1
    move v11, v10

    .line 98
    move v12, v11

    .line 99
    :cond_2
    :try_start_1
    invoke-interface {v9, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    const/4 v13, 0x1

    .line 104
    invoke-interface {v9, v13}, Landroid/database/Cursor;->getLong(I)J

    .line 105
    .line 106
    .line 107
    move-result-wide v14

    .line 108
    const-wide/16 v16, 0x1

    .line 109
    .line 110
    cmp-long v14, v14, v16

    .line 111
    .line 112
    if-ltz v14, :cond_4

    .line 113
    .line 114
    invoke-virtual {v5, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v14

    .line 118
    if-eqz v14, :cond_3

    .line 119
    .line 120
    move v11, v13

    .line 121
    goto :goto_2

    .line 122
    :cond_3
    invoke-virtual {v7, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v14

    .line 126
    if-eqz v14, :cond_4

    .line 127
    .line 128
    move v12, v13

    .line 129
    :cond_4
    :goto_2
    if-eqz v0, :cond_5

    .line 130
    .line 131
    invoke-virtual {v1, v3, v2, v0}, Lvp/n;->y0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lvp/r;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    if-eqz v0, :cond_5

    .line 136
    .line 137
    invoke-virtual {v1, v4, v0}, Lvp/n;->z0(Ljava/lang/String;Lvp/r;)V

    .line 138
    .line 139
    .line 140
    goto :goto_3

    .line 141
    :catchall_0
    move-exception v0

    .line 142
    goto :goto_4

    .line 143
    :catch_0
    move-exception v0

    .line 144
    goto :goto_5

    .line 145
    :cond_5
    :goto_3
    invoke-interface {v9}, Landroid/database/Cursor;->moveToNext()Z

    .line 146
    .line 147
    .line 148
    move-result v0
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 149
    if-nez v0, :cond_2

    .line 150
    .line 151
    goto :goto_7

    .line 152
    :goto_4
    move v10, v11

    .line 153
    goto :goto_9

    .line 154
    :goto_5
    move v10, v11

    .line 155
    goto :goto_6

    .line 156
    :catchall_1
    move-exception v0

    .line 157
    move v12, v10

    .line 158
    goto :goto_9

    .line 159
    :catch_1
    move-exception v0

    .line 160
    move v12, v10

    .line 161
    :goto_6
    :try_start_2
    iget-object v5, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast v5, Lvp/g1;

    .line 164
    .line 165
    iget-object v5, v5, Lvp/g1;->i:Lvp/p0;

    .line 166
    .line 167
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 168
    .line 169
    .line 170
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 171
    .line 172
    const-string v7, "Error querying snapshot. appId"

    .line 173
    .line 174
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 175
    .line 176
    .line 177
    move-result-object v11

    .line 178
    invoke-virtual {v5, v11, v0, v7}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 179
    .line 180
    .line 181
    move v11, v10

    .line 182
    :goto_7
    if-eqz v9, :cond_6

    .line 183
    .line 184
    invoke-interface {v9}, Landroid/database/Cursor;->close()V

    .line 185
    .line 186
    .line 187
    :cond_6
    if-nez v11, :cond_7

    .line 188
    .line 189
    if-eqz v6, :cond_7

    .line 190
    .line 191
    goto :goto_0

    .line 192
    :cond_7
    if-nez v12, :cond_8

    .line 193
    .line 194
    if-eqz v8, :cond_8

    .line 195
    .line 196
    goto :goto_1

    .line 197
    :cond_8
    :goto_8
    invoke-virtual {v1, v3, v2}, Lvp/n;->A0(Ljava/lang/String;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    return-void

    .line 201
    :catchall_2
    move-exception v0

    .line 202
    :goto_9
    if-eqz v9, :cond_9

    .line 203
    .line 204
    invoke-interface {v9}, Landroid/database/Cursor;->close()V

    .line 205
    .line 206
    .line 207
    :cond_9
    if-nez v10, :cond_b

    .line 208
    .line 209
    if-nez v6, :cond_a

    .line 210
    .line 211
    goto :goto_a

    .line 212
    :cond_a
    invoke-virtual {v1, v4, v6}, Lvp/n;->z0(Ljava/lang/String;Lvp/r;)V

    .line 213
    .line 214
    .line 215
    goto :goto_b

    .line 216
    :cond_b
    :goto_a
    if-nez v12, :cond_c

    .line 217
    .line 218
    if-eqz v8, :cond_c

    .line 219
    .line 220
    invoke-virtual {v1, v4, v8}, Lvp/n;->z0(Ljava/lang/String;Lvp/r;)V

    .line 221
    .line 222
    .line 223
    :cond_c
    :goto_b
    invoke-virtual {v1, v3, v2}, Lvp/n;->A0(Ljava/lang/String;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    throw v0
.end method

.method public final S0(Ljava/lang/String;Ljava/lang/String;)V
    .locals 4

    .line 1
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 11
    .line 12
    .line 13
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, "user_attributes"

    .line 18
    .line 19
    const-string v2, "app_id=? and name=?"

    .line 20
    .line 21
    filled-new-array {p1, p2}, [Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-virtual {v0, v1, v2, v3}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :catch_0
    move-exception v0

    .line 30
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lvp/g1;

    .line 33
    .line 34
    iget-object v1, p0, Lvp/g1;->i:Lvp/p0;

    .line 35
    .line 36
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 40
    .line 41
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iget-object p0, p0, Lvp/g1;->m:Lvp/k0;

    .line 46
    .line 47
    invoke-virtual {p0, p2}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string p2, "Error deleting user property. appId"

    .line 52
    .line 53
    invoke-virtual {v1, p2, p1, p0, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public final T0(Lvp/c4;)Z
    .locals 9

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    iget-object v1, p1, Lvp/c4;->b:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 11
    .line 12
    .line 13
    iget-object v2, p1, Lvp/c4;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lvp/c4;->c:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {p0, v2, v3}, Lvp/n;->U0(Ljava/lang/String;Ljava/lang/String;)Lvp/c4;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    if-nez v4, :cond_2

    .line 22
    .line 23
    invoke-static {v3}, Lvp/d4;->Y0(Ljava/lang/String;)Z

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    filled-new-array {v2}, [Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    const-string v5, "select count(1) from user_attributes where app_id=? and name not like \'!_%\' escape \'!\'"

    .line 34
    .line 35
    invoke-virtual {p0, v5, v4}, Lvp/n;->K0(Ljava/lang/String;[Ljava/lang/String;)J

    .line 36
    .line 37
    .line 38
    move-result-wide v4

    .line 39
    iget-object v6, v0, Lvp/g1;->g:Lvp/h;

    .line 40
    .line 41
    sget-object v7, Lvp/z;->V:Lvp/y;

    .line 42
    .line 43
    const/16 v8, 0x64

    .line 44
    .line 45
    invoke-virtual {v6, v2, v7}, Lvp/h;->i0(Ljava/lang/String;Lvp/y;)I

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    invoke-static {v6, v8}, Ljava/lang/Math;->min(II)I

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    const/16 v7, 0x19

    .line 54
    .line 55
    invoke-static {v6, v7}, Ljava/lang/Math;->max(II)I

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    int-to-long v6, v6

    .line 60
    cmp-long v4, v4, v6

    .line 61
    .line 62
    if-gez v4, :cond_1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    const-string v4, "_npa"

    .line 66
    .line 67
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-nez v4, :cond_2

    .line 72
    .line 73
    filled-new-array {v2, v1}, [Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    const-string v5, "select count(1) from user_attributes where app_id=? and origin=? AND name like \'!_%\' escape \'!\'"

    .line 78
    .line 79
    invoke-virtual {p0, v5, v4}, Lvp/n;->K0(Ljava/lang/String;[Ljava/lang/String;)J

    .line 80
    .line 81
    .line 82
    move-result-wide v4

    .line 83
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    const-wide/16 v6, 0x19

    .line 87
    .line 88
    cmp-long v4, v4, v6

    .line 89
    .line 90
    if-ltz v4, :cond_2

    .line 91
    .line 92
    :cond_1
    const/4 p0, 0x0

    .line 93
    return p0

    .line 94
    :cond_2
    :goto_0
    new-instance v4, Landroid/content/ContentValues;

    .line 95
    .line 96
    invoke-direct {v4}, Landroid/content/ContentValues;-><init>()V

    .line 97
    .line 98
    .line 99
    const-string v5, "app_id"

    .line 100
    .line 101
    invoke-virtual {v4, v5, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    const-string v5, "origin"

    .line 105
    .line 106
    invoke-virtual {v4, v5, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    const-string v1, "name"

    .line 110
    .line 111
    invoke-virtual {v4, v1, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    iget-wide v5, p1, Lvp/c4;->d:J

    .line 115
    .line 116
    const-string v1, "set_timestamp"

    .line 117
    .line 118
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    invoke-virtual {v4, v1, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 123
    .line 124
    .line 125
    iget-object p1, p1, Lvp/c4;->e:Ljava/lang/Object;

    .line 126
    .line 127
    invoke-static {v4, p1}, Lvp/n;->J0(Landroid/content/ContentValues;Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    const-string p1, "user_attributes"

    .line 135
    .line 136
    const/4 v1, 0x0

    .line 137
    const/4 v3, 0x5

    .line 138
    invoke-virtual {p0, p1, v1, v4, v3}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 139
    .line 140
    .line 141
    move-result-wide p0

    .line 142
    const-wide/16 v3, -0x1

    .line 143
    .line 144
    cmp-long p0, p0, v3

    .line 145
    .line 146
    if-nez p0, :cond_3

    .line 147
    .line 148
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 149
    .line 150
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 151
    .line 152
    .line 153
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 154
    .line 155
    const-string p1, "Failed to insert/update user property (got -1). appId"

    .line 156
    .line 157
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-virtual {p0, v1, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 162
    .line 163
    .line 164
    goto :goto_1

    .line 165
    :catch_0
    move-exception p0

    .line 166
    iget-object p1, v0, Lvp/g1;->i:Lvp/p0;

    .line 167
    .line 168
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 169
    .line 170
    .line 171
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 172
    .line 173
    const-string v0, "Error storing user property. appId"

    .line 174
    .line 175
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    invoke-virtual {p1, v1, p0, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 183
    return p0
.end method

.method public final U0(Ljava/lang/String;Ljava/lang/String;)Lvp/c4;
    .locals 11

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lvp/g1;

    .line 5
    .line 6
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 16
    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    const-string v4, "user_attributes"

    .line 24
    .line 25
    const-string v0, "set_timestamp"

    .line 26
    .line 27
    const-string v5, "value"

    .line 28
    .line 29
    const-string v6, "origin"

    .line 30
    .line 31
    filled-new-array {v0, v5, v6}, [Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    const-string v6, "app_id=? and name=?"

    .line 36
    .line 37
    filled-new-array {p1, p2}, [Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v7

    .line 41
    const/4 v9, 0x0

    .line 42
    const/4 v10, 0x0

    .line 43
    const/4 v8, 0x0

    .line 44
    invoke-virtual/range {v3 .. v10}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 45
    .line 46
    .line 47
    move-result-object v3
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_2
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 48
    :try_start_1
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-nez v0, :cond_0

    .line 53
    .line 54
    goto/16 :goto_4

    .line 55
    .line 56
    :cond_0
    const/4 v0, 0x0

    .line 57
    invoke-interface {v3, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 58
    .line 59
    .line 60
    move-result-wide v8

    .line 61
    const/4 v0, 0x1

    .line 62
    invoke-virtual {p0, v3, v0}, Lvp/n;->n0(Landroid/database/Cursor;I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v10

    .line 66
    if-nez v10, :cond_1

    .line 67
    .line 68
    goto :goto_4

    .line 69
    :cond_1
    const/4 p0, 0x2

    .line 70
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    new-instance v4, Lvp/c4;
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 75
    .line 76
    move-object v5, p1

    .line 77
    move-object v7, p2

    .line 78
    :try_start_2
    invoke-direct/range {v4 .. v10}, Lvp/c4;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    invoke-interface {v3}, Landroid/database/Cursor;->moveToNext()Z

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    if-eqz p0, :cond_2

    .line 86
    .line 87
    iget-object p0, v1, Lvp/g1;->i:Lvp/p0;

    .line 88
    .line 89
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 90
    .line 91
    .line 92
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 93
    .line 94
    const-string p1, "Got multiple records for user property, expected one. appId"

    .line 95
    .line 96
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :catchall_0
    move-exception v0

    .line 105
    move-object p0, v0

    .line 106
    goto :goto_2

    .line 107
    :catch_0
    move-exception v0

    .line 108
    :goto_0
    move-object p0, v0

    .line 109
    goto :goto_3

    .line 110
    :cond_2
    :goto_1
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 111
    .line 112
    .line 113
    return-object v4

    .line 114
    :catch_1
    move-exception v0

    .line 115
    move-object v5, p1

    .line 116
    move-object v7, p2

    .line 117
    goto :goto_0

    .line 118
    :goto_2
    move-object v2, v3

    .line 119
    goto :goto_5

    .line 120
    :catchall_1
    move-exception v0

    .line 121
    move-object p0, v0

    .line 122
    goto :goto_5

    .line 123
    :catch_2
    move-exception v0

    .line 124
    move-object v5, p1

    .line 125
    move-object v7, p2

    .line 126
    move-object p0, v0

    .line 127
    move-object v3, v2

    .line 128
    :goto_3
    :try_start_3
    iget-object p1, v1, Lvp/g1;->i:Lvp/p0;

    .line 129
    .line 130
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 131
    .line 132
    .line 133
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 134
    .line 135
    const-string p2, "Error querying user property. appId"

    .line 136
    .line 137
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    iget-object v1, v1, Lvp/g1;->m:Lvp/k0;

    .line 142
    .line 143
    invoke-virtual {v1, v7}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    invoke-virtual {p1, p2, v0, v1, p0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 148
    .line 149
    .line 150
    :goto_4
    if-eqz v3, :cond_3

    .line 151
    .line 152
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 153
    .line 154
    .line 155
    :cond_3
    return-object v2

    .line 156
    :goto_5
    if-eqz v2, :cond_4

    .line 157
    .line 158
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 159
    .line 160
    .line 161
    :cond_4
    throw p0
.end method

.method public final V0(Ljava/lang/String;)Ljava/util/List;
    .locals 12

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lvp/g1;

    .line 5
    .line 6
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 13
    .line 14
    .line 15
    new-instance v0, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 18
    .line 19
    .line 20
    const-string v10, "1000"

    .line 21
    .line 22
    const/4 v11, 0x0

    .line 23
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    const-string v3, "user_attributes"

    .line 28
    .line 29
    const-string v4, "name"

    .line 30
    .line 31
    const-string v5, "origin"

    .line 32
    .line 33
    const-string v6, "set_timestamp"

    .line 34
    .line 35
    const-string v7, "value"

    .line 36
    .line 37
    filled-new-array {v4, v5, v6, v7}, [Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    const-string v5, "app_id=?"

    .line 42
    .line 43
    filled-new-array {p1}, [Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    const-string v9, "rowid"

    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    const/4 v7, 0x0

    .line 53
    const/4 v8, 0x0

    .line 54
    invoke-virtual/range {v2 .. v10}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 55
    .line 56
    .line 57
    move-result-object v11

    .line 58
    invoke-interface {v11}, Landroid/database/Cursor;->moveToFirst()Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_3

    .line 63
    .line 64
    :goto_0
    const/4 v2, 0x0

    .line 65
    invoke-interface {v11, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    const/4 v2, 0x1

    .line 70
    invoke-interface {v11, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v2
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_2
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 74
    if-nez v2, :cond_0

    .line 75
    .line 76
    :try_start_1
    const-string v2, ""
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 77
    .line 78
    :cond_0
    move-object v5, v2

    .line 79
    goto :goto_1

    .line 80
    :catch_0
    move-exception v0

    .line 81
    move-object p0, v0

    .line 82
    move-object v4, p1

    .line 83
    goto :goto_4

    .line 84
    :goto_1
    const/4 v2, 0x2

    .line 85
    :try_start_2
    invoke-interface {v11, v2}, Landroid/database/Cursor;->getLong(I)J

    .line 86
    .line 87
    .line 88
    move-result-wide v7

    .line 89
    const/4 v2, 0x3

    .line 90
    invoke-virtual {p0, v11, v2}, Lvp/n;->n0(Landroid/database/Cursor;I)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v9
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 94
    if-nez v9, :cond_1

    .line 95
    .line 96
    :try_start_3
    iget-object v2, v1, Lvp/g1;->i:Lvp/p0;

    .line 97
    .line 98
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 99
    .line 100
    .line 101
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 102
    .line 103
    const-string v3, "Read invalid user property value, ignoring it. appId"

    .line 104
    .line 105
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    invoke-virtual {v2, v4, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_3
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 110
    .line 111
    .line 112
    move-object v4, p1

    .line 113
    goto :goto_2

    .line 114
    :catchall_0
    move-exception v0

    .line 115
    move-object p0, v0

    .line 116
    goto :goto_6

    .line 117
    :cond_1
    :try_start_4
    new-instance v3, Lvp/c4;
    :try_end_4
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_4 .. :try_end_4} :catch_2
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 118
    .line 119
    move-object v4, p1

    .line 120
    :try_start_5
    invoke-direct/range {v3 .. v9}, Lvp/c4;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    :goto_2
    invoke-interface {v11}, Landroid/database/Cursor;->moveToNext()Z

    .line 127
    .line 128
    .line 129
    move-result p1
    :try_end_5
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 130
    if-nez p1, :cond_2

    .line 131
    .line 132
    goto :goto_5

    .line 133
    :cond_2
    move-object p1, v4

    .line 134
    goto :goto_0

    .line 135
    :catch_1
    move-exception v0

    .line 136
    :goto_3
    move-object p0, v0

    .line 137
    goto :goto_4

    .line 138
    :catch_2
    move-exception v0

    .line 139
    move-object v4, p1

    .line 140
    goto :goto_3

    .line 141
    :goto_4
    :try_start_6
    iget-object p1, v1, Lvp/g1;->i:Lvp/p0;

    .line 142
    .line 143
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 144
    .line 145
    .line 146
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 147
    .line 148
    const-string v0, "Error querying user properties. appId"

    .line 149
    .line 150
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    invoke-virtual {p1, v1, p0, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 158
    .line 159
    :cond_3
    :goto_5
    if-eqz v11, :cond_4

    .line 160
    .line 161
    invoke-interface {v11}, Landroid/database/Cursor;->close()V

    .line 162
    .line 163
    .line 164
    :cond_4
    return-object v0

    .line 165
    :goto_6
    if-eqz v11, :cond_5

    .line 166
    .line 167
    invoke-interface {v11}, Landroid/database/Cursor;->close()V

    .line 168
    .line 169
    .line 170
    :cond_5
    throw p0
.end method

.method public final W0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lvp/g1;

    .line 8
    .line 9
    invoke-static/range {p1 .. p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 16
    .line 17
    .line 18
    new-instance v3, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    const-string v12, "1001"

    .line 24
    .line 25
    const-string v4, "*"

    .line 26
    .line 27
    :try_start_0
    new-instance v5, Ljava/util/ArrayList;

    .line 28
    .line 29
    const/4 v14, 0x3

    .line 30
    invoke-direct {v5, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 31
    .line 32
    .line 33
    move-object/from16 v15, p1

    .line 34
    .line 35
    invoke-virtual {v5, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    new-instance v6, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v7, "app_id=?"

    .line 41
    .line 42
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-static/range {p2 .. p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    if-nez v7, :cond_0

    .line 50
    .line 51
    move-object/from16 v7, p2

    .line 52
    .line 53
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    const-string v8, " and origin=?"

    .line 57
    .line 58
    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :catchall_0
    move-exception v0

    .line 63
    goto/16 :goto_6

    .line 64
    .line 65
    :catch_0
    move-exception v0

    .line 66
    goto/16 :goto_7

    .line 67
    .line 68
    :cond_0
    move-object/from16 v7, p2

    .line 69
    .line 70
    :goto_0
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 71
    .line 72
    .line 73
    move-result v8

    .line 74
    const/4 v9, 0x1

    .line 75
    if-nez v8, :cond_1

    .line 76
    .line 77
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v8

    .line 81
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 82
    .line 83
    .line 84
    move-result v8

    .line 85
    add-int/2addr v8, v9

    .line 86
    new-instance v10, Ljava/lang/StringBuilder;

    .line 87
    .line 88
    invoke-direct {v10, v8}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v10, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    const-string v4, " and name glob ?"

    .line 105
    .line 106
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    :cond_1
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    new-array v4, v4, [Ljava/lang/String;

    .line 114
    .line 115
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    move-object v8, v4

    .line 120
    check-cast v8, [Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    const-string v5, "user_attributes"

    .line 127
    .line 128
    const-string v10, "name"

    .line 129
    .line 130
    const-string v11, "set_timestamp"

    .line 131
    .line 132
    const-string v9, "value"

    .line 133
    .line 134
    const-string v13, "origin"

    .line 135
    .line 136
    filled-new-array {v10, v11, v9, v13}, [Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v9

    .line 140
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v6

    .line 144
    const-string v11, "rowid"

    .line 145
    .line 146
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    iget-object v13, v2, Lvp/g1;->i:Lvp/p0;

    .line 150
    .line 151
    move-object v7, v6

    .line 152
    move-object v6, v9

    .line 153
    const/4 v9, 0x0

    .line 154
    const/4 v10, 0x0

    .line 155
    const/4 v14, 0x1

    .line 156
    invoke-virtual/range {v4 .. v12}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 157
    .line 158
    .line 159
    move-result-object v4
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 160
    :try_start_1
    invoke-interface {v4}, Landroid/database/Cursor;->moveToFirst()Z

    .line 161
    .line 162
    .line 163
    move-result v5
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_4
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 164
    if-nez v5, :cond_2

    .line 165
    .line 166
    goto/16 :goto_9

    .line 167
    .line 168
    :cond_2
    move-object/from16 v5, p2

    .line 169
    .line 170
    :goto_1
    :try_start_2
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 171
    .line 172
    .line 173
    move-result v6

    .line 174
    const/16 v7, 0x3e8

    .line 175
    .line 176
    if-lt v6, v7, :cond_3

    .line 177
    .line 178
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 179
    .line 180
    .line 181
    iget-object v0, v13, Lvp/p0;->j:Lvp/n0;

    .line 182
    .line 183
    const-string v1, "Read more than the max allowed user properties, ignoring excess"

    .line 184
    .line 185
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 186
    .line 187
    .line 188
    move-result-object v6

    .line 189
    invoke-virtual {v0, v6, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    goto/16 :goto_9

    .line 193
    .line 194
    :catchall_1
    move-exception v0

    .line 195
    goto :goto_5

    .line 196
    :catch_1
    move-exception v0

    .line 197
    goto :goto_4

    .line 198
    :cond_3
    const/4 v6, 0x0

    .line 199
    invoke-interface {v4, v6}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v18

    .line 203
    invoke-interface {v4, v14}, Landroid/database/Cursor;->getLong(I)J

    .line 204
    .line 205
    .line 206
    move-result-wide v19

    .line 207
    const/4 v6, 0x2

    .line 208
    invoke-virtual {v0, v4, v6}, Lvp/n;->n0(Landroid/database/Cursor;I)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v21

    .line 212
    const/4 v6, 0x3

    .line 213
    invoke-interface {v4, v6}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v5
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 217
    if-nez v21, :cond_4

    .line 218
    .line 219
    :try_start_3
    invoke-static {v13}, Lvp/g1;->k(Lvp/n1;)V

    .line 220
    .line 221
    .line 222
    iget-object v7, v13, Lvp/p0;->j:Lvp/n0;

    .line 223
    .line 224
    const-string v8, "(2)Read invalid user property value, ignoring it"

    .line 225
    .line 226
    invoke-static {v15}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 227
    .line 228
    .line 229
    move-result-object v9

    .line 230
    invoke-virtual {v7, v8, v9, v5, v1}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    move-object/from16 v17, v5

    .line 234
    .line 235
    goto :goto_2

    .line 236
    :catch_2
    move-exception v0

    .line 237
    move-object/from16 v17, v5

    .line 238
    .line 239
    goto :goto_3

    .line 240
    :cond_4
    new-instance v15, Lvp/c4;
    :try_end_3
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 241
    .line 242
    move-object/from16 v16, p1

    .line 243
    .line 244
    move-object/from16 v17, v5

    .line 245
    .line 246
    :try_start_4
    invoke-direct/range {v15 .. v21}, Lvp/c4;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v3, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 250
    .line 251
    .line 252
    :goto_2
    invoke-interface {v4}, Landroid/database/Cursor;->moveToNext()Z

    .line 253
    .line 254
    .line 255
    move-result v5
    :try_end_4
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_4 .. :try_end_4} :catch_3
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 256
    if-nez v5, :cond_5

    .line 257
    .line 258
    goto :goto_9

    .line 259
    :cond_5
    move-object/from16 v15, p1

    .line 260
    .line 261
    move-object/from16 v5, v17

    .line 262
    .line 263
    goto :goto_1

    .line 264
    :catch_3
    move-exception v0

    .line 265
    :goto_3
    move-object v13, v4

    .line 266
    move-object/from16 v5, v17

    .line 267
    .line 268
    goto :goto_8

    .line 269
    :goto_4
    move-object v13, v4

    .line 270
    goto :goto_8

    .line 271
    :goto_5
    move-object v13, v4

    .line 272
    goto :goto_a

    .line 273
    :catch_4
    move-exception v0

    .line 274
    move-object/from16 v5, p2

    .line 275
    .line 276
    goto :goto_4

    .line 277
    :goto_6
    const/4 v13, 0x0

    .line 278
    goto :goto_a

    .line 279
    :goto_7
    move-object/from16 v5, p2

    .line 280
    .line 281
    const/4 v13, 0x0

    .line 282
    :goto_8
    :try_start_5
    iget-object v1, v2, Lvp/g1;->i:Lvp/p0;

    .line 283
    .line 284
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 285
    .line 286
    .line 287
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 288
    .line 289
    const-string v2, "(2)Error querying user properties"

    .line 290
    .line 291
    invoke-static/range {p1 .. p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 292
    .line 293
    .line 294
    move-result-object v3

    .line 295
    invoke-virtual {v1, v2, v3, v5, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 299
    .line 300
    move-object v4, v13

    .line 301
    :goto_9
    if-eqz v4, :cond_6

    .line 302
    .line 303
    invoke-interface {v4}, Landroid/database/Cursor;->close()V

    .line 304
    .line 305
    .line 306
    :cond_6
    return-object v3

    .line 307
    :catchall_2
    move-exception v0

    .line 308
    :goto_a
    if-eqz v13, :cond_7

    .line 309
    .line 310
    invoke-interface {v13}, Landroid/database/Cursor;->close()V

    .line 311
    .line 312
    .line 313
    :cond_7
    throw v0
.end method

.method public final X0(Lvp/f;)Z
    .locals 7

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 9
    .line 10
    .line 11
    iget-object v1, p1, Lvp/f;->d:Ljava/lang/String;

    .line 12
    .line 13
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-object v2, p1, Lvp/f;->f:Lvp/b4;

    .line 17
    .line 18
    iget-object v2, v2, Lvp/b4;->e:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {p0, v1, v2}, Lvp/n;->U0(Ljava/lang/String;Ljava/lang/String;)Lvp/c4;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    filled-new-array {v1}, [Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    const-string v3, "SELECT COUNT(1) FROM conditional_properties WHERE app_id=?"

    .line 31
    .line 32
    invoke-virtual {p0, v3, v2}, Lvp/n;->K0(Ljava/lang/String;[Ljava/lang/String;)J

    .line 33
    .line 34
    .line 35
    move-result-wide v2

    .line 36
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const-wide/16 v4, 0x3e8

    .line 40
    .line 41
    cmp-long v2, v2, v4

    .line 42
    .line 43
    if-gez v2, :cond_0

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const/4 p0, 0x0

    .line 47
    return p0

    .line 48
    :cond_1
    :goto_0
    new-instance v2, Landroid/content/ContentValues;

    .line 49
    .line 50
    invoke-direct {v2}, Landroid/content/ContentValues;-><init>()V

    .line 51
    .line 52
    .line 53
    const-string v3, "app_id"

    .line 54
    .line 55
    invoke-virtual {v2, v3, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    iget-object v3, p1, Lvp/f;->e:Ljava/lang/String;

    .line 59
    .line 60
    const-string v4, "origin"

    .line 61
    .line 62
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object v3, p1, Lvp/f;->f:Lvp/b4;

    .line 66
    .line 67
    iget-object v3, v3, Lvp/b4;->e:Ljava/lang/String;

    .line 68
    .line 69
    const-string v4, "name"

    .line 70
    .line 71
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    iget-object v3, p1, Lvp/f;->f:Lvp/b4;

    .line 75
    .line 76
    invoke-virtual {v3}, Lvp/b4;->h()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    invoke-static {v2, v3}, Lvp/n;->J0(Landroid/content/ContentValues;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    iget-boolean v3, p1, Lvp/f;->h:Z

    .line 87
    .line 88
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    const-string v4, "active"

    .line 93
    .line 94
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 95
    .line 96
    .line 97
    iget-object v3, p1, Lvp/f;->i:Ljava/lang/String;

    .line 98
    .line 99
    const-string v4, "trigger_event_name"

    .line 100
    .line 101
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    iget-wide v3, p1, Lvp/f;->k:J

    .line 105
    .line 106
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    const-string v4, "trigger_timeout"

    .line 111
    .line 112
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 113
    .line 114
    .line 115
    iget-object v3, p1, Lvp/f;->j:Lvp/t;

    .line 116
    .line 117
    iget-object v4, v0, Lvp/g1;->l:Lvp/d4;

    .line 118
    .line 119
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 120
    .line 121
    invoke-static {v4}, Lvp/g1;->g(Lap0/o;)V

    .line 122
    .line 123
    .line 124
    invoke-static {v3}, Lvp/d4;->E0(Landroid/os/Parcelable;)[B

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    const-string v5, "timed_out_event"

    .line 129
    .line 130
    invoke-virtual {v2, v5, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 131
    .line 132
    .line 133
    iget-wide v5, p1, Lvp/f;->g:J

    .line 134
    .line 135
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 136
    .line 137
    .line 138
    move-result-object v3

    .line 139
    const-string v5, "creation_timestamp"

    .line 140
    .line 141
    invoke-virtual {v2, v5, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 142
    .line 143
    .line 144
    invoke-static {v4}, Lvp/g1;->g(Lap0/o;)V

    .line 145
    .line 146
    .line 147
    iget-object v3, p1, Lvp/f;->l:Lvp/t;

    .line 148
    .line 149
    invoke-static {v3}, Lvp/d4;->E0(Landroid/os/Parcelable;)[B

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    const-string v4, "triggered_event"

    .line 154
    .line 155
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 156
    .line 157
    .line 158
    iget-object v3, p1, Lvp/f;->f:Lvp/b4;

    .line 159
    .line 160
    iget-wide v3, v3, Lvp/b4;->f:J

    .line 161
    .line 162
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 163
    .line 164
    .line 165
    move-result-object v3

    .line 166
    const-string v4, "triggered_timestamp"

    .line 167
    .line 168
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 169
    .line 170
    .line 171
    iget-wide v3, p1, Lvp/f;->m:J

    .line 172
    .line 173
    const-string v5, "time_to_live"

    .line 174
    .line 175
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    invoke-virtual {v2, v5, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 180
    .line 181
    .line 182
    iget-object p1, p1, Lvp/f;->n:Lvp/t;

    .line 183
    .line 184
    invoke-static {p1}, Lvp/d4;->E0(Landroid/os/Parcelable;)[B

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    const-string v3, "expired_event"

    .line 189
    .line 190
    invoke-virtual {v2, v3, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 191
    .line 192
    .line 193
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    const-string p1, "conditional_properties"

    .line 198
    .line 199
    const/4 v3, 0x0

    .line 200
    const/4 v4, 0x5

    .line 201
    invoke-virtual {p0, p1, v3, v2, v4}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 202
    .line 203
    .line 204
    move-result-wide p0

    .line 205
    const-wide/16 v2, -0x1

    .line 206
    .line 207
    cmp-long p0, p0, v2

    .line 208
    .line 209
    if-nez p0, :cond_2

    .line 210
    .line 211
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 212
    .line 213
    .line 214
    iget-object p0, v0, Lvp/p0;->j:Lvp/n0;

    .line 215
    .line 216
    const-string p1, "Failed to insert/update conditional user property (got -1)"

    .line 217
    .line 218
    invoke-static {v1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 219
    .line 220
    .line 221
    move-result-object v2

    .line 222
    invoke-virtual {p0, v2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 223
    .line 224
    .line 225
    goto :goto_1

    .line 226
    :catch_0
    move-exception p0

    .line 227
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 228
    .line 229
    .line 230
    iget-object p1, v0, Lvp/p0;->j:Lvp/n0;

    .line 231
    .line 232
    invoke-static {v1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    const-string v1, "Error storing conditional user property"

    .line 237
    .line 238
    invoke-virtual {p1, v0, p0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    :cond_2
    :goto_1
    const/4 p0, 0x1

    .line 242
    return p0
.end method

.method public final Y0(Ljava/lang/String;Ljava/lang/String;)Lvp/f;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    move-object v6, v1

    .line 6
    check-cast v6, Lvp/g1;

    .line 7
    .line 8
    invoke-static/range {p1 .. p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static/range {p2 .. p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 18
    .line 19
    .line 20
    const/4 v7, 0x0

    .line 21
    :try_start_0
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 22
    .line 23
    .line 24
    move-result-object v8

    .line 25
    const-string v9, "conditional_properties"

    .line 26
    .line 27
    const-string v10, "origin"

    .line 28
    .line 29
    const-string v11, "value"

    .line 30
    .line 31
    const-string v12, "active"

    .line 32
    .line 33
    const-string v13, "trigger_event_name"

    .line 34
    .line 35
    const-string v14, "trigger_timeout"

    .line 36
    .line 37
    const-string v15, "timed_out_event"

    .line 38
    .line 39
    const-string v16, "creation_timestamp"

    .line 40
    .line 41
    const-string v17, "triggered_event"

    .line 42
    .line 43
    const-string v18, "triggered_timestamp"

    .line 44
    .line 45
    const-string v19, "time_to_live"

    .line 46
    .line 47
    const-string v20, "expired_event"

    .line 48
    .line 49
    filled-new-array/range {v10 .. v20}, [Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v10

    .line 53
    const-string v11, "app_id=? and name=?"

    .line 54
    .line 55
    filled-new-array/range {p1 .. p2}, [Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v12

    .line 59
    const/4 v14, 0x0

    .line 60
    const/4 v15, 0x0

    .line 61
    const/4 v13, 0x0

    .line 62
    invoke-virtual/range {v8 .. v15}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 63
    .line 64
    .line 65
    move-result-object v8
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_2
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 66
    :try_start_1
    invoke-interface {v8}, Landroid/database/Cursor;->moveToFirst()Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-nez v1, :cond_0

    .line 71
    .line 72
    goto/16 :goto_5

    .line 73
    .line 74
    :cond_0
    const/4 v1, 0x0

    .line 75
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    if-nez v2, :cond_1

    .line 80
    .line 81
    const-string v2, ""

    .line 82
    .line 83
    :cond_1
    move-object v5, v2

    .line 84
    goto :goto_0

    .line 85
    :catchall_0
    move-exception v0

    .line 86
    goto/16 :goto_3

    .line 87
    .line 88
    :goto_0
    const/4 v2, 0x1

    .line 89
    invoke-virtual {v0, v8, v2}, Lvp/n;->n0(Landroid/database/Cursor;I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    const/4 v4, 0x2

    .line 94
    invoke-interface {v8, v4}, Landroid/database/Cursor;->getInt(I)I

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    if-eqz v4, :cond_2

    .line 99
    .line 100
    move v15, v2

    .line 101
    goto :goto_1

    .line 102
    :cond_2
    move v15, v1

    .line 103
    :goto_1
    const/4 v1, 0x3

    .line 104
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v16

    .line 108
    const/4 v1, 0x4

    .line 109
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getLong(I)J

    .line 110
    .line 111
    .line 112
    move-result-wide v18

    .line 113
    iget-object v0, v0, Lvp/q3;->f:Lvp/z3;

    .line 114
    .line 115
    iget-object v0, v0, Lvp/z3;->j:Lvp/s0;

    .line 116
    .line 117
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 118
    .line 119
    .line 120
    const/4 v1, 0x5

    .line 121
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getBlob(I)[B

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    sget-object v2, Lvp/t;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 126
    .line 127
    invoke-virtual {v0, v1, v2}, Lvp/s0;->F0([BLandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    move-object/from16 v17, v1

    .line 132
    .line 133
    check-cast v17, Lvp/t;

    .line 134
    .line 135
    const/4 v1, 0x6

    .line 136
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getLong(I)J

    .line 137
    .line 138
    .line 139
    move-result-wide v13

    .line 140
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 141
    .line 142
    .line 143
    const/4 v1, 0x7

    .line 144
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getBlob(I)[B

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    invoke-virtual {v0, v1, v2}, Lvp/s0;->F0([BLandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    move-object/from16 v20, v1

    .line 153
    .line 154
    check-cast v20, Lvp/t;

    .line 155
    .line 156
    const/16 v1, 0x8

    .line 157
    .line 158
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getLong(I)J

    .line 159
    .line 160
    .line 161
    move-result-wide v9

    .line 162
    const/16 v1, 0x9

    .line 163
    .line 164
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getLong(I)J

    .line 165
    .line 166
    .line 167
    move-result-wide v21

    .line 168
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 169
    .line 170
    .line 171
    const/16 v1, 0xa

    .line 172
    .line 173
    invoke-interface {v8, v1}, Landroid/database/Cursor;->getBlob(I)[B

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    invoke-virtual {v0, v1, v2}, Lvp/s0;->F0([BLandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 178
    .line 179
    .line 180
    move-result-object v0

    .line 181
    move-object/from16 v23, v0

    .line 182
    .line 183
    check-cast v23, Lvp/t;

    .line 184
    .line 185
    new-instance v0, Lvp/b4;
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 186
    .line 187
    move-object/from16 v4, p2

    .line 188
    .line 189
    move-wide v1, v9

    .line 190
    :try_start_2
    invoke-direct/range {v0 .. v5}, Lvp/b4;-><init>(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    new-instance v9, Lvp/f;

    .line 194
    .line 195
    move-object/from16 v10, p1

    .line 196
    .line 197
    move-object v12, v0

    .line 198
    move-object v11, v5

    .line 199
    invoke-direct/range {v9 .. v23}, Lvp/f;-><init>(Ljava/lang/String;Ljava/lang/String;Lvp/b4;JZLjava/lang/String;Lvp/t;JLvp/t;JLvp/t;)V

    .line 200
    .line 201
    .line 202
    invoke-interface {v8}, Landroid/database/Cursor;->moveToNext()Z

    .line 203
    .line 204
    .line 205
    move-result v0

    .line 206
    if-eqz v0, :cond_3

    .line 207
    .line 208
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 209
    .line 210
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 211
    .line 212
    .line 213
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 214
    .line 215
    const-string v1, "Got multiple records for conditional property, expected one"

    .line 216
    .line 217
    invoke-static/range {p1 .. p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 218
    .line 219
    .line 220
    move-result-object v2

    .line 221
    iget-object v3, v6, Lvp/g1;->m:Lvp/k0;

    .line 222
    .line 223
    invoke-virtual {v3, v4}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v3

    .line 227
    invoke-virtual {v0, v2, v3, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 228
    .line 229
    .line 230
    goto :goto_2

    .line 231
    :catch_0
    move-exception v0

    .line 232
    goto :goto_4

    .line 233
    :cond_3
    :goto_2
    invoke-interface {v8}, Landroid/database/Cursor;->close()V

    .line 234
    .line 235
    .line 236
    return-object v9

    .line 237
    :catch_1
    move-exception v0

    .line 238
    move-object/from16 v4, p2

    .line 239
    .line 240
    goto :goto_4

    .line 241
    :goto_3
    move-object v7, v8

    .line 242
    goto :goto_6

    .line 243
    :catchall_1
    move-exception v0

    .line 244
    goto :goto_6

    .line 245
    :catch_2
    move-exception v0

    .line 246
    move-object/from16 v4, p2

    .line 247
    .line 248
    move-object v8, v7

    .line 249
    :goto_4
    :try_start_3
    iget-object v1, v6, Lvp/g1;->i:Lvp/p0;

    .line 250
    .line 251
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 252
    .line 253
    .line 254
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 255
    .line 256
    const-string v2, "Error querying conditional property"

    .line 257
    .line 258
    invoke-static/range {p1 .. p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 259
    .line 260
    .line 261
    move-result-object v3

    .line 262
    iget-object v5, v6, Lvp/g1;->m:Lvp/k0;

    .line 263
    .line 264
    invoke-virtual {v5, v4}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object v4

    .line 268
    invoke-virtual {v1, v2, v3, v4, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 269
    .line 270
    .line 271
    :goto_5
    if-eqz v8, :cond_4

    .line 272
    .line 273
    invoke-interface {v8}, Landroid/database/Cursor;->close()V

    .line 274
    .line 275
    .line 276
    :cond_4
    return-object v7

    .line 277
    :goto_6
    if-eqz v7, :cond_5

    .line 278
    .line 279
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 280
    .line 281
    .line 282
    :cond_5
    throw v0
.end method

.method public final Z0(Ljava/lang/String;Ljava/lang/String;)V
    .locals 4

    .line 1
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 11
    .line 12
    .line 13
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, "conditional_properties"

    .line 18
    .line 19
    const-string v2, "app_id=? and name=?"

    .line 20
    .line 21
    filled-new-array {p1, p2}, [Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-virtual {v0, v1, v2, v3}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :catch_0
    move-exception v0

    .line 30
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lvp/g1;

    .line 33
    .line 34
    iget-object v1, p0, Lvp/g1;->i:Lvp/p0;

    .line 35
    .line 36
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 40
    .line 41
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iget-object p0, p0, Lvp/g1;->m:Lvp/k0;

    .line 46
    .line 47
    invoke-virtual {p0, p2}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string p2, "Error deleting conditional property"

    .line 52
    .line 53
    invoke-virtual {v1, p2, p1, p0, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public final a1(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;
    .locals 2

    .line 1
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 8
    .line 9
    .line 10
    new-instance v0, Ljava/util/ArrayList;

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    new-instance p1, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v1, "app_id=?"

    .line 22
    .line 23
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_0

    .line 31
    .line 32
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    const-string p2, " and origin=?"

    .line 36
    .line 37
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    :cond_0
    invoke-static {p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-nez p2, :cond_1

    .line 45
    .line 46
    invoke-static {p3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    const-string p3, "*"

    .line 51
    .line 52
    invoke-virtual {p2, p3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    const-string p2, " and name glob ?"

    .line 60
    .line 61
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 65
    .line 66
    .line 67
    move-result p2

    .line 68
    new-array p2, p2, [Ljava/lang/String;

    .line 69
    .line 70
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    check-cast p2, [Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    invoke-virtual {p0, p1, p2}, Lvp/n;->b1(Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0
.end method

.method public final b1(Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lvp/g1;

    .line 6
    .line 7
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 11
    .line 12
    .line 13
    new-instance v2, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    const-string v11, "1001"

    .line 19
    .line 20
    const/4 v12, 0x0

    .line 21
    :try_start_0
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    const-string v4, "conditional_properties"

    .line 26
    .line 27
    const-string v13, "app_id"

    .line 28
    .line 29
    const-string v14, "origin"

    .line 30
    .line 31
    const-string v15, "name"

    .line 32
    .line 33
    const-string v16, "value"

    .line 34
    .line 35
    const-string v17, "active"

    .line 36
    .line 37
    const-string v18, "trigger_event_name"

    .line 38
    .line 39
    const-string v19, "trigger_timeout"

    .line 40
    .line 41
    const-string v20, "timed_out_event"

    .line 42
    .line 43
    const-string v21, "creation_timestamp"

    .line 44
    .line 45
    const-string v22, "triggered_event"

    .line 46
    .line 47
    const-string v23, "triggered_timestamp"

    .line 48
    .line 49
    const-string v24, "time_to_live"

    .line 50
    .line 51
    const-string v25, "expired_event"

    .line 52
    .line 53
    filled-new-array/range {v13 .. v25}, [Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    const-string v10, "rowid"

    .line 58
    .line 59
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    const/4 v8, 0x0

    .line 63
    const/4 v9, 0x0

    .line 64
    move-object/from16 v6, p1

    .line 65
    .line 66
    move-object/from16 v7, p2

    .line 67
    .line 68
    invoke-virtual/range {v3 .. v11}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 69
    .line 70
    .line 71
    move-result-object v12

    .line 72
    invoke-interface {v12}, Landroid/database/Cursor;->moveToFirst()Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    if-eqz v3, :cond_3

    .line 77
    .line 78
    :cond_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    const/16 v4, 0x3e8

    .line 83
    .line 84
    if-lt v3, v4, :cond_1

    .line 85
    .line 86
    iget-object v0, v1, Lvp/g1;->i:Lvp/p0;

    .line 87
    .line 88
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 89
    .line 90
    .line 91
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 92
    .line 93
    const-string v3, "Read more than the max allowed conditional properties, ignoring extra"

    .line 94
    .line 95
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    invoke-virtual {v0, v4, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    goto/16 :goto_2

    .line 103
    .line 104
    :catchall_0
    move-exception v0

    .line 105
    goto/16 :goto_3

    .line 106
    .line 107
    :catch_0
    move-exception v0

    .line 108
    goto/16 :goto_1

    .line 109
    .line 110
    :cond_1
    const/4 v3, 0x0

    .line 111
    invoke-interface {v12, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v14

    .line 115
    const/4 v4, 0x1

    .line 116
    invoke-interface {v12, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v15

    .line 120
    const/4 v5, 0x2

    .line 121
    invoke-interface {v12, v5}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v9

    .line 125
    const/4 v5, 0x3

    .line 126
    invoke-virtual {v0, v12, v5}, Lvp/n;->n0(Landroid/database/Cursor;I)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v8

    .line 130
    const/4 v5, 0x4

    .line 131
    invoke-interface {v12, v5}, Landroid/database/Cursor;->getInt(I)I

    .line 132
    .line 133
    .line 134
    move-result v5

    .line 135
    if-eqz v5, :cond_2

    .line 136
    .line 137
    move/from16 v19, v4

    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_2
    move/from16 v19, v3

    .line 141
    .line 142
    :goto_0
    const/4 v3, 0x5

    .line 143
    invoke-interface {v12, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v20

    .line 147
    const/4 v3, 0x6

    .line 148
    invoke-interface {v12, v3}, Landroid/database/Cursor;->getLong(I)J

    .line 149
    .line 150
    .line 151
    move-result-wide v22

    .line 152
    iget-object v3, v0, Lvp/q3;->f:Lvp/z3;

    .line 153
    .line 154
    iget-object v3, v3, Lvp/z3;->j:Lvp/s0;

    .line 155
    .line 156
    invoke-static {v3}, Lvp/z3;->T(Lvp/u3;)V

    .line 157
    .line 158
    .line 159
    const/4 v4, 0x7

    .line 160
    invoke-interface {v12, v4}, Landroid/database/Cursor;->getBlob(I)[B

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    sget-object v5, Lvp/t;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 165
    .line 166
    invoke-virtual {v3, v4, v5}, Lvp/s0;->F0([BLandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    move-object/from16 v21, v4

    .line 171
    .line 172
    check-cast v21, Lvp/t;

    .line 173
    .line 174
    const/16 v4, 0x8

    .line 175
    .line 176
    invoke-interface {v12, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 177
    .line 178
    .line 179
    move-result-wide v17

    .line 180
    invoke-static {v3}, Lvp/z3;->T(Lvp/u3;)V

    .line 181
    .line 182
    .line 183
    const/16 v4, 0x9

    .line 184
    .line 185
    invoke-interface {v12, v4}, Landroid/database/Cursor;->getBlob(I)[B

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    invoke-virtual {v3, v4, v5}, Lvp/s0;->F0([BLandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    move-object/from16 v24, v4

    .line 194
    .line 195
    check-cast v24, Lvp/t;

    .line 196
    .line 197
    const/16 v4, 0xa

    .line 198
    .line 199
    invoke-interface {v12, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 200
    .line 201
    .line 202
    move-result-wide v6

    .line 203
    const/16 v4, 0xb

    .line 204
    .line 205
    invoke-interface {v12, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 206
    .line 207
    .line 208
    move-result-wide v25

    .line 209
    invoke-static {v3}, Lvp/z3;->T(Lvp/u3;)V

    .line 210
    .line 211
    .line 212
    const/16 v4, 0xc

    .line 213
    .line 214
    invoke-interface {v12, v4}, Landroid/database/Cursor;->getBlob(I)[B

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    invoke-virtual {v3, v4, v5}, Lvp/s0;->F0([BLandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 219
    .line 220
    .line 221
    move-result-object v3

    .line 222
    move-object/from16 v27, v3

    .line 223
    .line 224
    check-cast v27, Lvp/t;

    .line 225
    .line 226
    new-instance v16, Lvp/b4;

    .line 227
    .line 228
    move-object v10, v15

    .line 229
    move-object/from16 v5, v16

    .line 230
    .line 231
    invoke-direct/range {v5 .. v10}, Lvp/b4;-><init>(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    move-object/from16 v16, v5

    .line 235
    .line 236
    move-object v15, v10

    .line 237
    new-instance v13, Lvp/f;

    .line 238
    .line 239
    invoke-direct/range {v13 .. v27}, Lvp/f;-><init>(Ljava/lang/String;Ljava/lang/String;Lvp/b4;JZLjava/lang/String;Lvp/t;JLvp/t;JLvp/t;)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v2, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    invoke-interface {v12}, Landroid/database/Cursor;->moveToNext()Z

    .line 246
    .line 247
    .line 248
    move-result v3
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 249
    if-nez v3, :cond_0

    .line 250
    .line 251
    goto :goto_2

    .line 252
    :goto_1
    :try_start_1
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 253
    .line 254
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 255
    .line 256
    .line 257
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 258
    .line 259
    const-string v2, "Error querying conditional user property value"

    .line 260
    .line 261
    invoke-virtual {v1, v0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 265
    .line 266
    :cond_3
    :goto_2
    if-eqz v12, :cond_4

    .line 267
    .line 268
    invoke-interface {v12}, Landroid/database/Cursor;->close()V

    .line 269
    .line 270
    .line 271
    :cond_4
    return-object v2

    .line 272
    :goto_3
    if-eqz v12, :cond_5

    .line 273
    .line 274
    invoke-interface {v12}, Landroid/database/Cursor;->close()V

    .line 275
    .line 276
    .line 277
    :cond_5
    throw v0
.end method

.method public final c1(Ljava/lang/String;)Lvp/t0;
    .locals 51

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lvp/g1;

    .line 8
    .line 9
    invoke-static {v1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 16
    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    :try_start_0
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    const-string v5, "apps"

    .line 24
    .line 25
    const-string v6, "app_instance_id"

    .line 26
    .line 27
    const-string v7, "gmp_app_id"

    .line 28
    .line 29
    const-string v8, "resettable_device_id_hash"

    .line 30
    .line 31
    const-string v9, "last_bundle_index"

    .line 32
    .line 33
    const-string v10, "last_bundle_start_timestamp"

    .line 34
    .line 35
    const-string v11, "last_bundle_end_timestamp"

    .line 36
    .line 37
    const-string v12, "app_version"

    .line 38
    .line 39
    const-string v13, "app_store"

    .line 40
    .line 41
    const-string v14, "gmp_version"

    .line 42
    .line 43
    const-string v15, "dev_cert_hash"

    .line 44
    .line 45
    const-string v16, "measurement_enabled"

    .line 46
    .line 47
    const-string v17, "day"

    .line 48
    .line 49
    const-string v18, "daily_public_events_count"

    .line 50
    .line 51
    const-string v19, "daily_events_count"

    .line 52
    .line 53
    const-string v20, "daily_conversions_count"

    .line 54
    .line 55
    const-string v21, "config_fetched_time"

    .line 56
    .line 57
    const-string v22, "failed_config_fetch_time"

    .line 58
    .line 59
    const-string v23, "app_version_int"

    .line 60
    .line 61
    const-string v24, "firebase_instance_id"

    .line 62
    .line 63
    const-string v25, "daily_error_events_count"

    .line 64
    .line 65
    const-string v26, "daily_realtime_events_count"

    .line 66
    .line 67
    const-string v27, "health_monitor_sample"

    .line 68
    .line 69
    const-string v28, "android_id"

    .line 70
    .line 71
    const-string v29, "adid_reporting_enabled"

    .line 72
    .line 73
    const-string v30, "admob_app_id"

    .line 74
    .line 75
    const-string v31, "dynamite_version"

    .line 76
    .line 77
    const-string v32, "safelisted_events"

    .line 78
    .line 79
    const-string v33, "ga_app_id"

    .line 80
    .line 81
    const-string v34, "session_stitching_token"

    .line 82
    .line 83
    const-string v35, "sgtm_upload_enabled"

    .line 84
    .line 85
    const-string v36, "target_os_version"

    .line 86
    .line 87
    const-string v37, "session_stitching_token_hash"

    .line 88
    .line 89
    const-string v38, "ad_services_version"

    .line 90
    .line 91
    const-string v39, "unmatched_first_open_without_ad_id"

    .line 92
    .line 93
    const-string v40, "npa_metadata_value"

    .line 94
    .line 95
    const-string v41, "attribution_eligibility_status"

    .line 96
    .line 97
    const-string v42, "sgtm_preview_key"

    .line 98
    .line 99
    const-string v43, "dma_consent_state"

    .line 100
    .line 101
    const-string v44, "daily_realtime_dcu_count"

    .line 102
    .line 103
    const-string v45, "bundle_delivery_index"

    .line 104
    .line 105
    const-string v46, "serialized_npa_metadata"

    .line 106
    .line 107
    const-string v47, "unmatched_pfo"

    .line 108
    .line 109
    const-string v48, "unmatched_uwa"

    .line 110
    .line 111
    const-string v49, "ad_campaign_info"

    .line 112
    .line 113
    const-string v50, "client_upload_eligibility"

    .line 114
    .line 115
    filled-new-array/range {v6 .. v50}, [Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    const-string v7, "app_id=?"

    .line 120
    .line 121
    filled-new-array {v1}, [Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v8

    .line 125
    const/4 v10, 0x0

    .line 126
    const/4 v11, 0x0

    .line 127
    const/4 v9, 0x0

    .line 128
    invoke-virtual/range {v4 .. v11}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 129
    .line 130
    .line 131
    move-result-object v4
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 132
    :try_start_1
    invoke-interface {v4}, Landroid/database/Cursor;->moveToFirst()Z

    .line 133
    .line 134
    .line 135
    move-result v5

    .line 136
    if-nez v5, :cond_0

    .line 137
    .line 138
    goto/16 :goto_15

    .line 139
    .line 140
    :cond_0
    new-instance v5, Lvp/t0;

    .line 141
    .line 142
    iget-object v0, v0, Lvp/q3;->f:Lvp/z3;

    .line 143
    .line 144
    iget-object v6, v0, Lvp/z3;->o:Lvp/g1;

    .line 145
    .line 146
    invoke-direct {v5, v6, v1}, Lvp/t0;-><init>(Lvp/g1;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    iget-object v6, v5, Lvp/t0;->a:Lvp/g1;

    .line 150
    .line 151
    invoke-virtual {v0, v1}, Lvp/z3;->a(Ljava/lang/String;)Lvp/s1;

    .line 152
    .line 153
    .line 154
    move-result-object v7

    .line 155
    sget-object v8, Lvp/r1;->f:Lvp/r1;

    .line 156
    .line 157
    invoke-virtual {v7, v8}, Lvp/s1;->i(Lvp/r1;)Z

    .line 158
    .line 159
    .line 160
    move-result v7

    .line 161
    const/4 v9, 0x0

    .line 162
    if-eqz v7, :cond_1

    .line 163
    .line 164
    invoke-interface {v4, v9}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v7

    .line 168
    invoke-virtual {v5, v7}, Lvp/t0;->F(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    goto :goto_0

    .line 172
    :catchall_0
    move-exception v0

    .line 173
    goto/16 :goto_13

    .line 174
    .line 175
    :cond_1
    :goto_0
    const/4 v7, 0x1

    .line 176
    invoke-interface {v4, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v10

    .line 180
    invoke-virtual {v5, v10}, Lvp/t0;->H(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v0, v1}, Lvp/z3;->a(Ljava/lang/String;)Lvp/s1;

    .line 184
    .line 185
    .line 186
    move-result-object v10

    .line 187
    sget-object v11, Lvp/r1;->e:Lvp/r1;

    .line 188
    .line 189
    invoke-virtual {v10, v11}, Lvp/s1;->i(Lvp/r1;)Z

    .line 190
    .line 191
    .line 192
    move-result v10

    .line 193
    if-eqz v10, :cond_2

    .line 194
    .line 195
    const/4 v10, 0x2

    .line 196
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v10

    .line 200
    invoke-virtual {v5, v10}, Lvp/t0;->I(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    :cond_2
    const/4 v10, 0x3

    .line 204
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 205
    .line 206
    .line 207
    move-result-wide v10

    .line 208
    invoke-virtual {v5, v10, v11}, Lvp/t0;->e(J)V

    .line 209
    .line 210
    .line 211
    const/4 v10, 0x4

    .line 212
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 213
    .line 214
    .line 215
    move-result-wide v10

    .line 216
    invoke-virtual {v5, v10, v11}, Lvp/t0;->L(J)V

    .line 217
    .line 218
    .line 219
    const/4 v10, 0x5

    .line 220
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 221
    .line 222
    .line 223
    move-result-wide v10

    .line 224
    invoke-virtual {v5, v10, v11}, Lvp/t0;->M(J)V

    .line 225
    .line 226
    .line 227
    const/4 v10, 0x6

    .line 228
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object v10

    .line 232
    invoke-virtual {v5, v10}, Lvp/t0;->O(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    const/4 v10, 0x7

    .line 236
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v10

    .line 240
    invoke-virtual {v5, v10}, Lvp/t0;->R(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    const/16 v10, 0x8

    .line 244
    .line 245
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 246
    .line 247
    .line 248
    move-result-wide v10

    .line 249
    invoke-virtual {v5, v10, v11}, Lvp/t0;->S(J)V

    .line 250
    .line 251
    .line 252
    const/16 v10, 0x9

    .line 253
    .line 254
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 255
    .line 256
    .line 257
    move-result-wide v10

    .line 258
    invoke-virtual {v5, v10, v11}, Lvp/t0;->a(J)V

    .line 259
    .line 260
    .line 261
    const/16 v10, 0xa

    .line 262
    .line 263
    invoke-interface {v4, v10}, Landroid/database/Cursor;->isNull(I)Z

    .line 264
    .line 265
    .line 266
    move-result v11

    .line 267
    if-nez v11, :cond_3

    .line 268
    .line 269
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getInt(I)I

    .line 270
    .line 271
    .line 272
    move-result v10

    .line 273
    if-eqz v10, :cond_4

    .line 274
    .line 275
    :cond_3
    move v10, v7

    .line 276
    goto :goto_1

    .line 277
    :cond_4
    move v10, v9

    .line 278
    :goto_1
    invoke-virtual {v5, v10}, Lvp/t0;->d(Z)V

    .line 279
    .line 280
    .line 281
    const/16 v10, 0xb

    .line 282
    .line 283
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 284
    .line 285
    .line 286
    move-result-wide v10

    .line 287
    invoke-virtual {v5, v10, v11}, Lvp/t0;->i(J)V

    .line 288
    .line 289
    .line 290
    const/16 v10, 0xc

    .line 291
    .line 292
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 293
    .line 294
    .line 295
    move-result-wide v10

    .line 296
    invoke-virtual {v5, v10, v11}, Lvp/t0;->j(J)V

    .line 297
    .line 298
    .line 299
    const/16 v10, 0xd

    .line 300
    .line 301
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 302
    .line 303
    .line 304
    move-result-wide v10

    .line 305
    invoke-virtual {v5, v10, v11}, Lvp/t0;->k(J)V

    .line 306
    .line 307
    .line 308
    const/16 v10, 0xe

    .line 309
    .line 310
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 311
    .line 312
    .line 313
    move-result-wide v10

    .line 314
    invoke-virtual {v5, v10, v11}, Lvp/t0;->l(J)V

    .line 315
    .line 316
    .line 317
    const/16 v10, 0xf

    .line 318
    .line 319
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 320
    .line 321
    .line 322
    move-result-wide v10

    .line 323
    invoke-virtual {v5, v10, v11}, Lvp/t0;->f(J)V

    .line 324
    .line 325
    .line 326
    const/16 v10, 0x10

    .line 327
    .line 328
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 329
    .line 330
    .line 331
    move-result-wide v10

    .line 332
    invoke-virtual {v5, v10, v11}, Lvp/t0;->g(J)V

    .line 333
    .line 334
    .line 335
    const/16 v10, 0x11

    .line 336
    .line 337
    invoke-interface {v4, v10}, Landroid/database/Cursor;->isNull(I)Z

    .line 338
    .line 339
    .line 340
    move-result v11

    .line 341
    if-eqz v11, :cond_5

    .line 342
    .line 343
    const-wide/32 v10, -0x80000000

    .line 344
    .line 345
    .line 346
    goto :goto_2

    .line 347
    :cond_5
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getInt(I)I

    .line 348
    .line 349
    .line 350
    move-result v10

    .line 351
    int-to-long v10, v10

    .line 352
    :goto_2
    invoke-virtual {v5, v10, v11}, Lvp/t0;->Q(J)V

    .line 353
    .line 354
    .line 355
    const/16 v10, 0x12

    .line 356
    .line 357
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 358
    .line 359
    .line 360
    move-result-object v10

    .line 361
    invoke-virtual {v5, v10}, Lvp/t0;->K(Ljava/lang/String;)V

    .line 362
    .line 363
    .line 364
    const/16 v10, 0x13

    .line 365
    .line 366
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 367
    .line 368
    .line 369
    move-result-wide v10

    .line 370
    invoke-virtual {v5, v10, v11}, Lvp/t0;->n(J)V

    .line 371
    .line 372
    .line 373
    const/16 v10, 0x14

    .line 374
    .line 375
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 376
    .line 377
    .line 378
    move-result-wide v10

    .line 379
    invoke-virtual {v5, v10, v11}, Lvp/t0;->m(J)V

    .line 380
    .line 381
    .line 382
    const/16 v10, 0x15

    .line 383
    .line 384
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 385
    .line 386
    .line 387
    move-result-object v10

    .line 388
    invoke-virtual {v5, v10}, Lvp/t0;->v(Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    const/16 v10, 0x17

    .line 392
    .line 393
    invoke-interface {v4, v10}, Landroid/database/Cursor;->isNull(I)Z

    .line 394
    .line 395
    .line 396
    move-result v11

    .line 397
    if-nez v11, :cond_6

    .line 398
    .line 399
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getInt(I)I

    .line 400
    .line 401
    .line 402
    move-result v10

    .line 403
    if-eqz v10, :cond_7

    .line 404
    .line 405
    :cond_6
    move v10, v7

    .line 406
    goto :goto_3

    .line 407
    :cond_7
    move v10, v9

    .line 408
    :goto_3
    iget-object v11, v6, Lvp/g1;->j:Lvp/e1;

    .line 409
    .line 410
    invoke-static {v11}, Lvp/g1;->k(Lvp/n1;)V

    .line 411
    .line 412
    .line 413
    invoke-virtual {v11}, Lvp/e1;->a0()V

    .line 414
    .line 415
    .line 416
    iget-boolean v11, v5, Lvp/t0;->Q:Z

    .line 417
    .line 418
    iget-boolean v12, v5, Lvp/t0;->p:Z

    .line 419
    .line 420
    if-eq v12, v10, :cond_8

    .line 421
    .line 422
    move v12, v7

    .line 423
    goto :goto_4

    .line 424
    :cond_8
    move v12, v9

    .line 425
    :goto_4
    or-int/2addr v11, v12

    .line 426
    iput-boolean v11, v5, Lvp/t0;->Q:Z

    .line 427
    .line 428
    iput-boolean v10, v5, Lvp/t0;->p:Z

    .line 429
    .line 430
    const/16 v10, 0x19

    .line 431
    .line 432
    invoke-interface {v4, v10}, Landroid/database/Cursor;->isNull(I)Z

    .line 433
    .line 434
    .line 435
    move-result v11

    .line 436
    if-eqz v11, :cond_9

    .line 437
    .line 438
    const-wide/16 v10, 0x0

    .line 439
    .line 440
    goto :goto_5

    .line 441
    :cond_9
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 442
    .line 443
    .line 444
    move-result-wide v10

    .line 445
    :goto_5
    invoke-virtual {v5, v10, v11}, Lvp/t0;->c(J)V

    .line 446
    .line 447
    .line 448
    const/16 v10, 0x1a

    .line 449
    .line 450
    invoke-interface {v4, v10}, Landroid/database/Cursor;->isNull(I)Z

    .line 451
    .line 452
    .line 453
    move-result v11

    .line 454
    if-nez v11, :cond_a

    .line 455
    .line 456
    invoke-interface {v4, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 457
    .line 458
    .line 459
    move-result-object v10

    .line 460
    const-string v11, ","

    .line 461
    .line 462
    const/4 v12, -0x1

    .line 463
    invoke-virtual {v10, v11, v12}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 464
    .line 465
    .line 466
    move-result-object v10

    .line 467
    invoke-static {v10}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 468
    .line 469
    .line 470
    move-result-object v10

    .line 471
    invoke-virtual {v5, v10}, Lvp/t0;->x(Ljava/util/List;)V

    .line 472
    .line 473
    .line 474
    :cond_a
    invoke-virtual {v0, v1}, Lvp/z3;->a(Ljava/lang/String;)Lvp/s1;

    .line 475
    .line 476
    .line 477
    move-result-object v0

    .line 478
    invoke-virtual {v0, v8}, Lvp/s1;->i(Lvp/r1;)Z

    .line 479
    .line 480
    .line 481
    move-result v0

    .line 482
    if-eqz v0, :cond_b

    .line 483
    .line 484
    const/16 v0, 0x1c

    .line 485
    .line 486
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 491
    .line 492
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 493
    .line 494
    .line 495
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 496
    .line 497
    .line 498
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 499
    .line 500
    iget-object v10, v5, Lvp/t0;->t:Ljava/lang/String;

    .line 501
    .line 502
    invoke-static {v10, v0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 503
    .line 504
    .line 505
    move-result v10

    .line 506
    xor-int/2addr v10, v7

    .line 507
    or-int/2addr v8, v10

    .line 508
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 509
    .line 510
    iput-object v0, v5, Lvp/t0;->t:Ljava/lang/String;

    .line 511
    .line 512
    goto :goto_6

    .line 513
    :catch_0
    move-exception v0

    .line 514
    goto/16 :goto_14

    .line 515
    .line 516
    :cond_b
    :goto_6
    const/16 v0, 0x1d

    .line 517
    .line 518
    invoke-interface {v4, v0}, Landroid/database/Cursor;->isNull(I)Z

    .line 519
    .line 520
    .line 521
    move-result v8

    .line 522
    if-nez v8, :cond_c

    .line 523
    .line 524
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 525
    .line 526
    .line 527
    move-result v0

    .line 528
    if-eqz v0, :cond_c

    .line 529
    .line 530
    move v0, v7

    .line 531
    goto :goto_7

    .line 532
    :cond_c
    move v0, v9

    .line 533
    :goto_7
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 534
    .line 535
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 536
    .line 537
    .line 538
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 539
    .line 540
    .line 541
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 542
    .line 543
    iget-boolean v10, v5, Lvp/t0;->u:Z

    .line 544
    .line 545
    if-eq v10, v0, :cond_d

    .line 546
    .line 547
    move v10, v7

    .line 548
    goto :goto_8

    .line 549
    :cond_d
    move v10, v9

    .line 550
    :goto_8
    or-int/2addr v8, v10

    .line 551
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 552
    .line 553
    iput-boolean v0, v5, Lvp/t0;->u:Z

    .line 554
    .line 555
    const/16 v0, 0x27

    .line 556
    .line 557
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 558
    .line 559
    .line 560
    move-result-wide v10

    .line 561
    invoke-virtual {v5, v10, v11}, Lvp/t0;->r(J)V

    .line 562
    .line 563
    .line 564
    const/16 v0, 0x24

    .line 565
    .line 566
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 567
    .line 568
    .line 569
    move-result-object v0

    .line 570
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 571
    .line 572
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 573
    .line 574
    .line 575
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 576
    .line 577
    .line 578
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 579
    .line 580
    iget-object v10, v5, Lvp/t0;->C:Ljava/lang/String;

    .line 581
    .line 582
    if-eq v10, v0, :cond_e

    .line 583
    .line 584
    move v10, v7

    .line 585
    goto :goto_9

    .line 586
    :cond_e
    move v10, v9

    .line 587
    :goto_9
    or-int/2addr v8, v10

    .line 588
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 589
    .line 590
    iput-object v0, v5, Lvp/t0;->C:Ljava/lang/String;

    .line 591
    .line 592
    const/16 v0, 0x1e

    .line 593
    .line 594
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 595
    .line 596
    .line 597
    move-result-wide v10

    .line 598
    invoke-virtual {v5, v10, v11}, Lvp/t0;->z(J)V

    .line 599
    .line 600
    .line 601
    const/16 v0, 0x1f

    .line 602
    .line 603
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 604
    .line 605
    .line 606
    move-result-wide v10

    .line 607
    invoke-virtual {v5, v10, v11}, Lvp/t0;->A(J)V

    .line 608
    .line 609
    .line 610
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 611
    .line 612
    .line 613
    iget-object v0, v2, Lvp/g1;->g:Lvp/h;

    .line 614
    .line 615
    sget-object v8, Lvp/z;->P0:Lvp/y;

    .line 616
    .line 617
    invoke-virtual {v0, v1, v8}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 618
    .line 619
    .line 620
    move-result v0

    .line 621
    if-eqz v0, :cond_10

    .line 622
    .line 623
    const/16 v0, 0x20

    .line 624
    .line 625
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 626
    .line 627
    .line 628
    move-result v0

    .line 629
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 630
    .line 631
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 632
    .line 633
    .line 634
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 635
    .line 636
    .line 637
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 638
    .line 639
    iget v10, v5, Lvp/t0;->x:I

    .line 640
    .line 641
    if-eq v10, v0, :cond_f

    .line 642
    .line 643
    move v10, v7

    .line 644
    goto :goto_a

    .line 645
    :cond_f
    move v10, v9

    .line 646
    :goto_a
    or-int/2addr v8, v10

    .line 647
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 648
    .line 649
    iput v0, v5, Lvp/t0;->x:I

    .line 650
    .line 651
    const/16 v0, 0x23

    .line 652
    .line 653
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 654
    .line 655
    .line 656
    move-result-wide v10

    .line 657
    invoke-virtual {v5, v10, v11}, Lvp/t0;->B(J)V

    .line 658
    .line 659
    .line 660
    :cond_10
    const/16 v0, 0x21

    .line 661
    .line 662
    invoke-interface {v4, v0}, Landroid/database/Cursor;->isNull(I)Z

    .line 663
    .line 664
    .line 665
    move-result v8

    .line 666
    if-nez v8, :cond_11

    .line 667
    .line 668
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 669
    .line 670
    .line 671
    move-result v0

    .line 672
    if-eqz v0, :cond_11

    .line 673
    .line 674
    move v0, v7

    .line 675
    goto :goto_b

    .line 676
    :cond_11
    move v0, v9

    .line 677
    :goto_b
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 678
    .line 679
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 680
    .line 681
    .line 682
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 683
    .line 684
    .line 685
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 686
    .line 687
    iget-boolean v10, v5, Lvp/t0;->y:Z

    .line 688
    .line 689
    if-eq v10, v0, :cond_12

    .line 690
    .line 691
    move v10, v7

    .line 692
    goto :goto_c

    .line 693
    :cond_12
    move v10, v9

    .line 694
    :goto_c
    or-int/2addr v8, v10

    .line 695
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 696
    .line 697
    iput-boolean v0, v5, Lvp/t0;->y:Z

    .line 698
    .line 699
    const/16 v0, 0x22

    .line 700
    .line 701
    invoke-interface {v4, v0}, Landroid/database/Cursor;->isNull(I)Z

    .line 702
    .line 703
    .line 704
    move-result v8

    .line 705
    if-eqz v8, :cond_13

    .line 706
    .line 707
    move-object v0, v3

    .line 708
    goto :goto_e

    .line 709
    :cond_13
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 710
    .line 711
    .line 712
    move-result v0

    .line 713
    if-eqz v0, :cond_14

    .line 714
    .line 715
    move v0, v7

    .line 716
    goto :goto_d

    .line 717
    :cond_14
    move v0, v9

    .line 718
    :goto_d
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 719
    .line 720
    .line 721
    move-result-object v0

    .line 722
    :goto_e
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 723
    .line 724
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 725
    .line 726
    .line 727
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 728
    .line 729
    .line 730
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 731
    .line 732
    iget-object v10, v5, Lvp/t0;->q:Ljava/lang/Boolean;

    .line 733
    .line 734
    invoke-static {v10, v0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 735
    .line 736
    .line 737
    move-result v10

    .line 738
    xor-int/2addr v10, v7

    .line 739
    or-int/2addr v8, v10

    .line 740
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 741
    .line 742
    iput-object v0, v5, Lvp/t0;->q:Ljava/lang/Boolean;

    .line 743
    .line 744
    const/16 v0, 0x25

    .line 745
    .line 746
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 747
    .line 748
    .line 749
    move-result v0

    .line 750
    invoke-virtual {v5, v0}, Lvp/t0;->p(I)V

    .line 751
    .line 752
    .line 753
    const/16 v0, 0x26

    .line 754
    .line 755
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 756
    .line 757
    .line 758
    move-result v0

    .line 759
    invoke-virtual {v5, v0}, Lvp/t0;->q(I)V

    .line 760
    .line 761
    .line 762
    const/16 v0, 0x28

    .line 763
    .line 764
    invoke-interface {v4, v0}, Landroid/database/Cursor;->isNull(I)Z

    .line 765
    .line 766
    .line 767
    move-result v8

    .line 768
    if-eqz v8, :cond_15

    .line 769
    .line 770
    const-string v0, ""

    .line 771
    .line 772
    goto :goto_f

    .line 773
    :cond_15
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 774
    .line 775
    .line 776
    move-result-object v0

    .line 777
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 778
    .line 779
    .line 780
    :goto_f
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 781
    .line 782
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 783
    .line 784
    .line 785
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 786
    .line 787
    .line 788
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 789
    .line 790
    iget-object v10, v5, Lvp/t0;->G:Ljava/lang/String;

    .line 791
    .line 792
    if-eq v10, v0, :cond_16

    .line 793
    .line 794
    move v10, v7

    .line 795
    goto :goto_10

    .line 796
    :cond_16
    move v10, v9

    .line 797
    :goto_10
    or-int/2addr v8, v10

    .line 798
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 799
    .line 800
    iput-object v0, v5, Lvp/t0;->G:Ljava/lang/String;

    .line 801
    .line 802
    const/16 v0, 0x29

    .line 803
    .line 804
    invoke-interface {v4, v0}, Landroid/database/Cursor;->isNull(I)Z

    .line 805
    .line 806
    .line 807
    move-result v8

    .line 808
    if-nez v8, :cond_17

    .line 809
    .line 810
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 811
    .line 812
    .line 813
    move-result-wide v10

    .line 814
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 815
    .line 816
    .line 817
    move-result-object v0

    .line 818
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 819
    .line 820
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 821
    .line 822
    .line 823
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 824
    .line 825
    .line 826
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 827
    .line 828
    iget-object v10, v5, Lvp/t0;->z:Ljava/lang/Long;

    .line 829
    .line 830
    invoke-static {v10, v0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 831
    .line 832
    .line 833
    move-result v10

    .line 834
    xor-int/2addr v10, v7

    .line 835
    or-int/2addr v8, v10

    .line 836
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 837
    .line 838
    iput-object v0, v5, Lvp/t0;->z:Ljava/lang/Long;

    .line 839
    .line 840
    :cond_17
    const/16 v0, 0x2a

    .line 841
    .line 842
    invoke-interface {v4, v0}, Landroid/database/Cursor;->isNull(I)Z

    .line 843
    .line 844
    .line 845
    move-result v8

    .line 846
    if-nez v8, :cond_18

    .line 847
    .line 848
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 849
    .line 850
    .line 851
    move-result-wide v10

    .line 852
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 853
    .line 854
    .line 855
    move-result-object v0

    .line 856
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 857
    .line 858
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 859
    .line 860
    .line 861
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 862
    .line 863
    .line 864
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 865
    .line 866
    iget-object v10, v5, Lvp/t0;->A:Ljava/lang/Long;

    .line 867
    .line 868
    invoke-static {v10, v0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 869
    .line 870
    .line 871
    move-result v10

    .line 872
    xor-int/2addr v10, v7

    .line 873
    or-int/2addr v8, v10

    .line 874
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 875
    .line 876
    iput-object v0, v5, Lvp/t0;->A:Ljava/lang/Long;

    .line 877
    .line 878
    :cond_18
    const/16 v0, 0x2b

    .line 879
    .line 880
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getBlob(I)[B

    .line 881
    .line 882
    .line 883
    move-result-object v0

    .line 884
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 885
    .line 886
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 887
    .line 888
    .line 889
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 890
    .line 891
    .line 892
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 893
    .line 894
    iget-object v10, v5, Lvp/t0;->H:[B

    .line 895
    .line 896
    if-eq v10, v0, :cond_19

    .line 897
    .line 898
    move v10, v7

    .line 899
    goto :goto_11

    .line 900
    :cond_19
    move v10, v9

    .line 901
    :goto_11
    or-int/2addr v8, v10

    .line 902
    iput-boolean v8, v5, Lvp/t0;->Q:Z

    .line 903
    .line 904
    iput-object v0, v5, Lvp/t0;->H:[B

    .line 905
    .line 906
    const/16 v0, 0x2c

    .line 907
    .line 908
    invoke-interface {v4, v0}, Landroid/database/Cursor;->isNull(I)Z

    .line 909
    .line 910
    .line 911
    move-result v8

    .line 912
    if-nez v8, :cond_1b

    .line 913
    .line 914
    invoke-interface {v4, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 915
    .line 916
    .line 917
    move-result v0

    .line 918
    iget-object v8, v6, Lvp/g1;->j:Lvp/e1;

    .line 919
    .line 920
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 921
    .line 922
    .line 923
    invoke-virtual {v8}, Lvp/e1;->a0()V

    .line 924
    .line 925
    .line 926
    iget-boolean v8, v5, Lvp/t0;->Q:Z

    .line 927
    .line 928
    iget v10, v5, Lvp/t0;->I:I

    .line 929
    .line 930
    if-eq v10, v0, :cond_1a

    .line 931
    .line 932
    goto :goto_12

    .line 933
    :cond_1a
    move v7, v9

    .line 934
    :goto_12
    or-int/2addr v7, v8

    .line 935
    iput-boolean v7, v5, Lvp/t0;->Q:Z

    .line 936
    .line 937
    iput v0, v5, Lvp/t0;->I:I

    .line 938
    .line 939
    :cond_1b
    iget-object v0, v6, Lvp/g1;->j:Lvp/e1;

    .line 940
    .line 941
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 942
    .line 943
    .line 944
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 945
    .line 946
    .line 947
    iput-boolean v9, v5, Lvp/t0;->Q:Z

    .line 948
    .line 949
    invoke-interface {v4}, Landroid/database/Cursor;->moveToNext()Z

    .line 950
    .line 951
    .line 952
    move-result v0

    .line 953
    if-eqz v0, :cond_1c

    .line 954
    .line 955
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 956
    .line 957
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 958
    .line 959
    .line 960
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 961
    .line 962
    const-string v6, "Got multiple records for app, expected one. appId"

    .line 963
    .line 964
    invoke-static {v1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 965
    .line 966
    .line 967
    move-result-object v7

    .line 968
    invoke-virtual {v0, v7, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 969
    .line 970
    .line 971
    :cond_1c
    invoke-interface {v4}, Landroid/database/Cursor;->close()V

    .line 972
    .line 973
    .line 974
    return-object v5

    .line 975
    :goto_13
    move-object v3, v4

    .line 976
    goto :goto_16

    .line 977
    :catchall_1
    move-exception v0

    .line 978
    goto :goto_16

    .line 979
    :catch_1
    move-exception v0

    .line 980
    move-object v4, v3

    .line 981
    :goto_14
    :try_start_2
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 982
    .line 983
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 984
    .line 985
    .line 986
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 987
    .line 988
    const-string v5, "Error querying app. appId"

    .line 989
    .line 990
    invoke-static {v1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 991
    .line 992
    .line 993
    move-result-object v1

    .line 994
    invoke-virtual {v2, v1, v0, v5}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 995
    .line 996
    .line 997
    :goto_15
    if-eqz v4, :cond_1d

    .line 998
    .line 999
    invoke-interface {v4}, Landroid/database/Cursor;->close()V

    .line 1000
    .line 1001
    .line 1002
    :cond_1d
    return-object v3

    .line 1003
    :goto_16
    if-eqz v3, :cond_1e

    .line 1004
    .line 1005
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 1006
    .line 1007
    .line 1008
    :cond_1e
    throw v0
.end method

.method public final d0()V
    .locals 0

    .line 1
    return-void
.end method

.method public final d1(Lvp/t0;Z)V
    .locals 13

    .line 1
    const-string v0, "apps"

    .line 2
    .line 3
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lvp/g1;

    .line 6
    .line 7
    iget-object v2, p1, Lvp/t0;->a:Lvp/g1;

    .line 8
    .line 9
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1}, Lvp/t0;->D()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    new-instance v4, Landroid/content/ContentValues;

    .line 23
    .line 24
    invoke-direct {v4}, Landroid/content/ContentValues;-><init>()V

    .line 25
    .line 26
    .line 27
    const-string v5, "app_id"

    .line 28
    .line 29
    invoke-virtual {v4, v5, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    sget-object v5, Lvp/r1;->f:Lvp/r1;

    .line 33
    .line 34
    iget-object v6, p0, Lvp/q3;->f:Lvp/z3;

    .line 35
    .line 36
    const-string v7, "app_instance_id"

    .line 37
    .line 38
    const/4 v8, 0x0

    .line 39
    if-eqz p2, :cond_0

    .line 40
    .line 41
    invoke-virtual {v4, v7, v8}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    invoke-virtual {v6, v3}, Lvp/z3;->a(Ljava/lang/String;)Lvp/s1;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    invoke-virtual {p2, v5}, Lvp/s1;->i(Lvp/r1;)Z

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    if-eqz p2, :cond_1

    .line 54
    .line 55
    invoke-virtual {p1}, Lvp/t0;->E()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    :cond_1
    :goto_0
    invoke-virtual {p1}, Lvp/t0;->G()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    const-string v7, "gmp_app_id"

    .line 67
    .line 68
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v6, v3}, Lvp/z3;->a(Ljava/lang/String;)Lvp/s1;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    sget-object v7, Lvp/r1;->e:Lvp/r1;

    .line 76
    .line 77
    invoke-virtual {p2, v7}, Lvp/s1;->i(Lvp/r1;)Z

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    if-eqz p2, :cond_2

    .line 82
    .line 83
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 84
    .line 85
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 89
    .line 90
    .line 91
    iget-object p2, p1, Lvp/t0;->e:Ljava/lang/String;

    .line 92
    .line 93
    const-string v7, "resettable_device_id_hash"

    .line 94
    .line 95
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    :cond_2
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 99
    .line 100
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 104
    .line 105
    .line 106
    iget-wide v9, p1, Lvp/t0;->g:J

    .line 107
    .line 108
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 109
    .line 110
    .line 111
    move-result-object p2

    .line 112
    const-string v7, "last_bundle_index"

    .line 113
    .line 114
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 115
    .line 116
    .line 117
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 118
    .line 119
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 123
    .line 124
    .line 125
    iget-wide v9, p1, Lvp/t0;->h:J

    .line 126
    .line 127
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 128
    .line 129
    .line 130
    move-result-object p2

    .line 131
    const-string v7, "last_bundle_start_timestamp"

    .line 132
    .line 133
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 134
    .line 135
    .line 136
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 137
    .line 138
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 142
    .line 143
    .line 144
    iget-wide v9, p1, Lvp/t0;->i:J

    .line 145
    .line 146
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 147
    .line 148
    .line 149
    move-result-object p2

    .line 150
    const-string v7, "last_bundle_end_timestamp"

    .line 151
    .line 152
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {p1}, Lvp/t0;->N()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p2

    .line 159
    const-string v7, "app_version"

    .line 160
    .line 161
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 165
    .line 166
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 170
    .line 171
    .line 172
    iget-object p2, p1, Lvp/t0;->l:Ljava/lang/String;

    .line 173
    .line 174
    const-string v7, "app_store"

    .line 175
    .line 176
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 180
    .line 181
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 185
    .line 186
    .line 187
    iget-wide v9, p1, Lvp/t0;->m:J

    .line 188
    .line 189
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 190
    .line 191
    .line 192
    move-result-object p2

    .line 193
    const-string v7, "gmp_version"

    .line 194
    .line 195
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 196
    .line 197
    .line 198
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 199
    .line 200
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 204
    .line 205
    .line 206
    iget-wide v9, p1, Lvp/t0;->n:J

    .line 207
    .line 208
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 209
    .line 210
    .line 211
    move-result-object p2

    .line 212
    const-string v7, "dev_cert_hash"

    .line 213
    .line 214
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 215
    .line 216
    .line 217
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 218
    .line 219
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 223
    .line 224
    .line 225
    iget-boolean p2, p1, Lvp/t0;->o:Z

    .line 226
    .line 227
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 228
    .line 229
    .line 230
    move-result-object p2

    .line 231
    const-string v7, "measurement_enabled"

    .line 232
    .line 233
    invoke-virtual {v4, v7, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 234
    .line 235
    .line 236
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 237
    .line 238
    iget-object v7, v2, Lvp/g1;->j:Lvp/e1;

    .line 239
    .line 240
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 244
    .line 245
    .line 246
    iget-wide v9, p1, Lvp/t0;->J:J

    .line 247
    .line 248
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 249
    .line 250
    .line 251
    move-result-object p2

    .line 252
    const-string v9, "day"

    .line 253
    .line 254
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 255
    .line 256
    .line 257
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v7}, Lvp/e1;->a0()V

    .line 261
    .line 262
    .line 263
    iget-wide v9, p1, Lvp/t0;->K:J

    .line 264
    .line 265
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 266
    .line 267
    .line 268
    move-result-object p2

    .line 269
    const-string v9, "daily_public_events_count"

    .line 270
    .line 271
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 272
    .line 273
    .line 274
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v7}, Lvp/e1;->a0()V

    .line 278
    .line 279
    .line 280
    iget-wide v9, p1, Lvp/t0;->L:J

    .line 281
    .line 282
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 283
    .line 284
    .line 285
    move-result-object p2

    .line 286
    const-string v9, "daily_events_count"

    .line 287
    .line 288
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 289
    .line 290
    .line 291
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v7}, Lvp/e1;->a0()V

    .line 295
    .line 296
    .line 297
    iget-wide v9, p1, Lvp/t0;->M:J

    .line 298
    .line 299
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 300
    .line 301
    .line 302
    move-result-object p2

    .line 303
    const-string v9, "daily_conversions_count"

    .line 304
    .line 305
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 306
    .line 307
    .line 308
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 309
    .line 310
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 311
    .line 312
    .line 313
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 314
    .line 315
    .line 316
    iget-wide v9, p1, Lvp/t0;->R:J

    .line 317
    .line 318
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 319
    .line 320
    .line 321
    move-result-object p2

    .line 322
    const-string v9, "config_fetched_time"

    .line 323
    .line 324
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 325
    .line 326
    .line 327
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 328
    .line 329
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 330
    .line 331
    .line 332
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 333
    .line 334
    .line 335
    iget-wide v9, p1, Lvp/t0;->S:J

    .line 336
    .line 337
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 338
    .line 339
    .line 340
    move-result-object p2

    .line 341
    const-string v9, "failed_config_fetch_time"

    .line 342
    .line 343
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 344
    .line 345
    .line 346
    invoke-virtual {p1}, Lvp/t0;->P()J

    .line 347
    .line 348
    .line 349
    move-result-wide v9

    .line 350
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 351
    .line 352
    .line 353
    move-result-object p2

    .line 354
    const-string v9, "app_version_int"

    .line 355
    .line 356
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 357
    .line 358
    .line 359
    invoke-virtual {p1}, Lvp/t0;->J()Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object p2

    .line 363
    const-string v9, "firebase_instance_id"

    .line 364
    .line 365
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 369
    .line 370
    .line 371
    invoke-virtual {v7}, Lvp/e1;->a0()V

    .line 372
    .line 373
    .line 374
    iget-wide v9, p1, Lvp/t0;->N:J

    .line 375
    .line 376
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 377
    .line 378
    .line 379
    move-result-object p2

    .line 380
    const-string v9, "daily_error_events_count"

    .line 381
    .line 382
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 383
    .line 384
    .line 385
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v7}, Lvp/e1;->a0()V

    .line 389
    .line 390
    .line 391
    iget-wide v9, p1, Lvp/t0;->O:J

    .line 392
    .line 393
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 394
    .line 395
    .line 396
    move-result-object p2

    .line 397
    const-string v9, "daily_realtime_events_count"

    .line 398
    .line 399
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 400
    .line 401
    .line 402
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 403
    .line 404
    .line 405
    invoke-virtual {v7}, Lvp/e1;->a0()V

    .line 406
    .line 407
    .line 408
    iget-object p2, p1, Lvp/t0;->P:Ljava/lang/String;

    .line 409
    .line 410
    const-string v9, "health_monitor_sample"

    .line 411
    .line 412
    invoke-virtual {v4, v9, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 413
    .line 414
    .line 415
    const-string p2, "android_id"

    .line 416
    .line 417
    const-wide/16 v9, 0x0

    .line 418
    .line 419
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 420
    .line 421
    .line 422
    move-result-object v11

    .line 423
    invoke-virtual {v4, p2, v11}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 424
    .line 425
    .line 426
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 427
    .line 428
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 432
    .line 433
    .line 434
    iget-boolean p2, p1, Lvp/t0;->p:Z

    .line 435
    .line 436
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 437
    .line 438
    .line 439
    move-result-object p2

    .line 440
    const-string v11, "adid_reporting_enabled"

    .line 441
    .line 442
    invoke-virtual {v4, v11, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 443
    .line 444
    .line 445
    invoke-virtual {p1}, Lvp/t0;->b()J

    .line 446
    .line 447
    .line 448
    move-result-wide v11

    .line 449
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 450
    .line 451
    .line 452
    move-result-object p2

    .line 453
    const-string v11, "dynamite_version"

    .line 454
    .line 455
    invoke-virtual {v4, v11, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v6, v3}, Lvp/z3;->a(Ljava/lang/String;)Lvp/s1;

    .line 459
    .line 460
    .line 461
    move-result-object p2

    .line 462
    invoke-virtual {p2, v5}, Lvp/s1;->i(Lvp/r1;)Z

    .line 463
    .line 464
    .line 465
    move-result p2

    .line 466
    if-eqz p2, :cond_3

    .line 467
    .line 468
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 469
    .line 470
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 471
    .line 472
    .line 473
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 474
    .line 475
    .line 476
    iget-object p2, p1, Lvp/t0;->t:Ljava/lang/String;

    .line 477
    .line 478
    const-string v5, "session_stitching_token"

    .line 479
    .line 480
    invoke-virtual {v4, v5, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 481
    .line 482
    .line 483
    :cond_3
    invoke-virtual {p1}, Lvp/t0;->y()Z

    .line 484
    .line 485
    .line 486
    move-result p2

    .line 487
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 488
    .line 489
    .line 490
    move-result-object p2

    .line 491
    const-string v5, "sgtm_upload_enabled"

    .line 492
    .line 493
    invoke-virtual {v4, v5, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 494
    .line 495
    .line 496
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 497
    .line 498
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 499
    .line 500
    .line 501
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 502
    .line 503
    .line 504
    iget-wide v5, p1, Lvp/t0;->v:J

    .line 505
    .line 506
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 507
    .line 508
    .line 509
    move-result-object p2

    .line 510
    const-string v5, "target_os_version"

    .line 511
    .line 512
    invoke-virtual {v4, v5, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 513
    .line 514
    .line 515
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 516
    .line 517
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 518
    .line 519
    .line 520
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 521
    .line 522
    .line 523
    iget-wide v5, p1, Lvp/t0;->w:J

    .line 524
    .line 525
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 526
    .line 527
    .line 528
    move-result-object p2

    .line 529
    const-string v5, "session_stitching_token_hash"

    .line 530
    .line 531
    invoke-virtual {v4, v5, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 532
    .line 533
    .line 534
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 535
    .line 536
    .line 537
    iget-object p2, v1, Lvp/g1;->g:Lvp/h;

    .line 538
    .line 539
    iget-object v5, v1, Lvp/g1;->i:Lvp/p0;

    .line 540
    .line 541
    sget-object v6, Lvp/z;->P0:Lvp/y;

    .line 542
    .line 543
    invoke-virtual {p2, v3, v6}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 544
    .line 545
    .line 546
    move-result p2

    .line 547
    if-eqz p2, :cond_4

    .line 548
    .line 549
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 550
    .line 551
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 552
    .line 553
    .line 554
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 555
    .line 556
    .line 557
    iget p2, p1, Lvp/t0;->x:I

    .line 558
    .line 559
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 560
    .line 561
    .line 562
    move-result-object p2

    .line 563
    const-string v6, "ad_services_version"

    .line 564
    .line 565
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 566
    .line 567
    .line 568
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 569
    .line 570
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 571
    .line 572
    .line 573
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 574
    .line 575
    .line 576
    iget-wide v11, p1, Lvp/t0;->B:J

    .line 577
    .line 578
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 579
    .line 580
    .line 581
    move-result-object p2

    .line 582
    const-string v6, "attribution_eligibility_status"

    .line 583
    .line 584
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 585
    .line 586
    .line 587
    :cond_4
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 588
    .line 589
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 590
    .line 591
    .line 592
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 593
    .line 594
    .line 595
    iget-boolean p2, p1, Lvp/t0;->y:Z

    .line 596
    .line 597
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 598
    .line 599
    .line 600
    move-result-object p2

    .line 601
    const-string v6, "unmatched_first_open_without_ad_id"

    .line 602
    .line 603
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 604
    .line 605
    .line 606
    invoke-virtual {p1}, Lvp/t0;->w()Ljava/lang/Boolean;

    .line 607
    .line 608
    .line 609
    move-result-object p2

    .line 610
    const-string v6, "npa_metadata_value"

    .line 611
    .line 612
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 613
    .line 614
    .line 615
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 616
    .line 617
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 618
    .line 619
    .line 620
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 621
    .line 622
    .line 623
    iget-wide v11, p1, Lvp/t0;->F:J

    .line 624
    .line 625
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 626
    .line 627
    .line 628
    move-result-object p2

    .line 629
    const-string v6, "bundle_delivery_index"

    .line 630
    .line 631
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 632
    .line 633
    .line 634
    invoke-virtual {p1}, Lvp/t0;->C()Ljava/lang/String;

    .line 635
    .line 636
    .line 637
    move-result-object p2

    .line 638
    const-string v6, "sgtm_preview_key"

    .line 639
    .line 640
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 641
    .line 642
    .line 643
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 644
    .line 645
    .line 646
    invoke-virtual {v7}, Lvp/e1;->a0()V

    .line 647
    .line 648
    .line 649
    iget p2, p1, Lvp/t0;->D:I

    .line 650
    .line 651
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 652
    .line 653
    .line 654
    move-result-object p2

    .line 655
    const-string v6, "dma_consent_state"

    .line 656
    .line 657
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 658
    .line 659
    .line 660
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 661
    .line 662
    .line 663
    invoke-virtual {v7}, Lvp/e1;->a0()V

    .line 664
    .line 665
    .line 666
    iget p2, p1, Lvp/t0;->E:I

    .line 667
    .line 668
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 669
    .line 670
    .line 671
    move-result-object p2

    .line 672
    const-string v6, "daily_realtime_dcu_count"

    .line 673
    .line 674
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 675
    .line 676
    .line 677
    invoke-virtual {p1}, Lvp/t0;->s()Ljava/lang/String;

    .line 678
    .line 679
    .line 680
    move-result-object p2

    .line 681
    const-string v6, "serialized_npa_metadata"

    .line 682
    .line 683
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 684
    .line 685
    .line 686
    invoke-virtual {p1}, Lvp/t0;->t()I

    .line 687
    .line 688
    .line 689
    move-result p2

    .line 690
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 691
    .line 692
    .line 693
    move-result-object p2

    .line 694
    const-string v6, "client_upload_eligibility"

    .line 695
    .line 696
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 697
    .line 698
    .line 699
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 700
    .line 701
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 702
    .line 703
    .line 704
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 705
    .line 706
    .line 707
    iget-object p2, p1, Lvp/t0;->s:Ljava/util/ArrayList;

    .line 708
    .line 709
    const-string v6, "safelisted_events"

    .line 710
    .line 711
    if-eqz p2, :cond_6

    .line 712
    .line 713
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 714
    .line 715
    .line 716
    move-result v7

    .line 717
    if-eqz v7, :cond_5

    .line 718
    .line 719
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 720
    .line 721
    .line 722
    iget-object p2, v5, Lvp/p0;->m:Lvp/n0;

    .line 723
    .line 724
    const-string v7, "Safelisted events should not be an empty list. appId"

    .line 725
    .line 726
    invoke-virtual {p2, v3, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 727
    .line 728
    .line 729
    goto :goto_1

    .line 730
    :cond_5
    const-string v7, ","

    .line 731
    .line 732
    invoke-static {v7, p2}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 733
    .line 734
    .line 735
    move-result-object p2

    .line 736
    invoke-virtual {v4, v6, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 737
    .line 738
    .line 739
    :cond_6
    :goto_1
    sget-object p2, Lcom/google/android/gms/internal/measurement/w7;->e:Lcom/google/android/gms/internal/measurement/w7;

    .line 740
    .line 741
    iget-object p2, p2, Lcom/google/android/gms/internal/measurement/w7;->d:Lgr/p;

    .line 742
    .line 743
    iget-object p2, p2, Lgr/p;->d:Ljava/lang/Object;

    .line 744
    .line 745
    check-cast p2, Lcom/google/android/gms/internal/measurement/x7;

    .line 746
    .line 747
    iget-object p2, v1, Lvp/g1;->g:Lvp/h;

    .line 748
    .line 749
    sget-object v1, Lvp/z;->K0:Lvp/y;

    .line 750
    .line 751
    invoke-virtual {p2, v8, v1}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 752
    .line 753
    .line 754
    move-result p2

    .line 755
    if-eqz p2, :cond_7

    .line 756
    .line 757
    invoke-virtual {v4, v6}, Landroid/content/ContentValues;->containsKey(Ljava/lang/String;)Z

    .line 758
    .line 759
    .line 760
    move-result p2

    .line 761
    if-nez p2, :cond_7

    .line 762
    .line 763
    invoke-virtual {v4, v6, v8}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 764
    .line 765
    .line 766
    :cond_7
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 767
    .line 768
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 769
    .line 770
    .line 771
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 772
    .line 773
    .line 774
    iget-object p2, p1, Lvp/t0;->z:Ljava/lang/Long;

    .line 775
    .line 776
    const-string v1, "unmatched_pfo"

    .line 777
    .line 778
    invoke-virtual {v4, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 779
    .line 780
    .line 781
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 782
    .line 783
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 784
    .line 785
    .line 786
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 787
    .line 788
    .line 789
    iget-object p2, p1, Lvp/t0;->A:Ljava/lang/Long;

    .line 790
    .line 791
    const-string v1, "unmatched_uwa"

    .line 792
    .line 793
    invoke-virtual {v4, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 794
    .line 795
    .line 796
    iget-object p2, v2, Lvp/g1;->j:Lvp/e1;

    .line 797
    .line 798
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 799
    .line 800
    .line 801
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 802
    .line 803
    .line 804
    iget-object p1, p1, Lvp/t0;->H:[B

    .line 805
    .line 806
    const-string p2, "ad_campaign_info"

    .line 807
    .line 808
    invoke-virtual {v4, p2, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 809
    .line 810
    .line 811
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 812
    .line 813
    .line 814
    move-result-object p0

    .line 815
    const-string p1, "app_id = ?"

    .line 816
    .line 817
    filled-new-array {v3}, [Ljava/lang/String;

    .line 818
    .line 819
    .line 820
    move-result-object p2

    .line 821
    invoke-virtual {p0, v0, v4, p1, p2}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    .line 822
    .line 823
    .line 824
    move-result p1

    .line 825
    int-to-long p1, p1

    .line 826
    cmp-long p1, p1, v9

    .line 827
    .line 828
    if-nez p1, :cond_8

    .line 829
    .line 830
    const/4 p1, 0x5

    .line 831
    invoke-virtual {p0, v0, v8, v4, p1}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 832
    .line 833
    .line 834
    move-result-wide p0

    .line 835
    const-wide/16 v0, -0x1

    .line 836
    .line 837
    cmp-long p0, p0, v0

    .line 838
    .line 839
    if-nez p0, :cond_8

    .line 840
    .line 841
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 842
    .line 843
    .line 844
    iget-object p0, v5, Lvp/p0;->j:Lvp/n0;

    .line 845
    .line 846
    const-string p1, "Failed to insert/update app (got -1). appId"

    .line 847
    .line 848
    invoke-static {v3}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 849
    .line 850
    .line 851
    move-result-object p2

    .line 852
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 853
    .line 854
    .line 855
    return-void

    .line 856
    :catch_0
    move-exception p0

    .line 857
    goto :goto_2

    .line 858
    :cond_8
    return-void

    .line 859
    :goto_2
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 860
    .line 861
    .line 862
    iget-object p1, v5, Lvp/p0;->j:Lvp/n0;

    .line 863
    .line 864
    invoke-static {v3}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 865
    .line 866
    .line 867
    move-result-object p2

    .line 868
    const-string v0, "Error storing app. appId"

    .line 869
    .line 870
    invoke-virtual {p1, p2, p0, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 871
    .line 872
    .line 873
    return-void
.end method

.method public final e0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/h3;Ljava/lang/String;Ljava/util/Map;Lvp/q2;Ljava/lang/Long;)J
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p6

    .line 6
    .line 7
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    move-object v4, v0

    .line 10
    check-cast v4, Lvp/g1;

    .line 11
    .line 12
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Lvp/u3;->b0()V

    .line 16
    .line 17
    .line 18
    invoke-static/range {p2 .. p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-static {v2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1}, Lvp/u3;->b0()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1}, Lvp/n;->H0()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    const/4 v5, 0x0

    .line 35
    const/4 v6, 0x0

    .line 36
    const-string v7, "upload_queue"

    .line 37
    .line 38
    if-nez v0, :cond_0

    .line 39
    .line 40
    goto/16 :goto_1

    .line 41
    .line 42
    :cond_0
    iget-object v0, v1, Lvp/q3;->f:Lvp/z3;

    .line 43
    .line 44
    iget-object v8, v0, Lvp/z3;->l:Lvp/f3;

    .line 45
    .line 46
    iget-object v8, v8, Lvp/f3;->j:La8/s1;

    .line 47
    .line 48
    invoke-virtual {v8}, La8/s1;->g()J

    .line 49
    .line 50
    .line 51
    move-result-wide v8

    .line 52
    iget-object v10, v4, Lvp/g1;->n:Lto/a;

    .line 53
    .line 54
    iget-object v11, v4, Lvp/g1;->i:Lvp/p0;

    .line 55
    .line 56
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 60
    .line 61
    .line 62
    move-result-wide v12

    .line 63
    sub-long v8, v12, v8

    .line 64
    .line 65
    invoke-static {v8, v9}, Ljava/lang/Math;->abs(J)J

    .line 66
    .line 67
    .line 68
    move-result-wide v8

    .line 69
    sget-object v10, Lvp/z;->M:Lvp/y;

    .line 70
    .line 71
    invoke-virtual {v10, v5}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v10

    .line 75
    check-cast v10, Ljava/lang/Long;

    .line 76
    .line 77
    invoke-virtual {v10}, Ljava/lang/Long;->longValue()J

    .line 78
    .line 79
    .line 80
    move-result-wide v14

    .line 81
    cmp-long v8, v8, v14

    .line 82
    .line 83
    if-lez v8, :cond_3

    .line 84
    .line 85
    iget-object v0, v0, Lvp/z3;->l:Lvp/f3;

    .line 86
    .line 87
    iget-object v0, v0, Lvp/f3;->j:La8/s1;

    .line 88
    .line 89
    invoke-virtual {v0, v12, v13}, La8/s1;->h(J)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v1}, Lvp/u3;->b0()V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v1}, Lvp/n;->H0()Z

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    if-nez v0, :cond_1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_1
    invoke-virtual {v1}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    invoke-virtual {v1}, Lvp/n;->C0()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    new-array v9, v6, [Ljava/lang/String;

    .line 114
    .line 115
    invoke-virtual {v0, v7, v8, v9}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    if-lez v0, :cond_2

    .line 120
    .line 121
    invoke-static {v11}, Lvp/g1;->k(Lvp/n1;)V

    .line 122
    .line 123
    .line 124
    iget-object v8, v11, Lvp/p0;->r:Lvp/n0;

    .line 125
    .line 126
    const-string v9, "Deleted stale MeasurementBatch rows from upload_queue. rowsDeleted"

    .line 127
    .line 128
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    invoke-virtual {v8, v0, v9}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    :cond_2
    :goto_0
    invoke-static {v2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v1}, Lvp/u3;->b0()V

    .line 142
    .line 143
    .line 144
    :try_start_0
    iget-object v0, v4, Lvp/g1;->g:Lvp/h;

    .line 145
    .line 146
    sget-object v8, Lvp/z;->A:Lvp/y;

    .line 147
    .line 148
    invoke-virtual {v0, v2, v8}, Lvp/h;->i0(Ljava/lang/String;Lvp/y;)I

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    if-lez v0, :cond_3

    .line 153
    .line 154
    invoke-virtual {v1}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 155
    .line 156
    .line 157
    move-result-object v8

    .line 158
    const-string v9, "rowid in (SELECT rowid FROM upload_queue WHERE app_id=? ORDER BY rowid DESC LIMIT -1 OFFSET ?)"

    .line 159
    .line 160
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    filled-new-array {v2, v0}, [Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    invoke-virtual {v8, v7, v9, v0}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 169
    .line 170
    .line 171
    goto :goto_1

    .line 172
    :catch_0
    move-exception v0

    .line 173
    invoke-static {v11}, Lvp/g1;->k(Lvp/n1;)V

    .line 174
    .line 175
    .line 176
    iget-object v8, v11, Lvp/p0;->j:Lvp/n0;

    .line 177
    .line 178
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 179
    .line 180
    .line 181
    move-result-object v9

    .line 182
    const-string v10, "Error deleting over the limit queued batches. appId"

    .line 183
    .line 184
    invoke-virtual {v8, v9, v0, v10}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    :cond_3
    :goto_1
    new-instance v0, Ljava/util/ArrayList;

    .line 188
    .line 189
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 190
    .line 191
    .line 192
    invoke-interface/range {p4 .. p4}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 193
    .line 194
    .line 195
    move-result-object v8

    .line 196
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 197
    .line 198
    .line 199
    move-result-object v8

    .line 200
    :goto_2
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 201
    .line 202
    .line 203
    move-result v9

    .line 204
    if-eqz v9, :cond_4

    .line 205
    .line 206
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v9

    .line 210
    check-cast v9, Ljava/util/Map$Entry;

    .line 211
    .line 212
    invoke-interface {v9}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v10

    .line 216
    check-cast v10, Ljava/lang/String;

    .line 217
    .line 218
    invoke-interface {v9}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v9

    .line 222
    check-cast v9, Ljava/lang/String;

    .line 223
    .line 224
    invoke-static {v10}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v11

    .line 228
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 229
    .line 230
    .line 231
    move-result v11

    .line 232
    add-int/lit8 v11, v11, 0x1

    .line 233
    .line 234
    invoke-static {v9}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object v12

    .line 238
    invoke-virtual {v12}, Ljava/lang/String;->length()I

    .line 239
    .line 240
    .line 241
    move-result v12

    .line 242
    new-instance v13, Ljava/lang/StringBuilder;

    .line 243
    .line 244
    add-int/2addr v11, v12

    .line 245
    invoke-direct {v13, v11}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    const-string v10, "="

    .line 252
    .line 253
    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 254
    .line 255
    .line 256
    invoke-virtual {v13, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 257
    .line 258
    .line 259
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v9

    .line 263
    invoke-virtual {v0, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    goto :goto_2

    .line 267
    :cond_4
    invoke-virtual/range {p2 .. p2}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 268
    .line 269
    .line 270
    move-result-object v8

    .line 271
    new-instance v9, Landroid/content/ContentValues;

    .line 272
    .line 273
    invoke-direct {v9}, Landroid/content/ContentValues;-><init>()V

    .line 274
    .line 275
    .line 276
    const-string v10, "app_id"

    .line 277
    .line 278
    invoke-virtual {v9, v10, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    const-string v10, "measurement_batch"

    .line 282
    .line 283
    invoke-virtual {v9, v10, v8}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 284
    .line 285
    .line 286
    const-string v8, "upload_uri"

    .line 287
    .line 288
    move-object/from16 v10, p3

    .line 289
    .line 290
    invoke-virtual {v9, v8, v10}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    const-string v8, "\r\n"

    .line 294
    .line 295
    invoke-static {v8, v0}, Ljava/lang/String;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    const-string v8, "upload_headers"

    .line 300
    .line 301
    invoke-virtual {v9, v8, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    move-object/from16 v8, p5

    .line 305
    .line 306
    iget v0, v8, Lvp/q2;->d:I

    .line 307
    .line 308
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    const-string v8, "upload_type"

    .line 313
    .line 314
    invoke-virtual {v9, v8, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 315
    .line 316
    .line 317
    iget-object v0, v4, Lvp/g1;->n:Lto/a;

    .line 318
    .line 319
    iget-object v4, v4, Lvp/g1;->i:Lvp/p0;

    .line 320
    .line 321
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 322
    .line 323
    .line 324
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 325
    .line 326
    .line 327
    move-result-wide v10

    .line 328
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 329
    .line 330
    .line 331
    move-result-object v0

    .line 332
    const-string v8, "creation_timestamp"

    .line 333
    .line 334
    invoke-virtual {v9, v8, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 335
    .line 336
    .line 337
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    const-string v6, "retry_count"

    .line 342
    .line 343
    invoke-virtual {v9, v6, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 344
    .line 345
    .line 346
    if-eqz v3, :cond_5

    .line 347
    .line 348
    const-string v0, "associated_row_id"

    .line 349
    .line 350
    invoke-virtual {v9, v0, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 351
    .line 352
    .line 353
    :cond_5
    const-wide/16 v10, -0x1

    .line 354
    .line 355
    :try_start_1
    invoke-virtual {v1}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    invoke-virtual {v0, v7, v5, v9}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    .line 360
    .line 361
    .line 362
    move-result-wide v0

    .line 363
    cmp-long v3, v0, v10

    .line 364
    .line 365
    if-nez v3, :cond_6

    .line 366
    .line 367
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 368
    .line 369
    .line 370
    iget-object v0, v4, Lvp/p0;->j:Lvp/n0;

    .line 371
    .line 372
    const-string v1, "Failed to insert MeasurementBatch (got -1) to upload_queue. appId"

    .line 373
    .line 374
    invoke-virtual {v0, v2, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 375
    .line 376
    .line 377
    goto :goto_3

    .line 378
    :catch_1
    move-exception v0

    .line 379
    goto :goto_4

    .line 380
    :cond_6
    move-wide v10, v0

    .line 381
    :goto_3
    return-wide v10

    .line 382
    :goto_4
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 383
    .line 384
    .line 385
    iget-object v1, v4, Lvp/p0;->j:Lvp/n0;

    .line 386
    .line 387
    const-string v3, "Error storing MeasurementBatch to upload_queue. appId"

    .line 388
    .line 389
    invoke-virtual {v1, v2, v0, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 390
    .line 391
    .line 392
    return-wide v10
.end method

.method public final e1(JLjava/lang/String;ZZZZ)Lvp/k;
    .locals 13

    .line 1
    const/4 v7, 0x0

    .line 2
    const/4 v9, 0x0

    .line 3
    const-wide/16 v4, 0x1

    .line 4
    .line 5
    const/4 v6, 0x0

    .line 6
    move-object v0, p0

    .line 7
    move-wide v1, p1

    .line 8
    move-object/from16 v3, p3

    .line 9
    .line 10
    move/from16 v8, p4

    .line 11
    .line 12
    move/from16 v10, p5

    .line 13
    .line 14
    move/from16 v11, p6

    .line 15
    .line 16
    move/from16 v12, p7

    .line 17
    .line 18
    invoke-virtual/range {v0 .. v12}, Lvp/n;->f1(JLjava/lang/String;JZZZZZZZ)Lvp/k;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final f0(Ljava/lang/String;Lvp/s3;I)Ljava/util/List;
    .locals 18

    .line 1
    invoke-static/range {p1 .. p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual/range {p0 .. p0}, Lap0/o;->a0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual/range {p0 .. p0}, Lvp/u3;->b0()V

    .line 8
    .line 9
    .line 10
    const-string v0, " AND NOT "

    .line 11
    .line 12
    const-string v1, "app_id=?"

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    :try_start_0
    invoke-virtual/range {p0 .. p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    const-string v4, "upload_queue"

    .line 20
    .line 21
    const-string v5, "rowId"

    .line 22
    .line 23
    const-string v6, "app_id"

    .line 24
    .line 25
    const-string v7, "measurement_batch"

    .line 26
    .line 27
    const-string v8, "upload_uri"

    .line 28
    .line 29
    const-string v9, "upload_headers"

    .line 30
    .line 31
    const-string v10, "upload_type"

    .line 32
    .line 33
    const-string v11, "retry_count"

    .line 34
    .line 35
    const-string v12, "creation_timestamp"

    .line 36
    .line 37
    const-string v13, "associated_row_id"

    .line 38
    .line 39
    const-string v14, "last_upload_timestamp"

    .line 40
    .line 41
    filled-new-array/range {v5 .. v14}, [Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    move-object/from16 v6, p2

    .line 46
    .line 47
    iget-object v6, v6, Lvp/s3;->d:Ljava/util/List;

    .line 48
    .line 49
    invoke-static {v6}, Lvp/n;->D0(Ljava/util/List;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    invoke-virtual/range {p0 .. p0}, Lvp/n;->C0()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    add-int/lit8 v8, v8, 0x11

    .line 62
    .line 63
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 64
    .line 65
    .line 66
    move-result v9

    .line 67
    add-int/2addr v8, v9

    .line 68
    new-instance v9, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    invoke-direct {v9, v8}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v9, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v9, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    filled-new-array/range {p1 .. p1}, [Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v7

    .line 93
    const-string v10, "creation_timestamp ASC"

    .line 94
    .line 95
    if-lez p3, :cond_0

    .line 96
    .line 97
    invoke-static/range {p3 .. p3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    move-object v11, v0

    .line 102
    goto :goto_0

    .line 103
    :cond_0
    move-object v11, v2

    .line 104
    :goto_0
    const/4 v8, 0x0

    .line 105
    const/4 v9, 0x0

    .line 106
    invoke-virtual/range {v3 .. v11}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    new-instance v0, Ljava/util/ArrayList;

    .line 111
    .line 112
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 113
    .line 114
    .line 115
    :cond_1
    :goto_1
    invoke-interface {v2}, Landroid/database/Cursor;->moveToNext()Z

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    if-eqz v1, :cond_2

    .line 120
    .line 121
    const/4 v1, 0x0

    .line 122
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getLong(I)J

    .line 123
    .line 124
    .line 125
    move-result-wide v5

    .line 126
    const/4 v1, 0x2

    .line 127
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getBlob(I)[B

    .line 128
    .line 129
    .line 130
    move-result-object v7

    .line 131
    const/4 v1, 0x3

    .line 132
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v8

    .line 136
    const/4 v1, 0x4

    .line 137
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v9

    .line 141
    const/4 v1, 0x5

    .line 142
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getInt(I)I

    .line 143
    .line 144
    .line 145
    move-result v10

    .line 146
    const/4 v1, 0x6

    .line 147
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getInt(I)I

    .line 148
    .line 149
    .line 150
    move-result v11

    .line 151
    const/4 v1, 0x7

    .line 152
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getLong(I)J

    .line 153
    .line 154
    .line 155
    move-result-wide v12

    .line 156
    const/16 v1, 0x8

    .line 157
    .line 158
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getLong(I)J

    .line 159
    .line 160
    .line 161
    move-result-wide v14

    .line 162
    const/16 v1, 0x9

    .line 163
    .line 164
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getLong(I)J

    .line 165
    .line 166
    .line 167
    move-result-wide v16

    .line 168
    move-object/from16 v3, p0

    .line 169
    .line 170
    move-object/from16 v4, p1

    .line 171
    .line 172
    invoke-virtual/range {v3 .. v17}, Lvp/n;->B0(Ljava/lang/String;J[BLjava/lang/String;Ljava/lang/String;IIJJJ)Lvp/a4;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    if-eqz v1, :cond_1

    .line 177
    .line 178
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 179
    .line 180
    .line 181
    goto :goto_1

    .line 182
    :catchall_0
    move-exception v0

    .line 183
    goto :goto_2

    .line 184
    :catch_0
    move-exception v0

    .line 185
    move-object/from16 v3, p0

    .line 186
    .line 187
    :try_start_1
    iget-object v1, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast v1, Lvp/g1;

    .line 190
    .line 191
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 192
    .line 193
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 194
    .line 195
    .line 196
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 197
    .line 198
    const-string v3, "Error to querying MeasurementBatch from upload_queue. appId"

    .line 199
    .line 200
    move-object/from16 v4, p1

    .line 201
    .line 202
    invoke-virtual {v1, v4, v0, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 206
    .line 207
    :cond_2
    if-eqz v2, :cond_3

    .line 208
    .line 209
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 210
    .line 211
    .line 212
    :cond_3
    return-object v0

    .line 213
    :goto_2
    if-eqz v2, :cond_4

    .line 214
    .line 215
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 216
    .line 217
    .line 218
    :cond_4
    throw v0
.end method

.method public final f1(JLjava/lang/String;JZZZZZZZ)Lvp/k;
    .locals 14

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lvp/g1;

    .line 5
    .line 6
    invoke-static/range {p3 .. p3}, Lno/c0;->e(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 13
    .line 14
    .line 15
    filled-new-array/range {p3 .. p3}, [Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v2, Lvp/k;

    .line 20
    .line 21
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    const-string v5, "apps"

    .line 30
    .line 31
    const-string v6, "day"

    .line 32
    .line 33
    const-string v7, "daily_events_count"

    .line 34
    .line 35
    const-string v8, "daily_public_events_count"

    .line 36
    .line 37
    const-string v9, "daily_conversions_count"

    .line 38
    .line 39
    const-string v10, "daily_error_events_count"

    .line 40
    .line 41
    const-string v11, "daily_realtime_events_count"

    .line 42
    .line 43
    const-string v12, "daily_realtime_dcu_count"

    .line 44
    .line 45
    const-string v13, "daily_registered_triggers_count"

    .line 46
    .line 47
    filled-new-array/range {v6 .. v13}, [Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    const-string v7, "app_id=?"

    .line 52
    .line 53
    filled-new-array/range {p3 .. p3}, [Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v8

    .line 57
    const/4 v10, 0x0

    .line 58
    const/4 v11, 0x0

    .line 59
    const/4 v9, 0x0

    .line 60
    invoke-virtual/range {v4 .. v11}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-nez p0, :cond_0

    .line 69
    .line 70
    iget-object p0, v1, Lvp/g1;->i:Lvp/p0;

    .line 71
    .line 72
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 76
    .line 77
    const-string v0, "Not updating daily counts, app is not known. appId"

    .line 78
    .line 79
    invoke-static/range {p3 .. p3}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    invoke-virtual {p0, v4, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    goto/16 :goto_1

    .line 87
    .line 88
    :catchall_0
    move-exception v0

    .line 89
    move-object p0, v0

    .line 90
    goto/16 :goto_2

    .line 91
    .line 92
    :catch_0
    move-exception v0

    .line 93
    move-object p0, v0

    .line 94
    goto/16 :goto_0

    .line 95
    .line 96
    :cond_0
    const/4 p0, 0x0

    .line 97
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getLong(I)J

    .line 98
    .line 99
    .line 100
    move-result-wide v5

    .line 101
    cmp-long p0, v5, p1

    .line 102
    .line 103
    if-nez p0, :cond_1

    .line 104
    .line 105
    const/4 p0, 0x1

    .line 106
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getLong(I)J

    .line 107
    .line 108
    .line 109
    move-result-wide v5

    .line 110
    iput-wide v5, v2, Lvp/k;->b:J

    .line 111
    .line 112
    const/4 p0, 0x2

    .line 113
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getLong(I)J

    .line 114
    .line 115
    .line 116
    move-result-wide v5

    .line 117
    iput-wide v5, v2, Lvp/k;->a:J

    .line 118
    .line 119
    const/4 p0, 0x3

    .line 120
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getLong(I)J

    .line 121
    .line 122
    .line 123
    move-result-wide v5

    .line 124
    iput-wide v5, v2, Lvp/k;->c:J

    .line 125
    .line 126
    const/4 p0, 0x4

    .line 127
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getLong(I)J

    .line 128
    .line 129
    .line 130
    move-result-wide v5

    .line 131
    iput-wide v5, v2, Lvp/k;->d:J

    .line 132
    .line 133
    const/4 p0, 0x5

    .line 134
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getLong(I)J

    .line 135
    .line 136
    .line 137
    move-result-wide v5

    .line 138
    iput-wide v5, v2, Lvp/k;->e:J

    .line 139
    .line 140
    const/4 p0, 0x6

    .line 141
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getLong(I)J

    .line 142
    .line 143
    .line 144
    move-result-wide v5

    .line 145
    iput-wide v5, v2, Lvp/k;->f:J

    .line 146
    .line 147
    const/4 p0, 0x7

    .line 148
    invoke-interface {v3, p0}, Landroid/database/Cursor;->getLong(I)J

    .line 149
    .line 150
    .line 151
    move-result-wide v5

    .line 152
    iput-wide v5, v2, Lvp/k;->g:J

    .line 153
    .line 154
    :cond_1
    if-eqz p6, :cond_2

    .line 155
    .line 156
    iget-wide v5, v2, Lvp/k;->b:J

    .line 157
    .line 158
    add-long v5, v5, p4

    .line 159
    .line 160
    iput-wide v5, v2, Lvp/k;->b:J

    .line 161
    .line 162
    :cond_2
    if-eqz p7, :cond_3

    .line 163
    .line 164
    iget-wide v5, v2, Lvp/k;->a:J

    .line 165
    .line 166
    add-long v5, v5, p4

    .line 167
    .line 168
    iput-wide v5, v2, Lvp/k;->a:J

    .line 169
    .line 170
    :cond_3
    if-eqz p8, :cond_4

    .line 171
    .line 172
    iget-wide v5, v2, Lvp/k;->c:J

    .line 173
    .line 174
    add-long v5, v5, p4

    .line 175
    .line 176
    iput-wide v5, v2, Lvp/k;->c:J

    .line 177
    .line 178
    :cond_4
    if-eqz p9, :cond_5

    .line 179
    .line 180
    iget-wide v5, v2, Lvp/k;->d:J

    .line 181
    .line 182
    add-long v5, v5, p4

    .line 183
    .line 184
    iput-wide v5, v2, Lvp/k;->d:J

    .line 185
    .line 186
    :cond_5
    if-eqz p10, :cond_6

    .line 187
    .line 188
    iget-wide v5, v2, Lvp/k;->e:J

    .line 189
    .line 190
    add-long v5, v5, p4

    .line 191
    .line 192
    iput-wide v5, v2, Lvp/k;->e:J

    .line 193
    .line 194
    :cond_6
    if-eqz p11, :cond_7

    .line 195
    .line 196
    iget-wide v5, v2, Lvp/k;->f:J

    .line 197
    .line 198
    add-long v5, v5, p4

    .line 199
    .line 200
    iput-wide v5, v2, Lvp/k;->f:J

    .line 201
    .line 202
    :cond_7
    if-eqz p12, :cond_8

    .line 203
    .line 204
    iget-wide v5, v2, Lvp/k;->g:J

    .line 205
    .line 206
    add-long v5, v5, p4

    .line 207
    .line 208
    iput-wide v5, v2, Lvp/k;->g:J

    .line 209
    .line 210
    :cond_8
    new-instance p0, Landroid/content/ContentValues;

    .line 211
    .line 212
    invoke-direct {p0}, Landroid/content/ContentValues;-><init>()V

    .line 213
    .line 214
    .line 215
    const-string v5, "day"

    .line 216
    .line 217
    invoke-static/range {p1 .. p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 218
    .line 219
    .line 220
    move-result-object v6

    .line 221
    invoke-virtual {p0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 222
    .line 223
    .line 224
    const-string v5, "daily_public_events_count"

    .line 225
    .line 226
    iget-wide v6, v2, Lvp/k;->a:J

    .line 227
    .line 228
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 229
    .line 230
    .line 231
    move-result-object v6

    .line 232
    invoke-virtual {p0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 233
    .line 234
    .line 235
    const-string v5, "daily_events_count"

    .line 236
    .line 237
    iget-wide v6, v2, Lvp/k;->b:J

    .line 238
    .line 239
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    invoke-virtual {p0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 244
    .line 245
    .line 246
    const-string v5, "daily_conversions_count"

    .line 247
    .line 248
    iget-wide v6, v2, Lvp/k;->c:J

    .line 249
    .line 250
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 251
    .line 252
    .line 253
    move-result-object v6

    .line 254
    invoke-virtual {p0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 255
    .line 256
    .line 257
    const-string v5, "daily_error_events_count"

    .line 258
    .line 259
    iget-wide v6, v2, Lvp/k;->d:J

    .line 260
    .line 261
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 262
    .line 263
    .line 264
    move-result-object v6

    .line 265
    invoke-virtual {p0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 266
    .line 267
    .line 268
    const-string v5, "daily_realtime_events_count"

    .line 269
    .line 270
    iget-wide v6, v2, Lvp/k;->e:J

    .line 271
    .line 272
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 273
    .line 274
    .line 275
    move-result-object v6

    .line 276
    invoke-virtual {p0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 277
    .line 278
    .line 279
    const-string v5, "daily_realtime_dcu_count"

    .line 280
    .line 281
    iget-wide v6, v2, Lvp/k;->f:J

    .line 282
    .line 283
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 284
    .line 285
    .line 286
    move-result-object v6

    .line 287
    invoke-virtual {p0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 288
    .line 289
    .line 290
    const-string v5, "daily_registered_triggers_count"

    .line 291
    .line 292
    iget-wide v6, v2, Lvp/k;->g:J

    .line 293
    .line 294
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 295
    .line 296
    .line 297
    move-result-object v6

    .line 298
    invoke-virtual {p0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 299
    .line 300
    .line 301
    const-string v5, "apps"

    .line 302
    .line 303
    const-string v6, "app_id=?"

    .line 304
    .line 305
    invoke-virtual {v4, v5, p0, v6, v0}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 306
    .line 307
    .line 308
    goto :goto_1

    .line 309
    :goto_0
    :try_start_1
    iget-object v0, v1, Lvp/g1;->i:Lvp/p0;

    .line 310
    .line 311
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 312
    .line 313
    .line 314
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 315
    .line 316
    const-string v1, "Error updating daily counts. appId"

    .line 317
    .line 318
    invoke-static/range {p3 .. p3}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 319
    .line 320
    .line 321
    move-result-object v4

    .line 322
    invoke-virtual {v0, v4, p0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 323
    .line 324
    .line 325
    :goto_1
    if-eqz v3, :cond_9

    .line 326
    .line 327
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 328
    .line 329
    .line 330
    :cond_9
    return-object v2

    .line 331
    :goto_2
    if-eqz v3, :cond_a

    .line 332
    .line 333
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 334
    .line 335
    .line 336
    :cond_a
    throw p0
.end method

.method public final g0(Ljava/lang/String;)Z
    .locals 7

    .line 1
    sget-object v0, Lvp/q2;->f:Lvp/q2;

    .line 2
    .line 3
    filled-new-array {v0}, [Lvp/q2;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 11
    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    aget-object v0, v0, v3

    .line 15
    .line 16
    iget v0, v0, Lvp/q2;->d:I

    .line 17
    .line 18
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    invoke-static {v1}, Lvp/n;->D0(Ljava/util/List;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {p0}, Lvp/n;->C0()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 38
    .line 39
    .line 40
    move-result v5

    .line 41
    new-instance v6, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    add-int/lit8 v4, v4, 0x3d

    .line 44
    .line 45
    add-int/2addr v4, v5

    .line 46
    invoke-direct {v6, v4}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 47
    .line 48
    .line 49
    const-string v4, "SELECT COUNT(1) > 0 FROM upload_queue WHERE app_id=?"

    .line 50
    .line 51
    const-string v5, " AND NOT "

    .line 52
    .line 53
    invoke-static {v6, v4, v0, v5, v1}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    filled-new-array {p1}, [Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-virtual {p0, v0, p1}, Lvp/n;->K0(Ljava/lang/String;[Ljava/lang/String;)J

    .line 62
    .line 63
    .line 64
    move-result-wide p0

    .line 65
    const-wide/16 v0, 0x0

    .line 66
    .line 67
    cmp-long p0, p0, v0

    .line 68
    .line 69
    if-eqz p0, :cond_0

    .line 70
    .line 71
    return v2

    .line 72
    :cond_0
    return v3
.end method

.method public final g1(Ljava/lang/String;)Lrn/i;
    .locals 11

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lvp/g1;

    .line 5
    .line 6
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 13
    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    const-string v4, "apps"

    .line 21
    .line 22
    const-string p0, "remote_config"

    .line 23
    .line 24
    const-string v0, "config_last_modified_time"

    .line 25
    .line 26
    const-string v5, "e_tag"

    .line 27
    .line 28
    filled-new-array {p0, v0, v5}, [Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    const-string v6, "app_id=?"

    .line 33
    .line 34
    filled-new-array {p1}, [Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v7

    .line 38
    const/4 v9, 0x0

    .line 39
    const/4 v10, 0x0

    .line 40
    const/4 v8, 0x0

    .line 41
    invoke-virtual/range {v3 .. v10}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 42
    .line 43
    .line 44
    move-result-object p0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 45
    :try_start_1
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-nez v0, :cond_0

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_0
    const/4 v0, 0x0

    .line 53
    invoke-interface {p0, v0}, Landroid/database/Cursor;->getBlob(I)[B

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    const/4 v3, 0x1

    .line 58
    invoke-interface {p0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    const/4 v4, 0x2

    .line 63
    invoke-interface {p0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    if-eqz v5, :cond_1

    .line 72
    .line 73
    iget-object v5, v1, Lvp/g1;->i:Lvp/p0;

    .line 74
    .line 75
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 76
    .line 77
    .line 78
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 79
    .line 80
    const-string v6, "Got multiple records for app config, expected one. appId"

    .line 81
    .line 82
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    invoke-virtual {v5, v7, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :catchall_0
    move-exception v0

    .line 91
    move-object p1, v0

    .line 92
    goto :goto_1

    .line 93
    :catch_0
    move-exception v0

    .line 94
    goto :goto_2

    .line 95
    :cond_1
    :goto_0
    if-nez v0, :cond_2

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_2
    new-instance v5, Lrn/i;

    .line 99
    .line 100
    const/16 v6, 0x10

    .line 101
    .line 102
    invoke-direct {v5, v0, v3, v4, v6}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;I)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 103
    .line 104
    .line 105
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 106
    .line 107
    .line 108
    return-object v5

    .line 109
    :goto_1
    move-object v2, p0

    .line 110
    goto :goto_4

    .line 111
    :catchall_1
    move-exception v0

    .line 112
    move-object p0, v0

    .line 113
    move-object p1, p0

    .line 114
    goto :goto_4

    .line 115
    :catch_1
    move-exception v0

    .line 116
    move-object p0, v0

    .line 117
    move-object p0, v2

    .line 118
    :goto_2
    :try_start_2
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 119
    .line 120
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 121
    .line 122
    .line 123
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 124
    .line 125
    const-string v3, "Error querying remote config. appId"

    .line 126
    .line 127
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    invoke-virtual {v1, p1, v0, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 132
    .line 133
    .line 134
    :goto_3
    if-eqz p0, :cond_3

    .line 135
    .line 136
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 137
    .line 138
    .line 139
    :cond_3
    return-object v2

    .line 140
    :goto_4
    if-eqz v2, :cond_4

    .line 141
    .line 142
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 143
    .line 144
    .line 145
    :cond_4
    throw p1
.end method

.method public final h0(Ljava/lang/Long;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    filled-new-array {p1}, [Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    :try_start_0
    const-string v1, "upload_queue"

    .line 24
    .line 25
    const-string v2, "rowid=?"

    .line 26
    .line 27
    invoke-virtual {p0, v1, v2, p1}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    const/4 p1, 0x1

    .line 32
    if-eq p0, p1, :cond_0

    .line 33
    .line 34
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 35
    .line 36
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 40
    .line 41
    const-string p1, "Deleted fewer rows from upload_queue than expected"

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :catch_0
    move-exception p0

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    return-void

    .line 50
    :goto_0
    iget-object p1, v0, Lvp/g1;->i:Lvp/p0;

    .line 51
    .line 52
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 53
    .line 54
    .line 55
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 56
    .line 57
    const-string v0, "Failed to delete a MeasurementBatch in a upload_queue table"

    .line 58
    .line 59
    invoke-virtual {p1, p0, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method public final h1(Lcom/google/android/gms/internal/measurement/j3;Z)V
    .locals 9

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->b2()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-static {v0}, Lno/c0;->k(Z)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Lvp/n;->k0()V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Lvp/g1;

    .line 27
    .line 28
    iget-object v1, v0, Lvp/g1;->n:Lto/a;

    .line 29
    .line 30
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 36
    .line 37
    .line 38
    move-result-wide v1

    .line 39
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->c2()J

    .line 40
    .line 41
    .line 42
    move-result-wide v3

    .line 43
    sget-object v5, Lvp/z;->R:Lvp/y;

    .line 44
    .line 45
    const/4 v6, 0x0

    .line 46
    invoke-virtual {v5, v6}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    check-cast v7, Ljava/lang/Long;

    .line 51
    .line 52
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 53
    .line 54
    .line 55
    move-result-wide v7

    .line 56
    sub-long v7, v1, v7

    .line 57
    .line 58
    cmp-long v3, v3, v7

    .line 59
    .line 60
    if-ltz v3, :cond_0

    .line 61
    .line 62
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->c2()J

    .line 63
    .line 64
    .line 65
    move-result-wide v3

    .line 66
    invoke-virtual {v5, v6}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    check-cast v5, Ljava/lang/Long;

    .line 71
    .line 72
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 73
    .line 74
    .line 75
    move-result-wide v7

    .line 76
    add-long/2addr v7, v1

    .line 77
    cmp-long v3, v3, v7

    .line 78
    .line 79
    if-lez v3, :cond_1

    .line 80
    .line 81
    :cond_0
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 82
    .line 83
    .line 84
    iget-object v3, v0, Lvp/p0;->m:Lvp/n0;

    .line 85
    .line 86
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->c2()J

    .line 99
    .line 100
    .line 101
    move-result-wide v7

    .line 102
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    const-string v5, "Storing bundle outside of the max uploading time span. appId, now, timestamp"

    .line 107
    .line 108
    invoke-virtual {v3, v5, v4, v1, v2}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_1
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    :try_start_0
    iget-object v2, p0, Lvp/q3;->f:Lvp/z3;

    .line 116
    .line 117
    iget-object v2, v2, Lvp/z3;->j:Lvp/s0;

    .line 118
    .line 119
    invoke-static {v2}, Lvp/z3;->T(Lvp/u3;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v2, v1}, Lvp/s0;->M0([B)[B

    .line 123
    .line 124
    .line 125
    move-result-object v1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 126
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 127
    .line 128
    .line 129
    iget-object v2, v0, Lvp/p0;->r:Lvp/n0;

    .line 130
    .line 131
    array-length v3, v1

    .line 132
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    const-string v4, "Saving bundle, size"

    .line 137
    .line 138
    invoke-virtual {v2, v3, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    new-instance v2, Landroid/content/ContentValues;

    .line 142
    .line 143
    invoke-direct {v2}, Landroid/content/ContentValues;-><init>()V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    const-string v4, "app_id"

    .line 151
    .line 152
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->c2()J

    .line 156
    .line 157
    .line 158
    move-result-wide v3

    .line 159
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 160
    .line 161
    .line 162
    move-result-object v3

    .line 163
    const-string v4, "bundle_end_timestamp"

    .line 164
    .line 165
    invoke-virtual {v2, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 166
    .line 167
    .line 168
    const-string v3, "data"

    .line 169
    .line 170
    invoke-virtual {v2, v3, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 171
    .line 172
    .line 173
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 174
    .line 175
    .line 176
    move-result-object p2

    .line 177
    const-string v1, "has_realtime"

    .line 178
    .line 179
    invoke-virtual {v2, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->p0()Z

    .line 183
    .line 184
    .line 185
    move-result p2

    .line 186
    if-eqz p2, :cond_2

    .line 187
    .line 188
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->q0()I

    .line 189
    .line 190
    .line 191
    move-result p2

    .line 192
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object p2

    .line 196
    const-string v1, "retry_count"

    .line 197
    .line 198
    invoke-virtual {v2, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 199
    .line 200
    .line 201
    :cond_2
    :try_start_1
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    const-string p2, "queue"

    .line 206
    .line 207
    invoke-virtual {p0, p2, v6, v2}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    .line 208
    .line 209
    .line 210
    move-result-wide v1

    .line 211
    const-wide/16 v3, -0x1

    .line 212
    .line 213
    cmp-long p0, v1, v3

    .line 214
    .line 215
    if-nez p0, :cond_3

    .line 216
    .line 217
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 218
    .line 219
    .line 220
    iget-object p0, v0, Lvp/p0;->j:Lvp/n0;

    .line 221
    .line 222
    const-string p2, "Failed to insert bundle (got -1). appId"

    .line 223
    .line 224
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v1

    .line 228
    invoke-static {v1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 229
    .line 230
    .line 231
    move-result-object v1

    .line 232
    invoke-virtual {p0, v1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0

    .line 233
    .line 234
    .line 235
    return-void

    .line 236
    :catch_0
    move-exception p0

    .line 237
    goto :goto_0

    .line 238
    :cond_3
    return-void

    .line 239
    :goto_0
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 240
    .line 241
    .line 242
    iget-object p2, v0, Lvp/p0;->j:Lvp/n0;

    .line 243
    .line 244
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object p1

    .line 248
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 249
    .line 250
    .line 251
    move-result-object p1

    .line 252
    const-string v0, "Error storing bundle. appId"

    .line 253
    .line 254
    invoke-virtual {p2, p1, p0, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    return-void

    .line 258
    :catch_1
    move-exception p0

    .line 259
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 260
    .line 261
    .line 262
    iget-object p2, v0, Lvp/p0;->j:Lvp/n0;

    .line 263
    .line 264
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object p1

    .line 268
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    const-string v0, "Data loss. Failed to serialize bundle. appId"

    .line 273
    .line 274
    invoke-virtual {p2, p1, p0, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    return-void
.end method

.method public final i0()Ljava/lang/String;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :try_start_0
    const-string v2, "select app_id from queue order by has_realtime desc, rowid asc limit 1;"

    .line 7
    .line 8
    invoke-virtual {v0, v2, v1}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 9
    .line 10
    .line 11
    move-result-object v0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 12
    :try_start_1
    invoke-interface {v0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-interface {v0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    goto :goto_0

    .line 29
    :catch_0
    move-exception v2

    .line 30
    goto :goto_1

    .line 31
    :goto_0
    move-object v1, v0

    .line 32
    goto :goto_2

    .line 33
    :catchall_1
    move-exception p0

    .line 34
    goto :goto_2

    .line 35
    :catch_1
    move-exception v0

    .line 36
    move-object v2, v0

    .line 37
    move-object v0, v1

    .line 38
    :goto_1
    :try_start_2
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Lvp/g1;

    .line 41
    .line 42
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 43
    .line 44
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 48
    .line 49
    const-string v3, "Database error getting next bundle app id"

    .line 50
    .line 51
    invoke-virtual {p0, v2, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 52
    .line 53
    .line 54
    :cond_0
    if-eqz v0, :cond_1

    .line 55
    .line 56
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    .line 57
    .line 58
    .line 59
    :cond_1
    return-object v1

    .line 60
    :goto_2
    if-eqz v1, :cond_2

    .line 61
    .line 62
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 63
    .line 64
    .line 65
    :cond_2
    throw p0
.end method

.method public final j0(J)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {p1, p2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    filled-new-array {p1}, [Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    :try_start_0
    const-string p2, "queue"

    .line 20
    .line 21
    const-string v1, "rowid=?"

    .line 22
    .line 23
    invoke-virtual {v0, p2, v1, p1}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    const/4 p2, 0x1

    .line 28
    if-ne p1, p2, :cond_0

    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    new-instance p1, Landroid/database/sqlite/SQLiteException;

    .line 32
    .line 33
    const-string p2, "Deleted fewer rows from queue than expected"

    .line 34
    .line 35
    invoke-direct {p1, p2}, Landroid/database/sqlite/SQLiteException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p1
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    :catch_0
    move-exception p1

    .line 40
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Lvp/g1;

    .line 43
    .line 44
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 45
    .line 46
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 47
    .line 48
    .line 49
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 50
    .line 51
    const-string p2, "Failed to delete a bundle in a queue table"

    .line 52
    .line 53
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p1
.end method

.method public final k0()V
    .locals 10

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/n;->H0()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    goto/16 :goto_0

    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, Lvp/q3;->f:Lvp/z3;

    .line 16
    .line 17
    iget-object v1, v0, Lvp/z3;->l:Lvp/f3;

    .line 18
    .line 19
    iget-object v1, v1, Lvp/f3;->i:La8/s1;

    .line 20
    .line 21
    invoke-virtual {v1}, La8/s1;->g()J

    .line 22
    .line 23
    .line 24
    move-result-wide v1

    .line 25
    iget-object v3, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v3, Lvp/g1;

    .line 28
    .line 29
    iget-object v4, v3, Lvp/g1;->n:Lto/a;

    .line 30
    .line 31
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 35
    .line 36
    .line 37
    move-result-wide v4

    .line 38
    sub-long v1, v4, v1

    .line 39
    .line 40
    invoke-static {v1, v2}, Ljava/lang/Math;->abs(J)J

    .line 41
    .line 42
    .line 43
    move-result-wide v1

    .line 44
    sget-object v6, Lvp/z;->M:Lvp/y;

    .line 45
    .line 46
    const/4 v7, 0x0

    .line 47
    invoke-virtual {v6, v7}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    check-cast v6, Ljava/lang/Long;

    .line 52
    .line 53
    invoke-virtual {v6}, Ljava/lang/Long;->longValue()J

    .line 54
    .line 55
    .line 56
    move-result-wide v8

    .line 57
    cmp-long v1, v1, v8

    .line 58
    .line 59
    if-lez v1, :cond_1

    .line 60
    .line 61
    iget-object v0, v0, Lvp/z3;->l:Lvp/f3;

    .line 62
    .line 63
    iget-object v0, v0, Lvp/f3;->i:La8/s1;

    .line 64
    .line 65
    invoke-virtual {v0, v4, v5}, La8/s1;->h(J)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0}, Lvp/n;->H0()Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-eqz v0, :cond_1

    .line 79
    .line 80
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    iget-object v0, v3, Lvp/g1;->n:Lto/a;

    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 90
    .line 91
    .line 92
    move-result-wide v0

    .line 93
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    sget-object v1, Lvp/z;->R:Lvp/y;

    .line 98
    .line 99
    invoke-virtual {v1, v7}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    check-cast v1, Ljava/lang/Long;

    .line 104
    .line 105
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 106
    .line 107
    .line 108
    move-result-wide v1

    .line 109
    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    const-string v1, "queue"

    .line 118
    .line 119
    const-string v2, "abs(bundle_end_timestamp - ?) > cast(? as integer)"

    .line 120
    .line 121
    invoke-virtual {p0, v1, v2, v0}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    if-lez p0, :cond_1

    .line 126
    .line 127
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 128
    .line 129
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 130
    .line 131
    .line 132
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 133
    .line 134
    const-string v1, "Deleted stale rows. rowsDeleted"

    .line 135
    .line 136
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    invoke-virtual {v0, p0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    :cond_1
    :goto_0
    return-void
.end method

.method public final l0(Ljava/util/ArrayList;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    const-string v1, " AND (retry_count IS NULL OR retry_count < 2147483647)"

    .line 21
    .line 22
    const-string v2, "UPDATE queue SET retry_count = IFNULL(retry_count, 0) + 1 WHERE rowid IN "

    .line 23
    .line 24
    invoke-virtual {p0}, Lvp/n;->H0()Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-nez v3, :cond_0

    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    const-string v3, ","

    .line 32
    .line 33
    invoke-static {v3, p1}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    new-instance v4, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    add-int/lit8 v3, v3, 0x2

    .line 48
    .line 49
    invoke-direct {v4, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 50
    .line 51
    .line 52
    const-string v3, "("

    .line 53
    .line 54
    const-string v5, ")"

    .line 55
    .line 56
    invoke-static {v4, v3, p1, v5}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    new-instance v4, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    add-int/lit8 v3, v3, 0x50

    .line 67
    .line 68
    invoke-direct {v4, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 69
    .line 70
    .line 71
    const-string v3, "SELECT COUNT(1) FROM queue WHERE rowid IN "

    .line 72
    .line 73
    const-string v5, " AND retry_count =  2147483647 LIMIT 1"

    .line 74
    .line 75
    invoke-static {v4, v3, p1, v5}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    const/4 v4, 0x0

    .line 80
    invoke-virtual {p0, v3, v4}, Lvp/n;->K0(Ljava/lang/String;[Ljava/lang/String;)J

    .line 81
    .line 82
    .line 83
    move-result-wide v3

    .line 84
    const-wide/16 v5, 0x0

    .line 85
    .line 86
    cmp-long v3, v3, v5

    .line 87
    .line 88
    if-lez v3, :cond_1

    .line 89
    .line 90
    iget-object v3, v0, Lvp/g1;->i:Lvp/p0;

    .line 91
    .line 92
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 93
    .line 94
    .line 95
    iget-object v3, v3, Lvp/p0;->m:Lvp/n0;

    .line 96
    .line 97
    const-string v4, "The number of upload retries exceeds the limit. Will remain unchanged."

    .line 98
    .line 99
    invoke-virtual {v3, v4}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    :cond_1
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    add-int/lit8 v3, v3, 0x7f

    .line 111
    .line 112
    new-instance v4, Ljava/lang/StringBuilder;

    .line 113
    .line 114
    invoke-direct {v4, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    invoke-virtual {p0, p1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 131
    .line 132
    .line 133
    return-void

    .line 134
    :catch_0
    move-exception p0

    .line 135
    iget-object p1, v0, Lvp/g1;->i:Lvp/p0;

    .line 136
    .line 137
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 138
    .line 139
    .line 140
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 141
    .line 142
    const-string v0, "Error incrementing retry count. error"

    .line 143
    .line 144
    invoke-virtual {p1, p0, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    return-void

    .line 148
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 149
    .line 150
    const-string p1, "Given Integer is zero"

    .line 151
    .line 152
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw p0
.end method

.method public final m0(Ljava/lang/Long;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 9
    .line 10
    .line 11
    const-string v1, " SET retry_count = retry_count + 1, last_upload_timestamp = "

    .line 12
    .line 13
    const-string v2, " AND retry_count < 2147483647"

    .line 14
    .line 15
    const-string v3, " WHERE rowid = "

    .line 16
    .line 17
    const-string v4, "UPDATE upload_queue"

    .line 18
    .line 19
    invoke-virtual {p0}, Lvp/n;->H0()Z

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    if-nez v5, :cond_0

    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    new-instance v6, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    add-int/lit8 v5, v5, 0x56

    .line 37
    .line 38
    invoke-direct {v6, v5}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 39
    .line 40
    .line 41
    const-string v5, "SELECT COUNT(1) FROM upload_queue WHERE rowid = "

    .line 42
    .line 43
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v5, " AND retry_count =  2147483647 LIMIT 1"

    .line 50
    .line 51
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    const/4 v6, 0x0

    .line 59
    invoke-virtual {p0, v5, v6}, Lvp/n;->K0(Ljava/lang/String;[Ljava/lang/String;)J

    .line 60
    .line 61
    .line 62
    move-result-wide v5

    .line 63
    const-wide/16 v7, 0x0

    .line 64
    .line 65
    cmp-long v5, v5, v7

    .line 66
    .line 67
    if-lez v5, :cond_1

    .line 68
    .line 69
    iget-object v5, v0, Lvp/g1;->i:Lvp/p0;

    .line 70
    .line 71
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 72
    .line 73
    .line 74
    iget-object v5, v5, Lvp/p0;->m:Lvp/n0;

    .line 75
    .line 76
    const-string v6, "The number of upload retries exceeds the limit. Will remain unchanged."

    .line 77
    .line 78
    invoke-virtual {v5, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    :cond_1
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    iget-object v5, v0, Lvp/g1;->n:Lto/a;

    .line 86
    .line 87
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 91
    .line 92
    .line 93
    move-result-wide v5

    .line 94
    invoke-static {v5, v6}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v7

    .line 98
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    add-int/lit8 v7, v7, 0x3c

    .line 103
    .line 104
    new-instance v8, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    invoke-direct {v8, v7}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v8, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 120
    .line 121
    .line 122
    move-result v5

    .line 123
    add-int/lit8 v5, v5, 0x22

    .line 124
    .line 125
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 130
    .line 131
    .line 132
    move-result v6

    .line 133
    add-int/2addr v5, v6

    .line 134
    add-int/lit8 v5, v5, 0x1d

    .line 135
    .line 136
    new-instance v6, Ljava/lang/StringBuilder;

    .line 137
    .line 138
    invoke-direct {v6, v5}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    invoke-virtual {p0, p1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 161
    .line 162
    .line 163
    return-void

    .line 164
    :catch_0
    move-exception p0

    .line 165
    iget-object p1, v0, Lvp/g1;->i:Lvp/p0;

    .line 166
    .line 167
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 168
    .line 169
    .line 170
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 171
    .line 172
    const-string v0, "Error incrementing retry count. error"

    .line 173
    .line 174
    invoke-virtual {p1, p0, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    return-void
.end method

.method public final n0(Landroid/database/Cursor;I)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    invoke-interface {p1, p2}, Landroid/database/Cursor;->getType(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_4

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    if-eq v0, v2, :cond_3

    .line 14
    .line 15
    const/4 v2, 0x2

    .line 16
    if-eq v0, v2, :cond_2

    .line 17
    .line 18
    const/4 v2, 0x3

    .line 19
    if-eq v0, v2, :cond_1

    .line 20
    .line 21
    const/4 p1, 0x4

    .line 22
    if-eq v0, p1, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 25
    .line 26
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 30
    .line 31
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    const-string p2, "Loaded invalid unknown value type, ignoring it"

    .line 36
    .line 37
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    return-object v1

    .line 41
    :cond_0
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 42
    .line 43
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 47
    .line 48
    const-string p1, "Loaded invalid blob type value, ignoring it"

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    return-object v1

    .line 54
    :cond_1
    invoke-interface {p1, p2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :cond_2
    invoke-interface {p1, p2}, Landroid/database/Cursor;->getDouble(I)D

    .line 60
    .line 61
    .line 62
    move-result-wide p0

    .line 63
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :cond_3
    invoke-interface {p1, p2}, Landroid/database/Cursor;->getLong(I)J

    .line 69
    .line 70
    .line 71
    move-result-wide p0

    .line 72
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0

    .line 77
    :cond_4
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 78
    .line 79
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 83
    .line 84
    const-string p1, "Loaded invalid null value from database"

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    return-object v1
.end method

.method public final o0(Ljava/lang/String;)J
    .locals 13

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    const-string v1, "select first_open_count from app2 where app_id=?"

    .line 6
    .line 7
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "first_open_count"

    .line 11
    .line 12
    invoke-static {v2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-virtual {v3}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 26
    .line 27
    .line 28
    const-wide/16 v4, 0x0

    .line 29
    .line 30
    :try_start_0
    new-instance v6, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    const/16 v7, 0x30

    .line 33
    .line 34
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    filled-new-array {p1}, [Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    const-wide/16 v7, -0x1

    .line 49
    .line 50
    invoke-virtual {p0, v1, v6, v7, v8}, Lvp/n;->L0(Ljava/lang/String;[Ljava/lang/String;J)J

    .line 51
    .line 52
    .line 53
    move-result-wide v9
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 54
    cmp-long p0, v9, v7

    .line 55
    .line 56
    const-string v1, "app2"

    .line 57
    .line 58
    const-string v6, "app_id"

    .line 59
    .line 60
    if-nez p0, :cond_1

    .line 61
    .line 62
    :try_start_1
    new-instance p0, Landroid/content/ContentValues;

    .line 63
    .line 64
    invoke-direct {p0}, Landroid/content/ContentValues;-><init>()V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, v6, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const/4 v9, 0x0

    .line 71
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 72
    .line 73
    .line 74
    move-result-object v9

    .line 75
    invoke-virtual {p0, v2, v9}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 76
    .line 77
    .line 78
    const-string v10, "previous_install_count"

    .line 79
    .line 80
    invoke-virtual {p0, v10, v9}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 81
    .line 82
    .line 83
    const/4 v9, 0x0

    .line 84
    const/4 v10, 0x5

    .line 85
    invoke-virtual {v3, v1, v9, p0, v10}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 86
    .line 87
    .line 88
    move-result-wide v9

    .line 89
    cmp-long p0, v9, v7

    .line 90
    .line 91
    if-nez p0, :cond_0

    .line 92
    .line 93
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 94
    .line 95
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 99
    .line 100
    const-string v1, "Failed to insert column (got -1). appId"

    .line 101
    .line 102
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 103
    .line 104
    .line 105
    move-result-object v6

    .line 106
    invoke-virtual {p0, v6, v2, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 107
    .line 108
    .line 109
    goto :goto_2

    .line 110
    :catchall_0
    move-exception p0

    .line 111
    goto :goto_3

    .line 112
    :catch_0
    move-exception p0

    .line 113
    goto :goto_1

    .line 114
    :cond_0
    move-wide v9, v4

    .line 115
    :cond_1
    :try_start_2
    new-instance p0, Landroid/content/ContentValues;

    .line 116
    .line 117
    invoke-direct {p0}, Landroid/content/ContentValues;-><init>()V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p0, v6, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    const-wide/16 v11, 0x1

    .line 124
    .line 125
    add-long/2addr v11, v9

    .line 126
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    invoke-virtual {p0, v2, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 131
    .line 132
    .line 133
    const-string v6, "app_id = ?"

    .line 134
    .line 135
    filled-new-array {p1}, [Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v11

    .line 139
    invoke-virtual {v3, v1, p0, v6, v11}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    .line 140
    .line 141
    .line 142
    move-result p0

    .line 143
    int-to-long v11, p0

    .line 144
    cmp-long p0, v11, v4

    .line 145
    .line 146
    if-nez p0, :cond_2

    .line 147
    .line 148
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 149
    .line 150
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 151
    .line 152
    .line 153
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 154
    .line 155
    const-string v1, "Failed to update column (got 0). appId"

    .line 156
    .line 157
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    invoke-virtual {p0, v4, v2, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    goto :goto_2

    .line 165
    :catch_1
    move-exception p0

    .line 166
    goto :goto_0

    .line 167
    :cond_2
    invoke-virtual {v3}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 168
    .line 169
    .line 170
    move-wide v7, v9

    .line 171
    goto :goto_2

    .line 172
    :goto_0
    move-wide v4, v9

    .line 173
    :goto_1
    :try_start_3
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 174
    .line 175
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 176
    .line 177
    .line 178
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 179
    .line 180
    const-string v1, "Error inserting column. appId"

    .line 181
    .line 182
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    invoke-virtual {v0, v1, p1, v2, p0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 187
    .line 188
    .line 189
    move-wide v7, v4

    .line 190
    :goto_2
    invoke-virtual {v3}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 191
    .line 192
    .line 193
    return-wide v7

    .line 194
    :goto_3
    invoke-virtual {v3}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 195
    .line 196
    .line 197
    throw p0
.end method

.method public final p0(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 2

    .line 1
    filled-new-array {p1, p2}, [Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const-string p2, "select count(1) from raw_events where app_id = ? and name = ?"

    .line 6
    .line 7
    invoke-virtual {p0, p2, p1}, Lvp/n;->K0(Ljava/lang/String;[Ljava/lang/String;)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    cmp-long p0, p0, v0

    .line 14
    .line 15
    if-lez p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final q0(Ljava/lang/String;)J
    .locals 3

    .line 1
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    filled-new-array {p1}, [Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    const-string v0, "select count(1) from events where app_id=? and name not like \'!_%\' escape \'!\'"

    .line 9
    .line 10
    const-wide/16 v1, 0x0

    .line 11
    .line 12
    invoke-virtual {p0, v0, p1, v1, v2}, Lvp/n;->L0(Ljava/lang/String;[Ljava/lang/String;J)J

    .line 13
    .line 14
    .line 15
    move-result-wide p0

    .line 16
    return-wide p0
.end method

.method public final r0(Ljava/lang/String;Ljava/lang/Long;JLcom/google/android/gms/internal/measurement/b3;)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 5
    .line 6
    .line 7
    invoke-static {p5}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lvp/g1;

    .line 16
    .line 17
    invoke-virtual {p5}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 18
    .line 19
    .line 20
    move-result-object p5

    .line 21
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 22
    .line 23
    iget-object v2, v0, Lvp/g1;->i:Lvp/p0;

    .line 24
    .line 25
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 29
    .line 30
    iget-object v0, v0, Lvp/g1;->m:Lvp/k0;

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    array-length v3, p5

    .line 37
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    const-string v4, "Saving complex main event, appId, data size"

    .line 42
    .line 43
    invoke-virtual {v1, v0, v3, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    new-instance v0, Landroid/content/ContentValues;

    .line 47
    .line 48
    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 49
    .line 50
    .line 51
    const-string v1, "app_id"

    .line 52
    .line 53
    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const-string v1, "event_id"

    .line 57
    .line 58
    invoke-virtual {v0, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 59
    .line 60
    .line 61
    const-string p2, "children_to_process"

    .line 62
    .line 63
    invoke-static {p3, p4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 64
    .line 65
    .line 66
    move-result-object p3

    .line 67
    invoke-virtual {v0, p2, p3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 68
    .line 69
    .line 70
    const-string p2, "main_event"

    .line 71
    .line 72
    invoke-virtual {v0, p2, p5}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 73
    .line 74
    .line 75
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    const-string p2, "main_event_params"

    .line 80
    .line 81
    const/4 p3, 0x0

    .line 82
    const/4 p4, 0x5

    .line 83
    invoke-virtual {p0, p2, p3, v0, p4}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 84
    .line 85
    .line 86
    move-result-wide p2

    .line 87
    const-wide/16 p4, -0x1

    .line 88
    .line 89
    cmp-long p0, p2, p4

    .line 90
    .line 91
    if-nez p0, :cond_0

    .line 92
    .line 93
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 94
    .line 95
    .line 96
    iget-object p0, v2, Lvp/p0;->j:Lvp/n0;

    .line 97
    .line 98
    const-string p2, "Failed to insert complex main event (got -1). appId"

    .line 99
    .line 100
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 101
    .line 102
    .line 103
    move-result-object p3

    .line 104
    invoke-virtual {p0, p3, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 105
    .line 106
    .line 107
    return-void

    .line 108
    :catch_0
    move-exception p0

    .line 109
    goto :goto_0

    .line 110
    :cond_0
    return-void

    .line 111
    :goto_0
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 112
    .line 113
    .line 114
    iget-object p2, v2, Lvp/p0;->j:Lvp/n0;

    .line 115
    .line 116
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    const-string p3, "Error storing complex main event. appId"

    .line 121
    .line 122
    invoke-virtual {p2, p1, p0, p3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    return-void
.end method

.method public final s0(Ljava/lang/String;Ljava/lang/Long;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 25

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v5, p1

    .line 4
    .line 5
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v12, v0

    .line 8
    check-cast v12, Lvp/g1;

    .line 9
    .line 10
    invoke-static/range {p4 .. p4}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v1}, Lvp/u3;->b0()V

    .line 17
    .line 18
    .line 19
    if-eqz p2, :cond_0

    .line 20
    .line 21
    new-instance v0, Lh6/j;

    .line 22
    .line 23
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Long;->longValue()J

    .line 24
    .line 25
    .line 26
    move-result-wide v2

    .line 27
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v1, v0, Lh6/j;->e:Ljava/lang/Object;

    .line 31
    .line 32
    invoke-static {v5}, Lno/c0;->e(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iput-object v5, v0, Lh6/j;->f:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-static {v2, v3}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    filled-new-array {v5, v2}, [Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    const-string v3, "select rowid from raw_events where app_id = ? and timestamp < ? order by rowid desc limit 1"

    .line 46
    .line 47
    const-wide/16 v6, -0x1

    .line 48
    .line 49
    invoke-virtual {v1, v3, v2, v6, v7}, Lvp/n;->L0(Ljava/lang/String;[Ljava/lang/String;J)J

    .line 50
    .line 51
    .line 52
    move-result-wide v2

    .line 53
    iput-wide v2, v0, Lh6/j;->d:J

    .line 54
    .line 55
    :goto_0
    move-object v13, v0

    .line 56
    goto :goto_1

    .line 57
    :cond_0
    new-instance v0, Lh6/j;

    .line 58
    .line 59
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    iput-object v1, v0, Lh6/j;->e:Ljava/lang/Object;

    .line 63
    .line 64
    invoke-static {v5}, Lno/c0;->e(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    iput-object v5, v0, Lh6/j;->f:Ljava/lang/Object;

    .line 68
    .line 69
    const-wide/16 v2, -0x1

    .line 70
    .line 71
    iput-wide v2, v0, Lh6/j;->d:J

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :goto_1
    invoke-virtual {v13}, Lh6/j;->j()Ljava/util/List;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    :goto_2
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-nez v2, :cond_13

    .line 83
    .line 84
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 85
    .line 86
    .line 87
    move-result-object v14

    .line 88
    :goto_3
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_12

    .line 93
    .line 94
    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    move-object v15, v0

    .line 99
    check-cast v15, Lvp/l;

    .line 100
    .line 101
    invoke-static/range {p3 .. p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    if-nez v0, :cond_5

    .line 106
    .line 107
    iget-wide v2, v15, Lvp/l;->b:J

    .line 108
    .line 109
    const/4 v4, 0x0

    .line 110
    :try_start_0
    invoke-virtual {v1}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 111
    .line 112
    .line 113
    move-result-object v16

    .line 114
    const-string v17, "raw_events_metadata"

    .line 115
    .line 116
    const-string v0, "metadata"

    .line 117
    .line 118
    filled-new-array {v0}, [Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v18

    .line 122
    const-string v19, "app_id = ? and metadata_fingerprint = ?"

    .line 123
    .line 124
    invoke-static {v2, v3}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    filled-new-array {v5, v0}, [Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v20

    .line 132
    const-string v23, "rowid"

    .line 133
    .line 134
    const-string v24, "2"

    .line 135
    .line 136
    const/16 v21, 0x0

    .line 137
    .line 138
    const/16 v22, 0x0

    .line 139
    .line 140
    invoke-virtual/range {v16 .. v24}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 141
    .line 142
    .line 143
    move-result-object v2
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_3
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 144
    :try_start_1
    invoke-interface {v2}, Landroid/database/Cursor;->moveToFirst()Z

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    if-nez v0, :cond_1

    .line 149
    .line 150
    iget-object v0, v12, Lvp/g1;->i:Lvp/p0;

    .line 151
    .line 152
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 153
    .line 154
    .line 155
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 156
    .line 157
    const-string v3, "Raw event metadata record is missing. appId"

    .line 158
    .line 159
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 160
    .line 161
    .line 162
    move-result-object v6

    .line 163
    invoke-virtual {v0, v6, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 164
    .line 165
    .line 166
    :goto_4
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 167
    .line 168
    .line 169
    goto/16 :goto_b

    .line 170
    .line 171
    :catchall_0
    move-exception v0

    .line 172
    goto :goto_8

    .line 173
    :catch_0
    move-exception v0

    .line 174
    goto :goto_9

    .line 175
    :cond_1
    const/4 v0, 0x0

    .line 176
    :try_start_2
    invoke-interface {v2, v0}, Landroid/database/Cursor;->getBlob(I)[B

    .line 177
    .line 178
    .line 179
    move-result-object v0
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 180
    :try_start_3
    invoke-static {}, Lcom/google/android/gms/internal/measurement/j3;->U()Lcom/google/android/gms/internal/measurement/i3;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    invoke-static {v3, v0}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    check-cast v0, Lcom/google/android/gms/internal/measurement/i3;

    .line 189
    .line 190
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    move-object v3, v0

    .line 195
    check-cast v3, Lcom/google/android/gms/internal/measurement/j3;
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 196
    .line 197
    :try_start_4
    invoke-interface {v2}, Landroid/database/Cursor;->moveToNext()Z

    .line 198
    .line 199
    .line 200
    move-result v0

    .line 201
    if-eqz v0, :cond_2

    .line 202
    .line 203
    iget-object v0, v12, Lvp/g1;->i:Lvp/p0;

    .line 204
    .line 205
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 206
    .line 207
    .line 208
    iget-object v0, v0, Lvp/p0;->m:Lvp/n0;

    .line 209
    .line 210
    const-string v4, "Get multiple raw event metadata records, expected one. appId"

    .line 211
    .line 212
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 213
    .line 214
    .line 215
    move-result-object v6

    .line 216
    invoke-virtual {v0, v6, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    goto :goto_5

    .line 220
    :catch_1
    move-exception v0

    .line 221
    goto :goto_7

    .line 222
    :cond_2
    :goto_5
    invoke-interface {v2}, Landroid/database/Cursor;->close()V
    :try_end_4
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 223
    .line 224
    .line 225
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 226
    .line 227
    .line 228
    :cond_3
    :goto_6
    move-object v4, v3

    .line 229
    goto :goto_b

    .line 230
    :goto_7
    move-object v4, v2

    .line 231
    goto :goto_a

    .line 232
    :catch_2
    move-exception v0

    .line 233
    :try_start_5
    iget-object v3, v12, Lvp/g1;->i:Lvp/p0;

    .line 234
    .line 235
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 236
    .line 237
    .line 238
    iget-object v3, v3, Lvp/p0;->j:Lvp/n0;

    .line 239
    .line 240
    const-string v6, "Data loss. Failed to merge raw event metadata. appId"

    .line 241
    .line 242
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 243
    .line 244
    .line 245
    move-result-object v7

    .line 246
    invoke-virtual {v3, v7, v0, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_5
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 247
    .line 248
    .line 249
    goto :goto_4

    .line 250
    :goto_8
    move-object v4, v2

    .line 251
    goto :goto_c

    .line 252
    :goto_9
    move-object v3, v4

    .line 253
    goto :goto_7

    .line 254
    :catchall_1
    move-exception v0

    .line 255
    goto :goto_c

    .line 256
    :catch_3
    move-exception v0

    .line 257
    move-object v3, v4

    .line 258
    :goto_a
    :try_start_6
    iget-object v2, v12, Lvp/g1;->i:Lvp/p0;

    .line 259
    .line 260
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 261
    .line 262
    .line 263
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 264
    .line 265
    const-string v6, "Data loss. Error selecting raw event. appId"

    .line 266
    .line 267
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 268
    .line 269
    .line 270
    move-result-object v7

    .line 271
    invoke-virtual {v2, v7, v0, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 272
    .line 273
    .line 274
    if-eqz v4, :cond_3

    .line 275
    .line 276
    invoke-interface {v4}, Landroid/database/Cursor;->close()V

    .line 277
    .line 278
    .line 279
    goto :goto_6

    .line 280
    :goto_b
    if-eqz v4, :cond_5

    .line 281
    .line 282
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/j3;->U1()Lcom/google/android/gms/internal/measurement/r5;

    .line 283
    .line 284
    .line 285
    move-result-object v0

    .line 286
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    :cond_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 291
    .line 292
    .line 293
    move-result v2

    .line 294
    if-eqz v2, :cond_5

    .line 295
    .line 296
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v2

    .line 300
    check-cast v2, Lcom/google/android/gms/internal/measurement/s3;

    .line 301
    .line 302
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v2

    .line 306
    move-object/from16 v3, p3

    .line 307
    .line 308
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    move-result v2

    .line 312
    if-eqz v2, :cond_4

    .line 313
    .line 314
    goto/16 :goto_3

    .line 315
    .line 316
    :cond_5
    move-object/from16 v3, p3

    .line 317
    .line 318
    goto :goto_d

    .line 319
    :goto_c
    if-eqz v4, :cond_6

    .line 320
    .line 321
    invoke-interface {v4}, Landroid/database/Cursor;->close()V

    .line 322
    .line 323
    .line 324
    :cond_6
    throw v0

    .line 325
    :goto_d
    iget-object v0, v1, Lvp/q3;->f:Lvp/z3;

    .line 326
    .line 327
    iget-object v2, v0, Lvp/z3;->j:Lvp/s0;

    .line 328
    .line 329
    invoke-static {v2}, Lvp/z3;->T(Lvp/u3;)V

    .line 330
    .line 331
    .line 332
    iget-object v4, v15, Lvp/l;->d:Lcom/google/android/gms/internal/measurement/b3;

    .line 333
    .line 334
    new-instance v11, Landroid/os/Bundle;

    .line 335
    .line 336
    invoke-direct {v11}, Landroid/os/Bundle;-><init>()V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/b3;->p()Ljava/util/List;

    .line 340
    .line 341
    .line 342
    move-result-object v6

    .line 343
    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 344
    .line 345
    .line 346
    move-result-object v6

    .line 347
    :goto_e
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 348
    .line 349
    .line 350
    move-result v7

    .line 351
    if-eqz v7, :cond_c

    .line 352
    .line 353
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v7

    .line 357
    check-cast v7, Lcom/google/android/gms/internal/measurement/e3;

    .line 358
    .line 359
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->x()Z

    .line 360
    .line 361
    .line 362
    move-result v8

    .line 363
    if-eqz v8, :cond_7

    .line 364
    .line 365
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v8

    .line 369
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->y()D

    .line 370
    .line 371
    .line 372
    move-result-wide v9

    .line 373
    invoke-virtual {v11, v8, v9, v10}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    .line 374
    .line 375
    .line 376
    goto :goto_e

    .line 377
    :cond_7
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->v()Z

    .line 378
    .line 379
    .line 380
    move-result v8

    .line 381
    if-eqz v8, :cond_8

    .line 382
    .line 383
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v8

    .line 387
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->w()F

    .line 388
    .line 389
    .line 390
    move-result v7

    .line 391
    invoke-virtual {v11, v8, v7}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 392
    .line 393
    .line 394
    goto :goto_e

    .line 395
    :cond_8
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->t()Z

    .line 396
    .line 397
    .line 398
    move-result v8

    .line 399
    if-eqz v8, :cond_9

    .line 400
    .line 401
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object v8

    .line 405
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->u()J

    .line 406
    .line 407
    .line 408
    move-result-wide v9

    .line 409
    invoke-virtual {v11, v8, v9, v10}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 410
    .line 411
    .line 412
    goto :goto_e

    .line 413
    :cond_9
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->r()Z

    .line 414
    .line 415
    .line 416
    move-result v8

    .line 417
    if-eqz v8, :cond_a

    .line 418
    .line 419
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object v8

    .line 423
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->s()Ljava/lang/String;

    .line 424
    .line 425
    .line 426
    move-result-object v7

    .line 427
    invoke-virtual {v11, v8, v7}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 428
    .line 429
    .line 430
    goto :goto_e

    .line 431
    :cond_a
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->z()Ljava/util/List;

    .line 432
    .line 433
    .line 434
    move-result-object v8

    .line 435
    invoke-interface {v8}, Ljava/util/List;->isEmpty()Z

    .line 436
    .line 437
    .line 438
    move-result v8

    .line 439
    if-nez v8, :cond_b

    .line 440
    .line 441
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 442
    .line 443
    .line 444
    move-result-object v8

    .line 445
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/e3;->z()Ljava/util/List;

    .line 446
    .line 447
    .line 448
    move-result-object v7

    .line 449
    check-cast v7, Lcom/google/android/gms/internal/measurement/r5;

    .line 450
    .line 451
    invoke-static {v7}, Lvp/s0;->P0(Lcom/google/android/gms/internal/measurement/r5;)[Landroid/os/Bundle;

    .line 452
    .line 453
    .line 454
    move-result-object v7

    .line 455
    invoke-virtual {v11, v8, v7}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 456
    .line 457
    .line 458
    goto :goto_e

    .line 459
    :cond_b
    iget-object v8, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 460
    .line 461
    check-cast v8, Lvp/g1;

    .line 462
    .line 463
    iget-object v8, v8, Lvp/g1;->i:Lvp/p0;

    .line 464
    .line 465
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 466
    .line 467
    .line 468
    iget-object v8, v8, Lvp/p0;->j:Lvp/n0;

    .line 469
    .line 470
    const-string v9, "Unexpected parameter type for parameter"

    .line 471
    .line 472
    invoke-virtual {v8, v7, v9}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 473
    .line 474
    .line 475
    goto/16 :goto_e

    .line 476
    .line 477
    :cond_c
    const-string v2, "_o"

    .line 478
    .line 479
    invoke-virtual {v11, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 480
    .line 481
    .line 482
    move-result-object v6

    .line 483
    invoke-virtual {v11, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 487
    .line 488
    .line 489
    move-result-object v2

    .line 490
    if-nez v6, :cond_d

    .line 491
    .line 492
    const-string v6, ""

    .line 493
    .line 494
    :cond_d
    iget-object v7, v12, Lvp/g1;->l:Lvp/d4;

    .line 495
    .line 496
    iget-object v8, v12, Lvp/g1;->i:Lvp/p0;

    .line 497
    .line 498
    invoke-static {v7}, Lvp/g1;->g(Lap0/o;)V

    .line 499
    .line 500
    .line 501
    const-string v9, "_cmp"

    .line 502
    .line 503
    invoke-virtual {v2, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 504
    .line 505
    .line 506
    move-result v2

    .line 507
    if-nez v2, :cond_f

    .line 508
    .line 509
    move-object/from16 v2, p4

    .line 510
    .line 511
    move-object v9, v2

    .line 512
    :cond_e
    move-object/from16 v16, v4

    .line 513
    .line 514
    goto :goto_10

    .line 515
    :cond_f
    new-instance v2, Landroid/os/Bundle;

    .line 516
    .line 517
    move-object/from16 v9, p4

    .line 518
    .line 519
    invoke-direct {v2, v9}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 520
    .line 521
    .line 522
    invoke-virtual {v9}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 523
    .line 524
    .line 525
    move-result-object v10

    .line 526
    invoke-interface {v10}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 527
    .line 528
    .line 529
    move-result-object v10

    .line 530
    :goto_f
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 531
    .line 532
    .line 533
    move-result v16

    .line 534
    if-eqz v16, :cond_e

    .line 535
    .line 536
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 537
    .line 538
    .line 539
    move-result-object v16

    .line 540
    move-object/from16 v3, v16

    .line 541
    .line 542
    check-cast v3, Ljava/lang/String;

    .line 543
    .line 544
    move-object/from16 v16, v4

    .line 545
    .line 546
    const-string v4, "gad_"

    .line 547
    .line 548
    invoke-virtual {v3, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 549
    .line 550
    .line 551
    move-result v4

    .line 552
    if-eqz v4, :cond_10

    .line 553
    .line 554
    invoke-virtual {v2, v3}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    :cond_10
    move-object/from16 v3, p3

    .line 558
    .line 559
    move-object/from16 v4, v16

    .line 560
    .line 561
    goto :goto_f

    .line 562
    :goto_10
    invoke-virtual {v7, v11, v2}, Lvp/d4;->l0(Landroid/os/Bundle;Landroid/os/Bundle;)V

    .line 563
    .line 564
    .line 565
    iget-object v2, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 566
    .line 567
    move-object v3, v2

    .line 568
    check-cast v3, Lvp/g1;

    .line 569
    .line 570
    new-instance v2, Lh01/k;

    .line 571
    .line 572
    move-object v4, v6

    .line 573
    invoke-virtual/range {v16 .. v16}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 574
    .line 575
    .line 576
    move-result-object v6

    .line 577
    move-object v10, v8

    .line 578
    invoke-virtual/range {v16 .. v16}, Lcom/google/android/gms/internal/measurement/b3;->u()J

    .line 579
    .line 580
    .line 581
    move-result-wide v7

    .line 582
    invoke-virtual/range {v16 .. v16}, Lcom/google/android/gms/internal/measurement/b3;->w()J

    .line 583
    .line 584
    .line 585
    move-result-wide v16

    .line 586
    move-object/from16 p2, v10

    .line 587
    .line 588
    move-wide/from16 v9, v16

    .line 589
    .line 590
    invoke-direct/range {v2 .. v11}, Lh01/k;-><init>(Lvp/g1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JJLandroid/os/Bundle;)V

    .line 591
    .line 592
    .line 593
    iget-object v3, v2, Lh01/k;->g:Ljava/lang/Object;

    .line 594
    .line 595
    check-cast v3, Ljava/lang/String;

    .line 596
    .line 597
    iget-wide v4, v15, Lvp/l;->a:J

    .line 598
    .line 599
    iget-wide v6, v15, Lvp/l;->b:J

    .line 600
    .line 601
    iget-boolean v8, v15, Lvp/l;->c:Z

    .line 602
    .line 603
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 604
    .line 605
    .line 606
    invoke-virtual {v1}, Lvp/u3;->b0()V

    .line 607
    .line 608
    .line 609
    invoke-static {v3}, Lno/c0;->e(Ljava/lang/String;)V

    .line 610
    .line 611
    .line 612
    iget-object v0, v0, Lvp/z3;->j:Lvp/s0;

    .line 613
    .line 614
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 615
    .line 616
    .line 617
    invoke-virtual {v0, v2}, Lvp/s0;->C0(Lh01/k;)Lcom/google/android/gms/internal/measurement/b3;

    .line 618
    .line 619
    .line 620
    move-result-object v0

    .line 621
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 622
    .line 623
    .line 624
    move-result-object v0

    .line 625
    new-instance v9, Landroid/content/ContentValues;

    .line 626
    .line 627
    invoke-direct {v9}, Landroid/content/ContentValues;-><init>()V

    .line 628
    .line 629
    .line 630
    const-string v10, "app_id"

    .line 631
    .line 632
    invoke-virtual {v9, v10, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 633
    .line 634
    .line 635
    iget-object v10, v2, Lh01/k;->h:Ljava/lang/Object;

    .line 636
    .line 637
    check-cast v10, Ljava/lang/String;

    .line 638
    .line 639
    const-string v11, "name"

    .line 640
    .line 641
    invoke-virtual {v9, v11, v10}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 642
    .line 643
    .line 644
    const-string v10, "timestamp"

    .line 645
    .line 646
    iget-wide v1, v2, Lh01/k;->e:J

    .line 647
    .line 648
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 649
    .line 650
    .line 651
    move-result-object v1

    .line 652
    invoke-virtual {v9, v10, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 653
    .line 654
    .line 655
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 656
    .line 657
    .line 658
    move-result-object v1

    .line 659
    const-string v2, "metadata_fingerprint"

    .line 660
    .line 661
    invoke-virtual {v9, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 662
    .line 663
    .line 664
    const-string v1, "data"

    .line 665
    .line 666
    invoke-virtual {v9, v1, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 667
    .line 668
    .line 669
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 670
    .line 671
    .line 672
    move-result-object v0

    .line 673
    const-string v1, "realtime"

    .line 674
    .line 675
    invoke-virtual {v9, v1, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 676
    .line 677
    .line 678
    :try_start_7
    invoke-virtual/range {p0 .. p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 679
    .line 680
    .line 681
    move-result-object v0

    .line 682
    const-string v1, "raw_events"

    .line 683
    .line 684
    const-string v2, "rowid = ?"

    .line 685
    .line 686
    invoke-static {v4, v5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 687
    .line 688
    .line 689
    move-result-object v4

    .line 690
    filled-new-array {v4}, [Ljava/lang/String;

    .line 691
    .line 692
    .line 693
    move-result-object v4

    .line 694
    invoke-virtual {v0, v1, v9, v2, v4}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    .line 695
    .line 696
    .line 697
    move-result v0

    .line 698
    int-to-long v0, v0

    .line 699
    const-wide/16 v4, 0x1

    .line 700
    .line 701
    cmp-long v2, v0, v4

    .line 702
    .line 703
    if-eqz v2, :cond_11

    .line 704
    .line 705
    invoke-static/range {p2 .. p2}, Lvp/g1;->k(Lvp/n1;)V
    :try_end_7
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_7 .. :try_end_7} :catch_5

    .line 706
    .line 707
    .line 708
    move-object/from16 v10, p2

    .line 709
    .line 710
    :try_start_8
    iget-object v2, v10, Lvp/p0;->j:Lvp/n0;

    .line 711
    .line 712
    const-string v4, "Failed to update raw event. appId, updatedRows"

    .line 713
    .line 714
    invoke-static {v3}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 715
    .line 716
    .line 717
    move-result-object v5

    .line 718
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 719
    .line 720
    .line 721
    move-result-object v0

    .line 722
    invoke-virtual {v2, v5, v0, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_8
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_8 .. :try_end_8} :catch_4

    .line 723
    .line 724
    .line 725
    :cond_11
    :goto_11
    move-object/from16 v1, p0

    .line 726
    .line 727
    move-object/from16 v5, p1

    .line 728
    .line 729
    goto/16 :goto_3

    .line 730
    .line 731
    :catch_4
    move-exception v0

    .line 732
    goto :goto_12

    .line 733
    :catch_5
    move-exception v0

    .line 734
    move-object/from16 v10, p2

    .line 735
    .line 736
    :goto_12
    invoke-static {v10}, Lvp/g1;->k(Lvp/n1;)V

    .line 737
    .line 738
    .line 739
    iget-object v1, v10, Lvp/p0;->j:Lvp/n0;

    .line 740
    .line 741
    const-string v2, "Error updating raw event. appId"

    .line 742
    .line 743
    invoke-static {v3}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 744
    .line 745
    .line 746
    move-result-object v3

    .line 747
    invoke-virtual {v1, v3, v0, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 748
    .line 749
    .line 750
    goto :goto_11

    .line 751
    :cond_12
    invoke-virtual {v13}, Lh6/j;->j()Ljava/util/List;

    .line 752
    .line 753
    .line 754
    move-result-object v0

    .line 755
    move-object/from16 v1, p0

    .line 756
    .line 757
    move-object/from16 v5, p1

    .line 758
    .line 759
    goto/16 :goto_2

    .line 760
    .line 761
    :cond_13
    return-void
.end method

.method public final t0(Ljava/lang/String;)Lvp/s1;
    .locals 3

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 12
    .line 13
    .line 14
    filled-new-array {p1}, [Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    const-string v1, "select consent_state, consent_source from consent_settings where app_id=? limit 1;"

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0, v1, p1}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 26
    .line 27
    .line 28
    move-result-object p0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 29
    :try_start_1
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-nez p1, :cond_0

    .line 34
    .line 35
    iget-object p1, v0, Lvp/g1;->i:Lvp/p0;

    .line 36
    .line 37
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 38
    .line 39
    .line 40
    iget-object p1, p1, Lvp/p0;->r:Lvp/n0;

    .line 41
    .line 42
    const-string v1, "No data found"

    .line 43
    .line 44
    invoke-virtual {p1, v1}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 45
    .line 46
    .line 47
    :goto_0
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 48
    .line 49
    .line 50
    goto :goto_3

    .line 51
    :catchall_0
    move-exception p1

    .line 52
    goto :goto_1

    .line 53
    :catch_0
    move-exception p1

    .line 54
    goto :goto_2

    .line 55
    :cond_0
    const/4 p1, 0x0

    .line 56
    :try_start_2
    invoke-interface {p0, p1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    const/4 v1, 0x1

    .line 61
    invoke-interface {p0, v1}, Landroid/database/Cursor;->getInt(I)I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    invoke-static {v1, p1}, Lvp/s1;->c(ILjava/lang/String;)Lvp/s1;

    .line 66
    .line 67
    .line 68
    move-result-object v2
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 69
    goto :goto_0

    .line 70
    :goto_1
    move-object v2, p0

    .line 71
    goto :goto_4

    .line 72
    :catchall_1
    move-exception p0

    .line 73
    move-object p1, p0

    .line 74
    goto :goto_4

    .line 75
    :catch_1
    move-exception p0

    .line 76
    move-object p1, p0

    .line 77
    move-object p0, v2

    .line 78
    :goto_2
    :try_start_3
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 79
    .line 80
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 81
    .line 82
    .line 83
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 84
    .line 85
    const-string v1, "Error querying database."

    .line 86
    .line 87
    invoke-virtual {v0, p1, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 88
    .line 89
    .line 90
    if-eqz p0, :cond_1

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_1
    :goto_3
    if-nez v2, :cond_2

    .line 94
    .line 95
    sget-object p0, Lvp/s1;->c:Lvp/s1;

    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_2
    return-object v2

    .line 99
    :goto_4
    if-eqz v2, :cond_3

    .line 100
    .line 101
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 102
    .line 103
    .line 104
    :cond_3
    throw p1
.end method

.method public final u0(Ljava/lang/String;Lvp/o3;)V
    .locals 9

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 5
    .line 6
    .line 7
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lvp/g1;

    .line 13
    .line 14
    iget-object v1, v0, Lvp/g1;->n:Lto/a;

    .line 15
    .line 16
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 22
    .line 23
    .line 24
    move-result-wide v1

    .line 25
    sget-object v3, Lvp/z;->v0:Lvp/y;

    .line 26
    .line 27
    const/4 v4, 0x0

    .line 28
    invoke-virtual {v3, v4}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    check-cast v5, Ljava/lang/Long;

    .line 33
    .line 34
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 35
    .line 36
    .line 37
    move-result-wide v5

    .line 38
    sub-long v5, v1, v5

    .line 39
    .line 40
    iget-wide v7, p2, Lvp/o3;->e:J

    .line 41
    .line 42
    cmp-long v5, v7, v5

    .line 43
    .line 44
    if-ltz v5, :cond_0

    .line 45
    .line 46
    invoke-virtual {v3, v4}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    check-cast v3, Ljava/lang/Long;

    .line 51
    .line 52
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 53
    .line 54
    .line 55
    move-result-wide v5

    .line 56
    add-long/2addr v5, v1

    .line 57
    cmp-long v3, v7, v5

    .line 58
    .line 59
    if-lez v3, :cond_1

    .line 60
    .line 61
    :cond_0
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 62
    .line 63
    .line 64
    iget-object v3, v0, Lvp/p0;->m:Lvp/n0;

    .line 65
    .line 66
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    const-string v6, "Storing trigger URI outside of the max retention time span. appId, now, timestamp"

    .line 79
    .line 80
    invoke-virtual {v3, v6, v5, v1, v2}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :cond_1
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 84
    .line 85
    .line 86
    iget-object v1, v0, Lvp/p0;->r:Lvp/n0;

    .line 87
    .line 88
    const-string v2, "Saving trigger URI"

    .line 89
    .line 90
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    new-instance v1, Landroid/content/ContentValues;

    .line 94
    .line 95
    invoke-direct {v1}, Landroid/content/ContentValues;-><init>()V

    .line 96
    .line 97
    .line 98
    const-string v2, "app_id"

    .line 99
    .line 100
    invoke-virtual {v1, v2, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iget-object v2, p2, Lvp/o3;->d:Ljava/lang/String;

    .line 104
    .line 105
    const-string v3, "trigger_uri"

    .line 106
    .line 107
    invoke-virtual {v1, v3, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    iget p2, p2, Lvp/o3;->f:I

    .line 111
    .line 112
    const-string v2, "source"

    .line 113
    .line 114
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    invoke-virtual {v1, v2, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 119
    .line 120
    .line 121
    const-string p2, "timestamp_millis"

    .line 122
    .line 123
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 124
    .line 125
    .line 126
    move-result-object v2

    .line 127
    invoke-virtual {v1, p2, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 128
    .line 129
    .line 130
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    const-string p2, "trigger_uris"

    .line 135
    .line 136
    invoke-virtual {p0, p2, v4, v1}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    .line 137
    .line 138
    .line 139
    move-result-wide v1

    .line 140
    const-wide/16 v3, -0x1

    .line 141
    .line 142
    cmp-long p0, v1, v3

    .line 143
    .line 144
    if-nez p0, :cond_2

    .line 145
    .line 146
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 147
    .line 148
    .line 149
    iget-object p0, v0, Lvp/p0;->j:Lvp/n0;

    .line 150
    .line 151
    const-string p2, "Failed to insert trigger URI (got -1). appId"

    .line 152
    .line 153
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    invoke-virtual {p0, v1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 158
    .line 159
    .line 160
    return-void

    .line 161
    :catch_0
    move-exception p0

    .line 162
    goto :goto_0

    .line 163
    :cond_2
    return-void

    .line 164
    :goto_0
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 165
    .line 166
    .line 167
    iget-object p2, v0, Lvp/p0;->j:Lvp/n0;

    .line 168
    .line 169
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    const-string v0, "Error storing trigger URI. appId"

    .line 174
    .line 175
    invoke-virtual {p2, p1, p0, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    return-void
.end method

.method public final v0(Ljava/lang/String;Lvp/s1;)V
    .locals 2

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 11
    .line 12
    .line 13
    new-instance v0, Landroid/content/ContentValues;

    .line 14
    .line 15
    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 16
    .line 17
    .line 18
    const-string v1, "app_id"

    .line 19
    .line 20
    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p1, "consent_state"

    .line 24
    .line 25
    invoke-virtual {p2}, Lvp/s1;->g()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-virtual {v0, p1, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget p1, p2, Lvp/s1;->b:I

    .line 33
    .line 34
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    const-string p2, "consent_source"

    .line 39
    .line 40
    invoke-virtual {v0, p2, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lvp/n;->x0(Landroid/content/ContentValues;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final w0(Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :try_start_0
    invoke-virtual {v0, p1, p2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-interface {v1}, Landroid/database/Cursor;->moveToFirst()Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-interface {v1, p2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 26
    .line 27
    .line 28
    const-string p0, ""

    .line 29
    .line 30
    return-object p0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_0

    .line 33
    :catch_0
    move-exception p2

    .line 34
    :try_start_1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lvp/g1;

    .line 37
    .line 38
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 39
    .line 40
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 41
    .line 42
    .line 43
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 44
    .line 45
    const-string v0, "Database error"

    .line 46
    .line 47
    invoke-virtual {p0, p1, p2, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 51
    :goto_0
    if-eqz v1, :cond_1

    .line 52
    .line 53
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 54
    .line 55
    .line 56
    :cond_1
    throw p0
.end method

.method public final x0(Landroid/content/ContentValues;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    const-string v1, "app_id = ?"

    .line 6
    .line 7
    const-string v2, "app_id"

    .line 8
    .line 9
    const-string v3, "consent_settings"

    .line 10
    .line 11
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p1, v2}, Landroid/content/ContentValues;->getAsString(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    if-nez v4, :cond_0

    .line 20
    .line 21
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 22
    .line 23
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 27
    .line 28
    const-string p1, "Value of the primary key is not set."

    .line 29
    .line 30
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {p0, v1, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :catch_0
    move-exception p0

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-instance v5, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    const/16 v6, 0xa

    .line 43
    .line 44
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    filled-new-array {v4}, [Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    invoke-virtual {p0, v3, p1, v1, v4}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    int-to-long v4, v1

    .line 63
    const-wide/16 v6, 0x0

    .line 64
    .line 65
    cmp-long v1, v4, v6

    .line 66
    .line 67
    if-nez v1, :cond_1

    .line 68
    .line 69
    const/4 v1, 0x0

    .line 70
    const/4 v4, 0x5

    .line 71
    invoke-virtual {p0, v3, v1, p1, v4}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 72
    .line 73
    .line 74
    move-result-wide p0

    .line 75
    const-wide/16 v4, -0x1

    .line 76
    .line 77
    cmp-long p0, p0, v4

    .line 78
    .line 79
    if-nez p0, :cond_1

    .line 80
    .line 81
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 82
    .line 83
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 84
    .line 85
    .line 86
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 87
    .line 88
    const-string p1, "Failed to insert/update table (got -1). key"

    .line 89
    .line 90
    invoke-static {v3}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    invoke-virtual {p0, v1, v4, p1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 99
    .line 100
    .line 101
    :cond_1
    return-void

    .line 102
    :goto_0
    iget-object p1, v0, Lvp/g1;->i:Lvp/p0;

    .line 103
    .line 104
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 105
    .line 106
    .line 107
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 108
    .line 109
    invoke-static {v3}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    const-string v2, "Error storing into table. key"

    .line 118
    .line 119
    invoke-virtual {p1, v2, v0, v1, p0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    return-void
.end method

.method public final y0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lvp/r;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lvp/g1;

    .line 6
    .line 7
    invoke-static/range {p2 .. p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static/range {p3 .. p3}, Lno/c0;->e(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 17
    .line 18
    .line 19
    new-instance v2, Ljava/util/ArrayList;

    .line 20
    .line 21
    const-string v10, "last_exempt_from_sampling"

    .line 22
    .line 23
    const-string v11, "current_session_count"

    .line 24
    .line 25
    const-string v3, "lifetime_count"

    .line 26
    .line 27
    const-string v4, "current_bundle_count"

    .line 28
    .line 29
    const-string v5, "last_fire_timestamp"

    .line 30
    .line 31
    const-string v6, "last_bundled_timestamp"

    .line 32
    .line 33
    const-string v7, "last_bundled_day"

    .line 34
    .line 35
    const-string v8, "last_sampled_complex_event_id"

    .line 36
    .line 37
    const-string v9, "last_sampling_rate"

    .line 38
    .line 39
    filled-new-array/range {v3 .. v11}, [Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-static {v3}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 48
    .line 49
    .line 50
    const/4 v3, 0x0

    .line 51
    :try_start_0
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    const/4 v0, 0x0

    .line 56
    new-array v5, v0, [Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    move-object v6, v2

    .line 63
    check-cast v6, [Ljava/lang/String;

    .line 64
    .line 65
    const-string v7, "app_id=? and name=?"

    .line 66
    .line 67
    filled-new-array/range {p2 .. p3}, [Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v8

    .line 71
    const/4 v10, 0x0

    .line 72
    const/4 v11, 0x0

    .line 73
    const/4 v9, 0x0

    .line 74
    move-object/from16 v5, p1

    .line 75
    .line 76
    invoke-virtual/range {v4 .. v11}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 77
    .line 78
    .line 79
    move-result-object v2
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 80
    :try_start_1
    invoke-interface {v2}, Landroid/database/Cursor;->moveToFirst()Z

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    if-nez v4, :cond_0

    .line 85
    .line 86
    goto/16 :goto_9

    .line 87
    .line 88
    :cond_0
    invoke-interface {v2, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 89
    .line 90
    .line 91
    move-result-wide v8

    .line 92
    const/4 v4, 0x1

    .line 93
    invoke-interface {v2, v4}, Landroid/database/Cursor;->getLong(I)J

    .line 94
    .line 95
    .line 96
    move-result-wide v10

    .line 97
    const/4 v5, 0x2

    .line 98
    invoke-interface {v2, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 99
    .line 100
    .line 101
    move-result-wide v14

    .line 102
    const/4 v5, 0x3

    .line 103
    invoke-interface {v2, v5}, Landroid/database/Cursor;->isNull(I)Z

    .line 104
    .line 105
    .line 106
    move-result v6

    .line 107
    const-wide/16 v12, 0x0

    .line 108
    .line 109
    if-eqz v6, :cond_1

    .line 110
    .line 111
    move-wide/from16 v16, v12

    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_1
    invoke-interface {v2, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 115
    .line 116
    .line 117
    move-result-wide v5

    .line 118
    move-wide/from16 v16, v5

    .line 119
    .line 120
    :goto_0
    const/4 v5, 0x4

    .line 121
    invoke-interface {v2, v5}, Landroid/database/Cursor;->isNull(I)Z

    .line 122
    .line 123
    .line 124
    move-result v6

    .line 125
    if-eqz v6, :cond_2

    .line 126
    .line 127
    move-object/from16 v18, v3

    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_2
    invoke-interface {v2, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 131
    .line 132
    .line 133
    move-result-wide v5

    .line 134
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    move-object/from16 v18, v5

    .line 139
    .line 140
    :goto_1
    const/4 v5, 0x5

    .line 141
    invoke-interface {v2, v5}, Landroid/database/Cursor;->isNull(I)Z

    .line 142
    .line 143
    .line 144
    move-result v6

    .line 145
    if-eqz v6, :cond_3

    .line 146
    .line 147
    move-object/from16 v19, v3

    .line 148
    .line 149
    goto :goto_2

    .line 150
    :cond_3
    invoke-interface {v2, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 151
    .line 152
    .line 153
    move-result-wide v5

    .line 154
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 155
    .line 156
    .line 157
    move-result-object v5

    .line 158
    move-object/from16 v19, v5

    .line 159
    .line 160
    :goto_2
    const/4 v5, 0x6

    .line 161
    invoke-interface {v2, v5}, Landroid/database/Cursor;->isNull(I)Z

    .line 162
    .line 163
    .line 164
    move-result v6

    .line 165
    if-eqz v6, :cond_4

    .line 166
    .line 167
    move-object/from16 v20, v3

    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_4
    invoke-interface {v2, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 171
    .line 172
    .line 173
    move-result-wide v5

    .line 174
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 175
    .line 176
    .line 177
    move-result-object v5

    .line 178
    move-object/from16 v20, v5

    .line 179
    .line 180
    :goto_3
    const/4 v5, 0x7

    .line 181
    invoke-interface {v2, v5}, Landroid/database/Cursor;->isNull(I)Z

    .line 182
    .line 183
    .line 184
    move-result v6

    .line 185
    if-nez v6, :cond_6

    .line 186
    .line 187
    invoke-interface {v2, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 188
    .line 189
    .line 190
    move-result-wide v5

    .line 191
    const-wide/16 v21, 0x1

    .line 192
    .line 193
    cmp-long v5, v5, v21

    .line 194
    .line 195
    if-nez v5, :cond_5

    .line 196
    .line 197
    move v0, v4

    .line 198
    :cond_5
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    move-object/from16 v21, v0

    .line 203
    .line 204
    goto :goto_4

    .line 205
    :catchall_0
    move-exception v0

    .line 206
    goto :goto_7

    .line 207
    :cond_6
    move-object/from16 v21, v3

    .line 208
    .line 209
    :goto_4
    const/16 v0, 0x8

    .line 210
    .line 211
    invoke-interface {v2, v0}, Landroid/database/Cursor;->isNull(I)Z

    .line 212
    .line 213
    .line 214
    move-result v4

    .line 215
    if-eqz v4, :cond_7

    .line 216
    .line 217
    goto :goto_5

    .line 218
    :cond_7
    invoke-interface {v2, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 219
    .line 220
    .line 221
    move-result-wide v12

    .line 222
    :goto_5
    new-instance v5, Lvp/r;

    .line 223
    .line 224
    move-object/from16 v6, p2

    .line 225
    .line 226
    move-object/from16 v7, p3

    .line 227
    .line 228
    invoke-direct/range {v5 .. v21}, Lvp/r;-><init>(Ljava/lang/String;Ljava/lang/String;JJJJJLjava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Boolean;)V

    .line 229
    .line 230
    .line 231
    invoke-interface {v2}, Landroid/database/Cursor;->moveToNext()Z

    .line 232
    .line 233
    .line 234
    move-result v0

    .line 235
    if-eqz v0, :cond_8

    .line 236
    .line 237
    iget-object v0, v1, Lvp/g1;->i:Lvp/p0;

    .line 238
    .line 239
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 240
    .line 241
    .line 242
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 243
    .line 244
    const-string v4, "Got multiple records for event aggregates, expected one. appId"

    .line 245
    .line 246
    invoke-static/range {p2 .. p2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 247
    .line 248
    .line 249
    move-result-object v6

    .line 250
    invoke-virtual {v0, v6, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 251
    .line 252
    .line 253
    goto :goto_6

    .line 254
    :catch_0
    move-exception v0

    .line 255
    goto :goto_8

    .line 256
    :cond_8
    :goto_6
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 257
    .line 258
    .line 259
    return-object v5

    .line 260
    :goto_7
    move-object v3, v2

    .line 261
    goto :goto_a

    .line 262
    :catchall_1
    move-exception v0

    .line 263
    goto :goto_a

    .line 264
    :catch_1
    move-exception v0

    .line 265
    move-object v2, v3

    .line 266
    :goto_8
    :try_start_2
    iget-object v4, v1, Lvp/g1;->i:Lvp/p0;

    .line 267
    .line 268
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 269
    .line 270
    .line 271
    iget-object v4, v4, Lvp/p0;->j:Lvp/n0;

    .line 272
    .line 273
    const-string v5, "Error querying events. appId"

    .line 274
    .line 275
    invoke-static/range {p2 .. p2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 276
    .line 277
    .line 278
    move-result-object v6

    .line 279
    iget-object v1, v1, Lvp/g1;->m:Lvp/k0;

    .line 280
    .line 281
    move-object/from16 v7, p3

    .line 282
    .line 283
    invoke-virtual {v1, v7}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object v1

    .line 287
    invoke-virtual {v4, v5, v6, v1, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 288
    .line 289
    .line 290
    :goto_9
    if-eqz v2, :cond_9

    .line 291
    .line 292
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 293
    .line 294
    .line 295
    :cond_9
    return-object v3

    .line 296
    :goto_a
    if-eqz v3, :cond_a

    .line 297
    .line 298
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 299
    .line 300
    .line 301
    :cond_a
    throw v0
.end method

.method public final z0(Ljava/lang/String;Lvp/r;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 12
    .line 13
    .line 14
    new-instance v1, Landroid/content/ContentValues;

    .line 15
    .line 16
    invoke-direct {v1}, Landroid/content/ContentValues;-><init>()V

    .line 17
    .line 18
    .line 19
    iget-object v2, p2, Lvp/r;->a:Ljava/lang/String;

    .line 20
    .line 21
    const-string v3, "app_id"

    .line 22
    .line 23
    invoke-virtual {v1, v3, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v3, "name"

    .line 27
    .line 28
    iget-object v4, p2, Lvp/r;->b:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v1, v3, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    iget-wide v3, p2, Lvp/r;->c:J

    .line 34
    .line 35
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    const-string v4, "lifetime_count"

    .line 40
    .line 41
    invoke-virtual {v1, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 42
    .line 43
    .line 44
    iget-wide v3, p2, Lvp/r;->d:J

    .line 45
    .line 46
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    const-string v4, "current_bundle_count"

    .line 51
    .line 52
    invoke-virtual {v1, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 53
    .line 54
    .line 55
    iget-wide v3, p2, Lvp/r;->f:J

    .line 56
    .line 57
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    const-string v4, "last_fire_timestamp"

    .line 62
    .line 63
    invoke-virtual {v1, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 64
    .line 65
    .line 66
    iget-wide v3, p2, Lvp/r;->g:J

    .line 67
    .line 68
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    const-string v4, "last_bundled_timestamp"

    .line 73
    .line 74
    invoke-virtual {v1, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 75
    .line 76
    .line 77
    const-string v3, "last_bundled_day"

    .line 78
    .line 79
    iget-object v4, p2, Lvp/r;->h:Ljava/lang/Long;

    .line 80
    .line 81
    invoke-virtual {v1, v3, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 82
    .line 83
    .line 84
    const-string v3, "last_sampled_complex_event_id"

    .line 85
    .line 86
    iget-object v4, p2, Lvp/r;->i:Ljava/lang/Long;

    .line 87
    .line 88
    invoke-virtual {v1, v3, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 89
    .line 90
    .line 91
    const-string v3, "last_sampling_rate"

    .line 92
    .line 93
    iget-object v4, p2, Lvp/r;->j:Ljava/lang/Long;

    .line 94
    .line 95
    invoke-virtual {v1, v3, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 96
    .line 97
    .line 98
    iget-wide v3, p2, Lvp/r;->e:J

    .line 99
    .line 100
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    const-string v4, "current_session_count"

    .line 105
    .line 106
    invoke-virtual {v1, v4, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 107
    .line 108
    .line 109
    iget-object p2, p2, Lvp/r;->k:Ljava/lang/Boolean;

    .line 110
    .line 111
    const/4 v3, 0x0

    .line 112
    if-eqz p2, :cond_0

    .line 113
    .line 114
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    if-eqz p2, :cond_0

    .line 119
    .line 120
    const-wide/16 v4, 0x1

    .line 121
    .line 122
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    goto :goto_0

    .line 127
    :cond_0
    move-object p2, v3

    .line 128
    :goto_0
    const-string v4, "last_exempt_from_sampling"

    .line 129
    .line 130
    invoke-virtual {v1, v4, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 131
    .line 132
    .line 133
    :try_start_0
    invoke-virtual {p0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    const/4 p2, 0x5

    .line 138
    invoke-virtual {p0, p1, v3, v1, p2}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 139
    .line 140
    .line 141
    move-result-wide p0

    .line 142
    const-wide/16 v3, -0x1

    .line 143
    .line 144
    cmp-long p0, p0, v3

    .line 145
    .line 146
    if-nez p0, :cond_1

    .line 147
    .line 148
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 149
    .line 150
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 151
    .line 152
    .line 153
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 154
    .line 155
    const-string p1, "Failed to insert/update event aggregates (got -1). appId"

    .line 156
    .line 157
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 158
    .line 159
    .line 160
    move-result-object p2

    .line 161
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 162
    .line 163
    .line 164
    return-void

    .line 165
    :catch_0
    move-exception p0

    .line 166
    goto :goto_1

    .line 167
    :cond_1
    return-void

    .line 168
    :goto_1
    iget-object p1, v0, Lvp/g1;->i:Lvp/p0;

    .line 169
    .line 170
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 171
    .line 172
    .line 173
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 174
    .line 175
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 176
    .line 177
    .line 178
    move-result-object p2

    .line 179
    const-string v0, "Error storing event aggregates. appId"

    .line 180
    .line 181
    invoke-virtual {p1, p2, p0, v0}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    return-void
.end method

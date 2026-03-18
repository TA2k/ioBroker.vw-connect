.class public abstract Lbq/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc2/k;

.field public static final b:[Ljo/d;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 33

    .line 1
    new-instance v0, Lko/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lbp/l;

    .line 7
    .line 8
    const/4 v2, 0x2

    .line 9
    invoke-direct {v1, v2}, Lbp/l;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Lc2/k;

    .line 13
    .line 14
    const-string v3, "Wearable.API"

    .line 15
    .line 16
    invoke-direct {v2, v3, v1, v0}, Lc2/k;-><init>(Ljava/lang/String;Llp/wd;Lko/d;)V

    .line 17
    .line 18
    .line 19
    sput-object v2, Lbq/g;->a:Lc2/k;

    .line 20
    .line 21
    new-instance v4, Ljo/d;

    .line 22
    .line 23
    const-string v0, "app_client"

    .line 24
    .line 25
    const-wide/16 v1, 0x4

    .line 26
    .line 27
    invoke-direct {v4, v1, v2, v0}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 28
    .line 29
    .line 30
    new-instance v5, Ljo/d;

    .line 31
    .line 32
    const-wide/16 v0, 0x1

    .line 33
    .line 34
    const-string v2, "carrier_auth"

    .line 35
    .line 36
    invoke-direct {v5, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-instance v6, Ljo/d;

    .line 40
    .line 41
    const-string v2, "wear3_oem_companion"

    .line 42
    .line 43
    invoke-direct {v6, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    new-instance v7, Ljo/d;

    .line 47
    .line 48
    const-string v2, "wear_await_data_sync_complete"

    .line 49
    .line 50
    invoke-direct {v7, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 51
    .line 52
    .line 53
    new-instance v8, Ljo/d;

    .line 54
    .line 55
    const-string v2, "wear_backup_restore"

    .line 56
    .line 57
    const-wide/16 v9, 0x6

    .line 58
    .line 59
    invoke-direct {v8, v9, v10, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 60
    .line 61
    .line 62
    new-instance v9, Ljo/d;

    .line 63
    .line 64
    const-wide/16 v2, 0x2

    .line 65
    .line 66
    const-string v10, "wear_consent"

    .line 67
    .line 68
    invoke-direct {v9, v2, v3, v10}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 69
    .line 70
    .line 71
    new-instance v10, Ljo/d;

    .line 72
    .line 73
    const-string v11, "wear_consent_recordoptin"

    .line 74
    .line 75
    invoke-direct {v10, v0, v1, v11}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 76
    .line 77
    .line 78
    new-instance v11, Ljo/d;

    .line 79
    .line 80
    const-string v12, "wear_consent_recordoptin_swaadl"

    .line 81
    .line 82
    invoke-direct {v11, v0, v1, v12}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 83
    .line 84
    .line 85
    new-instance v12, Ljo/d;

    .line 86
    .line 87
    const-string v13, "wear_consent_supervised"

    .line 88
    .line 89
    invoke-direct {v12, v2, v3, v13}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 90
    .line 91
    .line 92
    new-instance v13, Ljo/d;

    .line 93
    .line 94
    const-string v14, "wear_get_phone_switching_feature_status"

    .line 95
    .line 96
    invoke-direct {v13, v0, v1, v14}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 97
    .line 98
    .line 99
    new-instance v14, Ljo/d;

    .line 100
    .line 101
    const-string v15, "wear_fast_pair_account_key_sync"

    .line 102
    .line 103
    invoke-direct {v14, v0, v1, v15}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 104
    .line 105
    .line 106
    new-instance v15, Ljo/d;

    .line 107
    .line 108
    const-string v2, "wear_fast_pair_get_account_keys"

    .line 109
    .line 110
    invoke-direct {v15, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 111
    .line 112
    .line 113
    new-instance v2, Ljo/d;

    .line 114
    .line 115
    const-string v3, "wear_fast_pair_get_account_key_by_account"

    .line 116
    .line 117
    invoke-direct {v2, v0, v1, v3}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 118
    .line 119
    .line 120
    new-instance v3, Ljo/d;

    .line 121
    .line 122
    move-object/from16 v18, v2

    .line 123
    .line 124
    const-string v2, "wear_flush_batched_data"

    .line 125
    .line 126
    invoke-direct {v3, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 127
    .line 128
    .line 129
    new-instance v2, Ljo/d;

    .line 130
    .line 131
    move-object/from16 v19, v3

    .line 132
    .line 133
    const-string v3, "wear_get_related_configs"

    .line 134
    .line 135
    invoke-direct {v2, v0, v1, v3}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 136
    .line 137
    .line 138
    new-instance v3, Ljo/d;

    .line 139
    .line 140
    move-object/from16 v20, v2

    .line 141
    .line 142
    const-string v2, "wear_get_node_id"

    .line 143
    .line 144
    invoke-direct {v3, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 145
    .line 146
    .line 147
    new-instance v2, Ljo/d;

    .line 148
    .line 149
    const-string v0, "wear_logging_service"

    .line 150
    .line 151
    move-object/from16 v23, v3

    .line 152
    .line 153
    move-object v1, v4

    .line 154
    const-wide/16 v3, 0x2

    .line 155
    .line 156
    invoke-direct {v2, v3, v4, v0}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 157
    .line 158
    .line 159
    new-instance v0, Ljo/d;

    .line 160
    .line 161
    const-string v3, "wear_retry_connection"

    .line 162
    .line 163
    move-object/from16 v24, v1

    .line 164
    .line 165
    move-object v4, v2

    .line 166
    const-wide/16 v1, 0x1

    .line 167
    .line 168
    invoke-direct {v0, v1, v2, v3}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 169
    .line 170
    .line 171
    new-instance v3, Ljo/d;

    .line 172
    .line 173
    move-object/from16 v21, v0

    .line 174
    .line 175
    const-string v0, "wear_set_cloud_sync_setting_by_node"

    .line 176
    .line 177
    invoke-direct {v3, v1, v2, v0}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 178
    .line 179
    .line 180
    new-instance v0, Ljo/d;

    .line 181
    .line 182
    const-string v1, "wear_first_party_consents"

    .line 183
    .line 184
    move-object/from16 v22, v3

    .line 185
    .line 186
    const-wide/16 v2, 0x2

    .line 187
    .line 188
    invoke-direct {v0, v2, v3, v1}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 189
    .line 190
    .line 191
    new-instance v1, Ljo/d;

    .line 192
    .line 193
    const-string v2, "wear_update_config"

    .line 194
    .line 195
    move-object/from16 v27, v4

    .line 196
    .line 197
    const-wide/16 v3, 0x1

    .line 198
    .line 199
    invoke-direct {v1, v3, v4, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 200
    .line 201
    .line 202
    new-instance v2, Ljo/d;

    .line 203
    .line 204
    move-object/from16 v25, v0

    .line 205
    .line 206
    const-string v0, "wear_update_connection_retry_strategy"

    .line 207
    .line 208
    invoke-direct {v2, v3, v4, v0}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 209
    .line 210
    .line 211
    new-instance v0, Ljo/d;

    .line 212
    .line 213
    move-object/from16 v26, v1

    .line 214
    .line 215
    const-string v1, "wear_update_delay_config"

    .line 216
    .line 217
    invoke-direct {v0, v3, v4, v1}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 218
    .line 219
    .line 220
    new-instance v1, Ljo/d;

    .line 221
    .line 222
    move-object/from16 v28, v0

    .line 223
    .line 224
    const-string v0, "wearable_services"

    .line 225
    .line 226
    invoke-direct {v1, v3, v4, v0}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 227
    .line 228
    .line 229
    new-instance v0, Ljo/d;

    .line 230
    .line 231
    move-object/from16 v29, v1

    .line 232
    .line 233
    const-string v1, "wear_cancel_migration"

    .line 234
    .line 235
    invoke-direct {v0, v3, v4, v1}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 236
    .line 237
    .line 238
    new-instance v1, Ljo/d;

    .line 239
    .line 240
    const-string v3, "wear_customizable_screens"

    .line 241
    .line 242
    move-object/from16 v32, v5

    .line 243
    .line 244
    const-wide/16 v4, 0x2

    .line 245
    .line 246
    invoke-direct {v1, v4, v5, v3}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 247
    .line 248
    .line 249
    new-instance v3, Ljo/d;

    .line 250
    .line 251
    const-string v4, "wear_wifi_immediate_connect"

    .line 252
    .line 253
    move-object v5, v0

    .line 254
    move-object/from16 v16, v1

    .line 255
    .line 256
    const-wide/16 v0, 0x1

    .line 257
    .line 258
    invoke-direct {v3, v0, v1, v4}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 259
    .line 260
    .line 261
    new-instance v4, Ljo/d;

    .line 262
    .line 263
    move-object/from16 v17, v2

    .line 264
    .line 265
    const-string v2, "wear_get_node_active_network_metered"

    .line 266
    .line 267
    invoke-direct {v4, v0, v1, v2}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 268
    .line 269
    .line 270
    new-instance v0, Ljo/d;

    .line 271
    .line 272
    const-string v1, "wear_consents_per_watch"

    .line 273
    .line 274
    move-object/from16 v30, v3

    .line 275
    .line 276
    const-wide/16 v2, 0x3

    .line 277
    .line 278
    invoke-direct {v0, v2, v3, v1}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 279
    .line 280
    .line 281
    move-object/from16 v31, v29

    .line 282
    .line 283
    move-object/from16 v29, v16

    .line 284
    .line 285
    move-object/from16 v16, v18

    .line 286
    .line 287
    move-object/from16 v18, v20

    .line 288
    .line 289
    move-object/from16 v20, v27

    .line 290
    .line 291
    move-object/from16 v27, v31

    .line 292
    .line 293
    move-object/from16 v31, v25

    .line 294
    .line 295
    move-object/from16 v25, v17

    .line 296
    .line 297
    move-object/from16 v17, v19

    .line 298
    .line 299
    move-object/from16 v19, v23

    .line 300
    .line 301
    move-object/from16 v23, v31

    .line 302
    .line 303
    move-object/from16 v31, v4

    .line 304
    .line 305
    move-object/from16 v4, v24

    .line 306
    .line 307
    move-object/from16 v24, v26

    .line 308
    .line 309
    move-object/from16 v26, v28

    .line 310
    .line 311
    move-object/from16 v28, v5

    .line 312
    .line 313
    move-object/from16 v5, v32

    .line 314
    .line 315
    move-object/from16 v32, v0

    .line 316
    .line 317
    filled-new-array/range {v4 .. v32}, [Ljo/d;

    .line 318
    .line 319
    .line 320
    move-result-object v0

    .line 321
    sput-object v0, Lbq/g;->b:[Ljo/d;

    .line 322
    .line 323
    return-void
.end method

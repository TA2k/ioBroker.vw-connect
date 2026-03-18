.class public final synthetic Lay/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lay/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase_Impl;)V
    .locals 0

    .line 2
    const/4 p1, 0x2

    iput p1, p0, Lay/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 11

    .line 1
    iget p0, p0, Lay/b;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const-string v1, "air_conditioning_gauge_temperature_button_minus"

    .line 5
    .line 6
    const-string v2, "air_conditioning_gauge_temperature_button_plus"

    .line 7
    .line 8
    const-string v3, "air_conditioning_gauge_windows_heating_button_stop"

    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    packed-switch p0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    new-instance p0, Llj0/a;

    .line 15
    .line 16
    invoke-direct {p0, v3}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    new-instance p0, Llj0/a;

    .line 21
    .line 22
    invoke-direct {p0, v2}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_1
    new-instance p0, Llj0/a;

    .line 27
    .line 28
    invoke-direct {p0, v1}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_2
    new-instance p0, Llj0/a;

    .line 33
    .line 34
    const-string v0, "air_conditioning_gauge_windows_heating_button_start"

    .line 35
    .line 36
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_3
    new-instance p0, Llj0/a;

    .line 41
    .line 42
    invoke-direct {p0, v3}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_4
    new-instance p0, Llj0/a;

    .line 47
    .line 48
    invoke-direct {p0, v1}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_5
    new-instance p0, Llj0/a;

    .line 53
    .line 54
    invoke-direct {p0, v2}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_6
    sget-object p0, Lc/j;->a:Ll2/e0;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_7
    sget-object p0, Lc/i;->a:Ll2/e0;

    .line 62
    .line 63
    return-object v0

    .line 64
    :pswitch_8
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-virtual {p0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_9
    new-instance p0, Llj0/a;

    .line 74
    .line 75
    const-string v0, "ai_trip_plan_btn_edit_trip"

    .line 76
    .line 77
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_a
    new-instance p0, Llj0/a;

    .line 82
    .line 83
    const-string v0, "global_button_leave"

    .line 84
    .line 85
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_b
    new-instance p0, Llj0/a;

    .line 90
    .line 91
    const-string v0, "ai_trip_plan_btn_refresh"

    .line 92
    .line 93
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    return-object p0

    .line 97
    :pswitch_c
    new-instance p0, Llj0/a;

    .line 98
    .line 99
    const-string v0, "maps_route_preview_button_show_route"

    .line 100
    .line 101
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    return-object p0

    .line 105
    :pswitch_d
    new-instance p0, Lqz0/d;

    .line 106
    .line 107
    const-class v0, Lqy0/c;

    .line 108
    .line 109
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 110
    .line 111
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    new-array v1, v4, [Ljava/lang/annotation/Annotation;

    .line 116
    .line 117
    invoke-direct {p0, v0, v1}, Lqz0/d;-><init>(Lhy0/d;[Ljava/lang/annotation/Annotation;)V

    .line 118
    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_e
    new-instance p0, Lqz0/d;

    .line 122
    .line 123
    const-class v0, Lqy0/b;

    .line 124
    .line 125
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 126
    .line 127
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    new-array v1, v4, [Ljava/lang/annotation/Annotation;

    .line 132
    .line 133
    invoke-direct {p0, v0, v1}, Lqz0/d;-><init>(Lhy0/d;[Ljava/lang/annotation/Annotation;)V

    .line 134
    .line 135
    .line 136
    return-object p0

    .line 137
    :pswitch_f
    new-instance p0, Lkj0/h;

    .line 138
    .line 139
    const-string v0, "Vehicle - Home - Ordered"

    .line 140
    .line 141
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    return-object p0

    .line 145
    :pswitch_10
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    new-instance v0, Ljava/lang/StringBuilder;

    .line 150
    .line 151
    const-string v1, "LocaleChanged: "

    .line 152
    .line 153
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :pswitch_11
    sget p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->j:I

    .line 165
    .line 166
    const-string p0, "missing triggerTimestamp"

    .line 167
    .line 168
    return-object p0

    .line 169
    :pswitch_12
    new-instance p0, Lbp0/i;

    .line 170
    .line 171
    invoke-direct {p0}, Lbp0/i;-><init>()V

    .line 172
    .line 173
    .line 174
    return-object p0

    .line 175
    :pswitch_13
    sget-object p0, Lzg/f1;->Companion:Lzg/e1;

    .line 176
    .line 177
    invoke-virtual {p0}, Lzg/e1;->serializer()Lqz0/a;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    return-object p0

    .line 182
    :pswitch_14
    new-instance p0, Luz0/d;

    .line 183
    .line 184
    sget-object v0, Lbh/a;->a:Lbh/a;

    .line 185
    .line 186
    invoke-direct {p0, v0, v4}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 187
    .line 188
    .line 189
    return-object p0

    .line 190
    :pswitch_15
    new-instance v5, Lqz0/f;

    .line 191
    .line 192
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 193
    .line 194
    const-class v0, Lbh/k;

    .line 195
    .line 196
    invoke-virtual {p0, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 197
    .line 198
    .line 199
    move-result-object v7

    .line 200
    const-class v0, Lbh/f;

    .line 201
    .line 202
    invoke-virtual {p0, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    const-class v1, Lbh/i;

    .line 207
    .line 208
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    const/4 v1, 0x2

    .line 213
    new-array v8, v1, [Lhy0/d;

    .line 214
    .line 215
    aput-object v0, v8, v4

    .line 216
    .line 217
    const/4 v0, 0x1

    .line 218
    aput-object p0, v8, v0

    .line 219
    .line 220
    new-array v9, v1, [Lqz0/a;

    .line 221
    .line 222
    sget-object p0, Lbh/d;->a:Lbh/d;

    .line 223
    .line 224
    aput-object p0, v9, v4

    .line 225
    .line 226
    sget-object p0, Lbh/g;->a:Lbh/g;

    .line 227
    .line 228
    aput-object p0, v9, v0

    .line 229
    .line 230
    new-array v10, v4, [Ljava/lang/annotation/Annotation;

    .line 231
    .line 232
    const-string v6, "cariad.charging.multicharge.kitten.wallboxes.models.onboarding.ChargingStationSupportedConfigurationComponent"

    .line 233
    .line 234
    invoke-direct/range {v5 .. v10}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;[Ljava/lang/annotation/Annotation;)V

    .line 235
    .line 236
    .line 237
    return-object v5

    .line 238
    :pswitch_16
    new-instance p0, Luz0/d;

    .line 239
    .line 240
    sget-object v0, Lbh/k;->Companion:Lbh/j;

    .line 241
    .line 242
    invoke-virtual {v0}, Lbh/j;->serializer()Lqz0/a;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    invoke-direct {p0, v0, v4}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 247
    .line 248
    .line 249
    return-object p0

    .line 250
    :pswitch_17
    sget-object p0, Lbe0/b;->a:Ll2/e0;

    .line 251
    .line 252
    sget-object p0, Lyy0/h;->d:Lyy0/h;

    .line 253
    .line 254
    return-object p0

    .line 255
    :pswitch_18
    sget-object p0, Lb91/e;->a:[Lhy0/z;

    .line 256
    .line 257
    const-string p0, "CorruptionException in openTelemetry.offlineEventStore, dropping stored spans"

    .line 258
    .line 259
    return-object p0

    .line 260
    :pswitch_19
    sget-object p0, Lb91/c;->a:[Lhy0/z;

    .line 261
    .line 262
    const-string p0, "CorruptionException in openTelemetry.offlineLogRecordStore, dropping stored log records"

    .line 263
    .line 264
    return-object p0

    .line 265
    :pswitch_1a
    new-instance p0, La61/a;

    .line 266
    .line 267
    invoke-direct {p0, v4}, La61/a;-><init>(I)V

    .line 268
    .line 269
    .line 270
    return-object p0

    .line 271
    :pswitch_1b
    sget-object p0, La40/b;->b:La40/b;

    .line 272
    .line 273
    return-object p0

    .line 274
    :pswitch_1c
    invoke-static {}, Lcz/myskoda/api/bff_shop/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 275
    .line 276
    .line 277
    move-result-object p0

    .line 278
    return-object p0

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.class public final synthetic Lua0/a;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Lua0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lua0/a;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;)Lcz/skodaauto/myskoda/feature/widget/model/VehicleStatus;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Lua0/g;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lua0/a;->d:Lua0/a;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    check-cast p1, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;

    .line 2
    .line 3
    const-string p0, "p0"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getVehicle()Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleDto;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 v0, 0x0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleDto;->getName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move-object p0, v0

    .line 21
    :goto_0
    if-nez p0, :cond_1

    .line 22
    .line 23
    const-string p0, ""

    .line 24
    .line 25
    :cond_1
    move-object v2, p0

    .line 26
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getVehicle()Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleDto;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    if-eqz p0, :cond_2

    .line 31
    .line 32
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleDto;->getRenderUrl()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    if-eqz p0, :cond_2

    .line 37
    .line 38
    new-instance v1, Ld01/z;

    .line 39
    .line 40
    const/4 v3, 0x0

    .line 41
    invoke-direct {v1, v3}, Ld01/z;-><init>(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v1, v0, p0}, Ld01/z;->h(Ld01/a0;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1}, Ld01/z;->c()Ld01/a0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-virtual {p0}, Ld01/a0;->k()Ljava/net/URL;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    move-object v3, p0

    .line 56
    goto :goto_1

    .line 57
    :cond_2
    move-object v3, v0

    .line 58
    :goto_1
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getVehicle()Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleDto;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    if-eqz p0, :cond_3

    .line 63
    .line 64
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleDto;->getLicensePlate()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-eqz p0, :cond_3

    .line 69
    .line 70
    move-object v4, p0

    .line 71
    goto :goto_2

    .line 72
    :cond_3
    move-object v4, v0

    .line 73
    :goto_2
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getVehicleStatus()Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleStatusDto;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    if-eqz p0, :cond_4

    .line 78
    .line 79
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleStatusDto;->getDrivingRangeInKm()Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    if-eqz p0, :cond_4

    .line 84
    .line 85
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    int-to-double v5, p0

    .line 90
    const-wide v7, 0x408f400000000000L    # 1000.0

    .line 91
    .line 92
    .line 93
    .line 94
    .line 95
    mul-double/2addr v5, v7

    .line 96
    new-instance p0, Lqr0/d;

    .line 97
    .line 98
    invoke-direct {p0, v5, v6}, Lqr0/d;-><init>(D)V

    .line 99
    .line 100
    .line 101
    move-object v6, p0

    .line 102
    goto :goto_3

    .line 103
    :cond_4
    move-object v6, v0

    .line 104
    :goto_3
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getVehicleStatus()Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleStatusDto;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    if-eqz p0, :cond_8

    .line 109
    .line 110
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetVehicleStatusDto;->getDoorsLocked()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-eqz p0, :cond_5

    .line 115
    .line 116
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 117
    .line 118
    invoke-virtual {p0, v1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    const-string v1, "toUpperCase(...)"

    .line 123
    .line 124
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_5
    move-object p0, v0

    .line 129
    :goto_4
    const-string v1, "CLOSED"

    .line 130
    .line 131
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_6

    .line 136
    .line 137
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 138
    .line 139
    goto :goto_5

    .line 140
    :cond_6
    const-string v1, "OPEN"

    .line 141
    .line 142
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    if-eqz p0, :cond_7

    .line 147
    .line 148
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 149
    .line 150
    goto :goto_5

    .line 151
    :cond_7
    move-object p0, v0

    .line 152
    :goto_5
    move-object v5, p0

    .line 153
    goto :goto_6

    .line 154
    :cond_8
    move-object v5, v0

    .line 155
    :goto_6
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getChargingStatus()Lcz/myskoda/api/bff_widgets/v2/WidgetChargingStatusDto;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-eqz p0, :cond_9

    .line 160
    .line 161
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetChargingStatusDto;->getStateOfChargeInPercent()Ljava/lang/Integer;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    if-eqz p0, :cond_9

    .line 166
    .line 167
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    new-instance v1, Lqr0/l;

    .line 172
    .line 173
    invoke-direct {v1, p0}, Lqr0/l;-><init>(I)V

    .line 174
    .line 175
    .line 176
    move-object v7, v1

    .line 177
    goto :goto_7

    .line 178
    :cond_9
    move-object v7, v0

    .line 179
    :goto_7
    const-string p0, "CONSERVING"

    .line 180
    .line 181
    const-string v1, "CHARGING"

    .line 182
    .line 183
    filled-new-array {p0, v1}, [Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    check-cast p0, Ljava/lang/Iterable;

    .line 192
    .line 193
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getChargingStatus()Lcz/myskoda/api/bff_widgets/v2/WidgetChargingStatusDto;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    if-eqz v1, :cond_a

    .line 198
    .line 199
    invoke-virtual {v1}, Lcz/myskoda/api/bff_widgets/v2/WidgetChargingStatusDto;->getState()Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    goto :goto_8

    .line 204
    :cond_a
    move-object v1, v0

    .line 205
    :goto_8
    invoke-static {p0, v1}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v8

    .line 209
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getChargingStatus()Lcz/myskoda/api/bff_widgets/v2/WidgetChargingStatusDto;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    if-eqz p0, :cond_b

    .line 214
    .line 215
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetChargingStatusDto;->getRemainingTimeToFullyChargedInMinutes()Ljava/lang/Integer;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    if-eqz p0, :cond_b

    .line 220
    .line 221
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 222
    .line 223
    .line 224
    move-result p0

    .line 225
    sget-object v1, Lmy0/e;->i:Lmy0/e;

    .line 226
    .line 227
    invoke-static {p0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 228
    .line 229
    .line 230
    move-result-wide v9

    .line 231
    new-instance p0, Lmy0/c;

    .line 232
    .line 233
    invoke-direct {p0, v9, v10}, Lmy0/c;-><init>(J)V

    .line 234
    .line 235
    .line 236
    move-object v9, p0

    .line 237
    goto :goto_9

    .line 238
    :cond_b
    move-object v9, v0

    .line 239
    :goto_9
    invoke-virtual {p1}, Lcz/myskoda/api/bff_widgets/v2/VehicleStatusWidgetDto;->getParkingPosition()Lcz/myskoda/api/bff_widgets/v2/WidgetParkingPositionDto;

    .line 240
    .line 241
    .line 242
    move-result-object p0

    .line 243
    if-eqz p0, :cond_d

    .line 244
    .line 245
    new-instance p1, Lxa0/c;

    .line 246
    .line 247
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetParkingPositionDto;->getFormattedAddress()Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object v1

    .line 251
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetParkingPositionDto;->getMaps()Lcz/myskoda/api/bff_widgets/v2/WidgetParkingPositionMapsDto;

    .line 252
    .line 253
    .line 254
    move-result-object v10

    .line 255
    if-eqz v10, :cond_c

    .line 256
    .line 257
    invoke-virtual {v10}, Lcz/myskoda/api/bff_widgets/v2/WidgetParkingPositionMapsDto;->getLightMapUrl()Ljava/lang/String;

    .line 258
    .line 259
    .line 260
    move-result-object v10

    .line 261
    if-eqz v10, :cond_c

    .line 262
    .line 263
    new-instance v11, Ld01/z;

    .line 264
    .line 265
    const/4 v12, 0x0

    .line 266
    invoke-direct {v11, v12}, Ld01/z;-><init>(I)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {v11, v0, v10}, Ld01/z;->h(Ld01/a0;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v11}, Ld01/z;->c()Ld01/a0;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    invoke-virtual {v0}, Ld01/a0;->k()Ljava/net/URL;

    .line 277
    .line 278
    .line 279
    move-result-object v0

    .line 280
    :cond_c
    invoke-virtual {p0}, Lcz/myskoda/api/bff_widgets/v2/WidgetParkingPositionDto;->getState()Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object p0

    .line 284
    const-string v10, "IN_MOTION"

    .line 285
    .line 286
    invoke-static {p0, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result p0

    .line 290
    invoke-direct {p1, v1, v0, p0}, Lxa0/c;-><init>(Ljava/lang/String;Ljava/net/URL;Z)V

    .line 291
    .line 292
    .line 293
    move-object v10, p1

    .line 294
    goto :goto_a

    .line 295
    :cond_d
    move-object v10, v0

    .line 296
    :goto_a
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 297
    .line 298
    .line 299
    move-result-object p0

    .line 300
    const/4 p1, 0x0

    .line 301
    invoke-virtual {p0, p1}, Ljava/time/OffsetDateTime;->withSecond(I)Ljava/time/OffsetDateTime;

    .line 302
    .line 303
    .line 304
    move-result-object p0

    .line 305
    invoke-virtual {p0, p1}, Ljava/time/OffsetDateTime;->withNano(I)Ljava/time/OffsetDateTime;

    .line 306
    .line 307
    .line 308
    move-result-object v11

    .line 309
    const-string p0, "withNano(...)"

    .line 310
    .line 311
    invoke-static {v11, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 312
    .line 313
    .line 314
    new-instance v1, Lxa0/a;

    .line 315
    .line 316
    invoke-direct/range {v1 .. v11}, Lxa0/a;-><init>(Ljava/lang/String;Ljava/net/URL;Ljava/lang/String;Ljava/lang/Boolean;Lqr0/d;Lqr0/l;ZLmy0/c;Lxa0/c;Ljava/time/OffsetDateTime;)V

    .line 317
    .line 318
    .line 319
    return-object v1
.end method

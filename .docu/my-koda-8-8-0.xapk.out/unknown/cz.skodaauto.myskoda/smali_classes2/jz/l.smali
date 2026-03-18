.class public final synthetic Ljz/l;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Ljz/l;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Ljz/l;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;)Lcz/skodaauto/myskoda/feature/auxiliaryheating/model/AuxiliaryHeatingStatus;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Ljz/b;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Ljz/l;->d:Ljz/l;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    check-cast p1, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;

    .line 2
    .line 3
    const-string p0, "p0"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getState()Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    sget-object v0, Ljz/a;->a:[I

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    aget p0, v0, p0

    .line 19
    .line 20
    packed-switch p0, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    new-instance p0, La8/r0;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :pswitch_0
    sget-object p0, Lmz/e;->h:Lmz/e;

    .line 30
    .line 31
    :goto_0
    move-object v2, p0

    .line 32
    goto :goto_1

    .line 33
    :pswitch_1
    sget-object p0, Lmz/e;->i:Lmz/e;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :pswitch_2
    sget-object p0, Lmz/e;->g:Lmz/e;

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :pswitch_3
    sget-object p0, Lmz/e;->e:Lmz/e;

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :pswitch_4
    sget-object p0, Lmz/e;->f:Lmz/e;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :pswitch_5
    sget-object p0, Lmz/e;->d:Lmz/e;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :goto_1
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getStartMode()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    const/4 v0, 0x0

    .line 53
    if-eqz p0, :cond_0

    .line 54
    .line 55
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 56
    .line 57
    invoke-virtual {p0, v1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string v1, "toUpperCase(...)"

    .line 62
    .line 63
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_0
    move-object p0, v0

    .line 68
    :goto_2
    if-eqz p0, :cond_7

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    const v3, -0x7cc649eb

    .line 75
    .line 76
    .line 77
    if-eq v1, v3, :cond_5

    .line 78
    .line 79
    const v3, -0x459172c3    # -9.1000256E-4f

    .line 80
    .line 81
    .line 82
    if-eq v1, v3, :cond_3

    .line 83
    .line 84
    const v3, 0x5a3a4fd2

    .line 85
    .line 86
    .line 87
    if-eq v1, v3, :cond_1

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_1
    const-string v1, "HEATING"

    .line 91
    .line 92
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-nez p0, :cond_2

    .line 97
    .line 98
    goto :goto_4

    .line 99
    :cond_2
    sget-object p0, Lmz/d;->d:Lmz/d;

    .line 100
    .line 101
    :goto_3
    move-object v5, p0

    .line 102
    goto :goto_5

    .line 103
    :cond_3
    const-string v1, "VENTILATION"

    .line 104
    .line 105
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    if-nez p0, :cond_4

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_4
    sget-object p0, Lmz/d;->e:Lmz/d;

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_5
    const-string v1, "UNSUPPORTED"

    .line 116
    .line 117
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    if-nez p0, :cond_6

    .line 122
    .line 123
    goto :goto_4

    .line 124
    :cond_6
    sget-object p0, Lmz/d;->g:Lmz/d;

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_7
    :goto_4
    sget-object p0, Lmz/d;->f:Lmz/d;

    .line 128
    .line 129
    goto :goto_3

    .line 130
    :goto_5
    sget p0, Lmy0/c;->g:I

    .line 131
    .line 132
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getDurationInSeconds()I

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 137
    .line 138
    invoke-static {p0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 139
    .line 140
    .line 141
    move-result-wide v3

    .line 142
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getEstimatedDateTimeToReachTargetTemperature()Ljava/time/OffsetDateTime;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getTargetTemperature()Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    if-eqz p0, :cond_b

    .line 151
    .line 152
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;->getUnitInCar()Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 153
    .line 154
    .line 155
    move-result-object v6

    .line 156
    sget-object v7, Ljz/a;->b:[I

    .line 157
    .line 158
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 159
    .line 160
    .line 161
    move-result v6

    .line 162
    aget v6, v7, v6

    .line 163
    .line 164
    const/4 v7, 0x1

    .line 165
    if-eq v6, v7, :cond_a

    .line 166
    .line 167
    const/4 v7, 0x2

    .line 168
    if-eq v6, v7, :cond_9

    .line 169
    .line 170
    const/4 p0, 0x3

    .line 171
    if-ne v6, p0, :cond_8

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_8
    new-instance p0, La8/r0;

    .line 175
    .line 176
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 177
    .line 178
    .line 179
    throw p0

    .line 180
    :cond_9
    new-instance v6, Lqr0/q;

    .line 181
    .line 182
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;->getTemperatureValue()D

    .line 183
    .line 184
    .line 185
    move-result-wide v7

    .line 186
    sget-object p0, Lqr0/r;->e:Lqr0/r;

    .line 187
    .line 188
    invoke-direct {v6, v7, v8, p0}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 189
    .line 190
    .line 191
    goto :goto_7

    .line 192
    :cond_a
    new-instance v6, Lqr0/q;

    .line 193
    .line 194
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;->getTemperatureValue()D

    .line 195
    .line 196
    .line 197
    move-result-wide v7

    .line 198
    sget-object p0, Lqr0/r;->d:Lqr0/r;

    .line 199
    .line 200
    invoke-direct {v6, v7, v8, p0}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 201
    .line 202
    .line 203
    goto :goto_7

    .line 204
    :cond_b
    :goto_6
    move-object v6, v0

    .line 205
    :goto_7
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getErrors()Ljava/util/List;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    if-nez p0, :cond_c

    .line 210
    .line 211
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 212
    .line 213
    :cond_c
    check-cast p0, Ljava/lang/Iterable;

    .line 214
    .line 215
    new-instance v7, Ljava/util/ArrayList;

    .line 216
    .line 217
    const/16 v8, 0xa

    .line 218
    .line 219
    invoke-static {p0, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 220
    .line 221
    .line 222
    move-result v9

    .line 223
    invoke-direct {v7, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 224
    .line 225
    .line 226
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    :goto_8
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 231
    .line 232
    .line 233
    move-result v9

    .line 234
    if-eqz v9, :cond_d

    .line 235
    .line 236
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v9

    .line 240
    check-cast v9, Lcz/myskoda/api/bff_air_conditioning/v2/ErrorDto;

    .line 241
    .line 242
    new-instance v10, Lmz/g;

    .line 243
    .line 244
    invoke-virtual {v9}, Lcz/myskoda/api/bff_air_conditioning/v2/ErrorDto;->getType()Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object v11

    .line 248
    invoke-virtual {v9}, Lcz/myskoda/api/bff_air_conditioning/v2/ErrorDto;->getDescription()Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object v9

    .line 252
    invoke-direct {v10, v11, v9}, Lmz/g;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v7, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    goto :goto_8

    .line 259
    :cond_d
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getTimers()Ljava/util/List;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    check-cast p0, Ljava/lang/Iterable;

    .line 264
    .line 265
    move v9, v8

    .line 266
    new-instance v8, Ljava/util/ArrayList;

    .line 267
    .line 268
    invoke-static {p0, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 269
    .line 270
    .line 271
    move-result v9

    .line 272
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 273
    .line 274
    .line 275
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 276
    .line 277
    .line 278
    move-result-object p0

    .line 279
    :goto_9
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 280
    .line 281
    .line 282
    move-result v9

    .line 283
    if-eqz v9, :cond_e

    .line 284
    .line 285
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v9

    .line 289
    check-cast v9, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;

    .line 290
    .line 291
    invoke-static {v9}, Lwn0/c;->b(Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;)Lao0/c;

    .line 292
    .line 293
    .line 294
    move-result-object v9

    .line 295
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 296
    .line 297
    .line 298
    goto :goto_9

    .line 299
    :cond_e
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getCarCapturedTimestamp()Ljava/time/OffsetDateTime;

    .line 300
    .line 301
    .line 302
    move-result-object v9

    .line 303
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;->getOutsideTemperature()Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;

    .line 304
    .line 305
    .line 306
    move-result-object p0

    .line 307
    if-eqz p0, :cond_f

    .line 308
    .line 309
    invoke-static {p0}, Ljb0/t;->a(Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;)Lmb0/c;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    :cond_f
    move-object v10, v0

    .line 314
    new-instance v0, Lmz/f;

    .line 315
    .line 316
    invoke-direct/range {v0 .. v10}, Lmz/f;-><init>(Ljava/time/OffsetDateTime;Lmz/e;JLmz/d;Lqr0/q;Ljava/util/List;Ljava/util/List;Ljava/time/OffsetDateTime;Lmb0/c;)V

    .line 317
    .line 318
    .line 319
    return-object v0

    .line 320
    nop

    .line 321
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.class public final synthetic Lz81/g;
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
    iput p1, p0, Lz81/g;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 11

    .line 1
    iget p0, p0, Lz81/g;->d:I

    .line 2
    .line 3
    const-string v0, "unknown"

    .line 4
    .line 5
    const-string v1, "notSupported"

    .line 6
    .line 7
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    packed-switch p0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    sget-object p0, Lzl/l;->a:Lzl/l;

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_0
    sget-object p0, Lzl/q;->a:Ll2/u2;

    .line 18
    .line 19
    sget-object p0, Lzl/a;->a:Lzl/a;

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_1
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 23
    .line 24
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_2
    sget p0, Lzj0/j;->b:F

    .line 30
    .line 31
    return-object v2

    .line 32
    :pswitch_3
    new-instance p0, Luz0/d;

    .line 33
    .line 34
    sget-object v0, Lzi/b;->a:Lzi/b;

    .line 35
    .line 36
    invoke-direct {p0, v0, v4}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 37
    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_4
    invoke-static {}, Lzg/w1;->values()[Lzg/w1;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    const-string v2, "solarAndGrid"

    .line 45
    .line 46
    const-string v4, "solarOnly"

    .line 47
    .line 48
    const-string v5, "disabled"

    .line 49
    .line 50
    filled-new-array {v5, v2, v4, v1, v0}, [Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    filled-new-array {v3, v3, v3, v3, v3}, [[Ljava/lang/annotation/Annotation;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.PvSurplusCharging.Mode"

    .line 59
    .line 60
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_5
    invoke-static {}, Lzg/u1;->values()[Lzg/u1;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string v2, "noConnection"

    .line 70
    .line 71
    const-string v4, "ready"

    .line 72
    .line 73
    const-string v5, "notConfigured"

    .line 74
    .line 75
    filled-new-array {v5, v1, v2, v4, v0}, [Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    filled-new-array {v3, v3, v3, v3, v3}, [[Ljava/lang/annotation/Annotation;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.PvSurplusCharging.ModbusState"

    .line 84
    .line 85
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :pswitch_6
    sget-object p0, Lzg/u1;->Companion:Lzg/t1;

    .line 91
    .line 92
    invoke-virtual {p0}, Lzg/t1;->serializer()Lqz0/a;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0

    .line 97
    :pswitch_7
    sget-object p0, Lzg/w1;->Companion:Lzg/v1;

    .line 98
    .line 99
    invoke-virtual {p0}, Lzg/v1;->serializer()Lqz0/a;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0

    .line 104
    :pswitch_8
    invoke-static {}, Lzg/f1;->values()[Lzg/f1;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    const-string v6, "NorthWest"

    .line 109
    .line 110
    const-string v7, "NorthEast"

    .line 111
    .line 112
    const-string v0, "South"

    .line 113
    .line 114
    const-string v1, "SouthWest"

    .line 115
    .line 116
    const-string v2, "SouthEast"

    .line 117
    .line 118
    const-string v3, "West"

    .line 119
    .line 120
    const-string v4, "East"

    .line 121
    .line 122
    const-string v5, "North"

    .line 123
    .line 124
    filled-new-array/range {v0 .. v7}, [Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    const/4 v7, 0x0

    .line 129
    const/4 v8, 0x0

    .line 130
    const/4 v1, 0x0

    .line 131
    const/4 v2, 0x0

    .line 132
    const/4 v3, 0x0

    .line 133
    const/4 v4, 0x0

    .line 134
    const/4 v5, 0x0

    .line 135
    const/4 v6, 0x0

    .line 136
    filled-new-array/range {v1 .. v8}, [[Ljava/lang/annotation/Annotation;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.PVInstallation.Azimuth"

    .line 141
    .line 142
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    return-object p0

    .line 147
    :pswitch_9
    sget-object p0, Lzg/f1;->Companion:Lzg/e1;

    .line 148
    .line 149
    invoke-virtual {p0}, Lzg/e1;->serializer()Lqz0/a;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    return-object p0

    .line 154
    :pswitch_a
    new-instance p0, Luz0/d;

    .line 155
    .line 156
    sget-object v0, Lzg/w0;->Companion:Lzg/p0;

    .line 157
    .line 158
    invoke-virtual {v0}, Lzg/p0;->serializer()Lqz0/a;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    invoke-direct {p0, v0, v4}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 163
    .line 164
    .line 165
    return-object p0

    .line 166
    :pswitch_b
    new-instance v5, Lqz0/f;

    .line 167
    .line 168
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 169
    .line 170
    const-class v0, Lzg/w0;

    .line 171
    .line 172
    invoke-virtual {p0, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 173
    .line 174
    .line 175
    move-result-object v7

    .line 176
    const-class v0, Lzg/o0;

    .line 177
    .line 178
    invoke-virtual {p0, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    const-class v1, Lzg/s0;

    .line 183
    .line 184
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    const-class v2, Lzg/v0;

    .line 189
    .line 190
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    const/4 v2, 0x3

    .line 195
    new-array v8, v2, [Lhy0/d;

    .line 196
    .line 197
    aput-object v0, v8, v4

    .line 198
    .line 199
    const/4 v0, 0x1

    .line 200
    aput-object v1, v8, v0

    .line 201
    .line 202
    const/4 v1, 0x2

    .line 203
    aput-object p0, v8, v1

    .line 204
    .line 205
    new-array v9, v2, [Lqz0/a;

    .line 206
    .line 207
    sget-object p0, Lzg/m0;->a:Lzg/m0;

    .line 208
    .line 209
    aput-object p0, v9, v4

    .line 210
    .line 211
    sget-object p0, Lzg/q0;->a:Lzg/q0;

    .line 212
    .line 213
    aput-object p0, v9, v0

    .line 214
    .line 215
    sget-object p0, Lzg/t0;->a:Lzg/t0;

    .line 216
    .line 217
    aput-object p0, v9, v1

    .line 218
    .line 219
    new-instance p0, Lje/e;

    .line 220
    .line 221
    invoke-direct {p0, v1}, Lje/e;-><init>(I)V

    .line 222
    .line 223
    .line 224
    new-array v10, v0, [Ljava/lang/annotation/Annotation;

    .line 225
    .line 226
    aput-object p0, v10, v4

    .line 227
    .line 228
    const-string v6, "cariad.charging.multicharge.kitten.wallboxes.models.HomeChargingInfrastructure"

    .line 229
    .line 230
    invoke-direct/range {v5 .. v10}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;[Ljava/lang/annotation/Annotation;)V

    .line 231
    .line 232
    .line 233
    return-object v5

    .line 234
    :pswitch_c
    new-instance p0, Luz0/d;

    .line 235
    .line 236
    sget-object v0, Lzg/d;->a:Lzg/d;

    .line 237
    .line 238
    invoke-direct {p0, v0, v4}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 239
    .line 240
    .line 241
    return-object p0

    .line 242
    :pswitch_d
    new-instance p0, Luz0/d;

    .line 243
    .line 244
    sget-object v0, Lzg/l;->a:Lzg/l;

    .line 245
    .line 246
    invoke-direct {p0, v0, v4}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 247
    .line 248
    .line 249
    return-object p0

    .line 250
    :pswitch_e
    invoke-static {}, Lzg/g;->values()[Lzg/g;

    .line 251
    .line 252
    .line 253
    move-result-object p0

    .line 254
    const-string v7, "WAITING_FOR_AUTHORIZATION"

    .line 255
    .line 256
    const-string v8, "WAITING_FOR_CHARGING"

    .line 257
    .line 258
    const-string v0, "AVAILABLE"

    .line 259
    .line 260
    const-string v1, "CHARGING_IN_PROGRESS"

    .line 261
    .line 262
    const-string v2, "CHARGING_NOT_POSSIBLE"

    .line 263
    .line 264
    const-string v3, "CHARGING_PROCESS_FINISHED"

    .line 265
    .line 266
    const-string v4, "PAUSE"

    .line 267
    .line 268
    const-string v5, "READY_FOR_CHARGING"

    .line 269
    .line 270
    const-string v6, "UNKNOWN"

    .line 271
    .line 272
    filled-new-array/range {v0 .. v8}, [Ljava/lang/String;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    const/4 v8, 0x0

    .line 277
    const/4 v9, 0x0

    .line 278
    const/4 v1, 0x0

    .line 279
    const/4 v2, 0x0

    .line 280
    const/4 v3, 0x0

    .line 281
    const/4 v4, 0x0

    .line 282
    const/4 v5, 0x0

    .line 283
    const/4 v6, 0x0

    .line 284
    const/4 v7, 0x0

    .line 285
    filled-new-array/range {v1 .. v9}, [[Ljava/lang/annotation/Annotation;

    .line 286
    .line 287
    .line 288
    move-result-object v1

    .line 289
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.ChargingStation.Status"

    .line 290
    .line 291
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 292
    .line 293
    .line 294
    move-result-object p0

    .line 295
    return-object p0

    .line 296
    :pswitch_f
    sget-object p0, Lzg/g;->Companion:Lzg/f;

    .line 297
    .line 298
    invoke-virtual {p0}, Lzg/f;->serializer()Lqz0/a;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    return-object p0

    .line 303
    :pswitch_10
    new-instance p0, Luz0/d;

    .line 304
    .line 305
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 306
    .line 307
    invoke-direct {p0, v0, v4}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 308
    .line 309
    .line 310
    return-object p0

    .line 311
    :pswitch_11
    const-string p0, ""

    .line 312
    .line 313
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 314
    .line 315
    .line 316
    move-result-object p0

    .line 317
    return-object p0

    .line 318
    :pswitch_12
    sget-object p0, Lzb/o0;->a:Ll2/u2;

    .line 319
    .line 320
    return-object v3

    .line 321
    :pswitch_13
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 322
    .line 323
    const-string v0, "CompositionLocal LocalFullScreenComponentManager not present"

    .line 324
    .line 325
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    throw p0

    .line 329
    :pswitch_14
    new-instance p0, Ld01/h0;

    .line 330
    .line 331
    invoke-direct {p0}, Ld01/h0;-><init>()V

    .line 332
    .line 333
    .line 334
    return-object p0

    .line 335
    :pswitch_15
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 336
    .line 337
    const-string v0, "CompositionLocal LocalIsDarkMode not present"

    .line 338
    .line 339
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    throw p0

    .line 343
    :pswitch_16
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 344
    .line 345
    const-string v0, "CompositionLocal LocalI18nResources not present"

    .line 346
    .line 347
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 348
    .line 349
    .line 350
    throw p0

    .line 351
    :pswitch_17
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 352
    .line 353
    const-string v0, "CompositionLocal LocalBrandUi not present"

    .line 354
    .line 355
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    throw p0

    .line 359
    :pswitch_18
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 360
    .line 361
    const-string v0, "CompositionLocal LocalLokator not present"

    .line 362
    .line 363
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 364
    .line 365
    .line 366
    throw p0

    .line 367
    :pswitch_19
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 368
    .line 369
    const-string v0, "LocalComponentOutsideScreen not added to the composition"

    .line 370
    .line 371
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 372
    .line 373
    .line 374
    throw p0

    .line 375
    :pswitch_1a
    return-object v2

    .line 376
    :pswitch_1b
    sget-object p0, Lz81/h;->a:Lio/opentelemetry/api/common/AttributeKey;

    .line 377
    .line 378
    const-string p0, "Connection mode requires API key, but provided key is blank - will export log records to device log only"

    .line 379
    .line 380
    return-object p0

    .line 381
    :pswitch_1c
    sget-object p0, Lz81/h;->a:Lio/opentelemetry/api/common/AttributeKey;

    .line 382
    .line 383
    const-string p0, "Connection mode requires API key, but provided key is blank - will export spans to device log only"

    .line 384
    .line 385
    return-object p0

    .line 386
    nop

    .line 387
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

.class public final synthetic Ljb0/v;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Ljb0/v;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Ljb0/v;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;)Lcz/skodaauto/myskoda/library/airconditioning/model/AirConditioningStatus;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Ljb0/b;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Ljb0/v;->d:Ljb0/v;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    check-cast v0, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;

    .line 4
    .line 5
    const-string v1, "p0"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getState()Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningStateDto;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    const-string v2, "<this>"

    .line 15
    .line 16
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sget-object v3, Ljb0/a;->a:[I

    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    aget v1, v3, v1

    .line 26
    .line 27
    packed-switch v1, :pswitch_data_0

    .line 28
    .line 29
    .line 30
    new-instance v0, La8/r0;

    .line 31
    .line 32
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw v0

    .line 36
    :pswitch_0
    sget-object v1, Lmb0/e;->k:Lmb0/e;

    .line 37
    .line 38
    :goto_0
    move-object v4, v1

    .line 39
    goto :goto_1

    .line 40
    :pswitch_1
    sget-object v1, Lmb0/e;->j:Lmb0/e;

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_2
    sget-object v1, Lmb0/e;->i:Lmb0/e;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_3
    sget-object v1, Lmb0/e;->h:Lmb0/e;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :pswitch_4
    sget-object v1, Lmb0/e;->g:Lmb0/e;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :pswitch_5
    sget-object v1, Lmb0/e;->f:Lmb0/e;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :pswitch_6
    sget-object v1, Lmb0/e;->e:Lmb0/e;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_7
    sget-object v1, Lmb0/e;->d:Lmb0/e;

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :goto_1
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getWindowHeatingState()Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWindowHeatingStateDto;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    new-instance v5, Lmb0/n;

    .line 66
    .line 67
    if-eqz v1, :cond_0

    .line 68
    .line 69
    invoke-virtual {v1}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWindowHeatingStateDto;->getFront()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    if-eqz v3, :cond_0

    .line 74
    .line 75
    invoke-static {v3}, Ljb0/b;->k(Ljava/lang/String;)Lmb0/o;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    goto :goto_2

    .line 80
    :cond_0
    sget-object v3, Lmb0/o;->g:Lmb0/o;

    .line 81
    .line 82
    :goto_2
    if-eqz v1, :cond_1

    .line 83
    .line 84
    invoke-virtual {v1}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWindowHeatingStateDto;->getRear()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    if-eqz v1, :cond_1

    .line 89
    .line 90
    invoke-static {v1}, Ljb0/b;->k(Ljava/lang/String;)Lmb0/o;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    goto :goto_3

    .line 95
    :cond_1
    sget-object v1, Lmb0/o;->g:Lmb0/o;

    .line 96
    .line 97
    :goto_3
    invoke-direct {v5, v3, v1}, Lmb0/n;-><init>(Lmb0/o;Lmb0/o;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getWindowHeatingEnabled()Ljava/lang/Boolean;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getEstimatedDateTimeToReachTargetTemperature()Ljava/time/OffsetDateTime;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getTargetTemperature()Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    if-eqz v1, :cond_2

    .line 113
    .line 114
    invoke-static {v1}, Ljb0/k;->b(Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;)Lqr0/q;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    move-object v8, v1

    .line 119
    goto :goto_4

    .line 120
    :cond_2
    const/4 v8, 0x0

    .line 121
    :goto_4
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getAirConditioningWithoutExternalPower()Ljava/lang/Boolean;

    .line 122
    .line 123
    .line 124
    move-result-object v9

    .line 125
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getAirConditioningAtUnlock()Ljava/lang/Boolean;

    .line 126
    .line 127
    .line 128
    move-result-object v10

    .line 129
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getSteeringWheelPosition()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    const-string v11, "LEFT"

    .line 134
    .line 135
    invoke-static {v1, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v11

    .line 139
    if-eqz v11, :cond_3

    .line 140
    .line 141
    sget-object v1, Lmb0/m;->d:Lmb0/m;

    .line 142
    .line 143
    :goto_5
    move-object v11, v1

    .line 144
    goto :goto_6

    .line 145
    :cond_3
    const-string v11, "RIGHT"

    .line 146
    .line 147
    invoke-static {v1, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-eqz v1, :cond_4

    .line 152
    .line 153
    sget-object v1, Lmb0/m;->e:Lmb0/m;

    .line 154
    .line 155
    goto :goto_5

    .line 156
    :cond_4
    sget-object v1, Lmb0/m;->f:Lmb0/m;

    .line 157
    .line 158
    goto :goto_5

    .line 159
    :goto_6
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getSeatHeatingActivated()Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;

    .line 160
    .line 161
    .line 162
    move-result-object v1

    .line 163
    new-instance v12, Lmb0/l;

    .line 164
    .line 165
    if-eqz v1, :cond_5

    .line 166
    .line 167
    invoke-virtual {v1}, Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;->getFrontLeft()Ljava/lang/Boolean;

    .line 168
    .line 169
    .line 170
    move-result-object v13

    .line 171
    goto :goto_7

    .line 172
    :cond_5
    const/4 v13, 0x0

    .line 173
    :goto_7
    if-eqz v1, :cond_6

    .line 174
    .line 175
    invoke-virtual {v1}, Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;->getFrontRight()Ljava/lang/Boolean;

    .line 176
    .line 177
    .line 178
    move-result-object v14

    .line 179
    goto :goto_8

    .line 180
    :cond_6
    const/4 v14, 0x0

    .line 181
    :goto_8
    if-eqz v1, :cond_7

    .line 182
    .line 183
    invoke-virtual {v1}, Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;->getRearLeft()Ljava/lang/Boolean;

    .line 184
    .line 185
    .line 186
    move-result-object v15

    .line 187
    goto :goto_9

    .line 188
    :cond_7
    const/4 v15, 0x0

    .line 189
    :goto_9
    if-eqz v1, :cond_8

    .line 190
    .line 191
    invoke-virtual {v1}, Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;->getRearRight()Ljava/lang/Boolean;

    .line 192
    .line 193
    .line 194
    move-result-object v1

    .line 195
    goto :goto_a

    .line 196
    :cond_8
    const/4 v1, 0x0

    .line 197
    :goto_a
    invoke-direct {v12, v13, v14, v15, v1}, Lmb0/l;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getHeaterSource()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v1

    .line 204
    const-string v13, "AUTOMATIC"

    .line 205
    .line 206
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result v13

    .line 210
    if-eqz v13, :cond_9

    .line 211
    .line 212
    sget-object v1, Lmb0/i;->e:Lmb0/i;

    .line 213
    .line 214
    :goto_b
    move-object v13, v1

    .line 215
    goto :goto_c

    .line 216
    :cond_9
    const-string v13, "ELECTRIC"

    .line 217
    .line 218
    invoke-static {v1, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result v1

    .line 222
    if-eqz v1, :cond_a

    .line 223
    .line 224
    sget-object v1, Lmb0/i;->d:Lmb0/i;

    .line 225
    .line 226
    goto :goto_b

    .line 227
    :cond_a
    sget-object v1, Lmb0/i;->f:Lmb0/i;

    .line 228
    .line 229
    goto :goto_b

    .line 230
    :goto_c
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getChargerConnectionState()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    if-eqz v1, :cond_d

    .line 235
    .line 236
    sget-object v14, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 237
    .line 238
    invoke-virtual {v1, v14}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    const-string v14, "toUpperCase(...)"

    .line 243
    .line 244
    invoke-static {v1, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    const-string v14, "CONNECTED"

    .line 248
    .line 249
    invoke-virtual {v1, v14}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 250
    .line 251
    .line 252
    move-result v14

    .line 253
    if-eqz v14, :cond_b

    .line 254
    .line 255
    sget-object v1, Lmb0/g;->d:Lmb0/g;

    .line 256
    .line 257
    goto :goto_d

    .line 258
    :cond_b
    const-string v14, "DISCONNECTED"

    .line 259
    .line 260
    invoke-virtual {v1, v14}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v1

    .line 264
    if-eqz v1, :cond_c

    .line 265
    .line 266
    sget-object v1, Lmb0/g;->e:Lmb0/g;

    .line 267
    .line 268
    goto :goto_d

    .line 269
    :cond_c
    const/4 v1, 0x0

    .line 270
    :goto_d
    move-object v14, v1

    .line 271
    goto :goto_e

    .line 272
    :cond_d
    const/4 v14, 0x0

    .line 273
    :goto_e
    invoke-virtual {v0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getErrors()Ljava/util/List;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    sget-object v15, Lmx0/s;->d:Lmx0/s;

    .line 278
    .line 279
    if-nez v1, :cond_e

    .line 280
    .line 281
    move-object v1, v15

    .line 282
    :cond_e
    check-cast v1, Ljava/lang/Iterable;

    .line 283
    .line 284
    move-object/from16 v16, v15

    .line 285
    .line 286
    new-instance v15, Ljava/util/ArrayList;

    .line 287
    .line 288
    const/16 v3, 0xa

    .line 289
    .line 290
    move-object/from16 p1, v0

    .line 291
    .line 292
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 293
    .line 294
    .line 295
    move-result v0

    .line 296
    invoke-direct {v15, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 297
    .line 298
    .line 299
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    :goto_f
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 304
    .line 305
    .line 306
    move-result v1

    .line 307
    if-eqz v1, :cond_17

    .line 308
    .line 309
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v1

    .line 313
    check-cast v1, Lcz/myskoda/api/bff_air_conditioning/v2/ErrorDto;

    .line 314
    .line 315
    new-instance v3, Lmb0/a;

    .line 316
    .line 317
    move-object/from16 v18, v0

    .line 318
    .line 319
    invoke-virtual {v1}, Lcz/myskoda/api/bff_air_conditioning/v2/ErrorDto;->getType()Ljava/lang/String;

    .line 320
    .line 321
    .line 322
    move-result-object v0

    .line 323
    if-eqz v0, :cond_f

    .line 324
    .line 325
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 326
    .line 327
    .line 328
    move-result v19

    .line 329
    sparse-switch v19, :sswitch_data_0

    .line 330
    .line 331
    .line 332
    :cond_f
    move-object/from16 v19, v1

    .line 333
    .line 334
    goto/16 :goto_10

    .line 335
    .line 336
    :sswitch_0
    move-object/from16 v19, v1

    .line 337
    .line 338
    const-string v1, "UNPROCESSABLE_REQUEST"

    .line 339
    .line 340
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    move-result v0

    .line 344
    if-nez v0, :cond_10

    .line 345
    .line 346
    goto/16 :goto_10

    .line 347
    .line 348
    :cond_10
    sget-object v0, Lmb0/b;->j:Lmb0/b;

    .line 349
    .line 350
    goto :goto_11

    .line 351
    :sswitch_1
    move-object/from16 v19, v1

    .line 352
    .line 353
    const-string v1, "NUMBER_OF_OPERATIONS_EXHAUSTED"

    .line 354
    .line 355
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    move-result v0

    .line 359
    if-nez v0, :cond_11

    .line 360
    .line 361
    goto :goto_10

    .line 362
    :cond_11
    sget-object v0, Lmb0/b;->i:Lmb0/b;

    .line 363
    .line 364
    goto :goto_11

    .line 365
    :sswitch_2
    move-object/from16 v19, v1

    .line 366
    .line 367
    const-string v1, "CAPABILITY_DISABLED_BY_USER"

    .line 368
    .line 369
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    move-result v0

    .line 373
    if-nez v0, :cond_12

    .line 374
    .line 375
    goto :goto_10

    .line 376
    :cond_12
    sget-object v0, Lmb0/b;->e:Lmb0/b;

    .line 377
    .line 378
    goto :goto_11

    .line 379
    :sswitch_3
    move-object/from16 v19, v1

    .line 380
    .line 381
    const-string v1, "VEHICLE_IN_DEEP_SLEEP"

    .line 382
    .line 383
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 384
    .line 385
    .line 386
    move-result v0

    .line 387
    if-nez v0, :cond_13

    .line 388
    .line 389
    goto :goto_10

    .line 390
    :cond_13
    sget-object v0, Lmb0/b;->h:Lmb0/b;

    .line 391
    .line 392
    goto :goto_11

    .line 393
    :sswitch_4
    move-object/from16 v19, v1

    .line 394
    .line 395
    const-string v1, "UNAVAILABLE_VEHICLE_INFORMATION"

    .line 396
    .line 397
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 398
    .line 399
    .line 400
    move-result v0

    .line 401
    if-nez v0, :cond_14

    .line 402
    .line 403
    goto :goto_10

    .line 404
    :cond_14
    sget-object v0, Lmb0/b;->k:Lmb0/b;

    .line 405
    .line 406
    goto :goto_11

    .line 407
    :sswitch_5
    move-object/from16 v19, v1

    .line 408
    .line 409
    const-string v1, "EXACTLY_TWO_TIMERS_REQUIRED"

    .line 410
    .line 411
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 412
    .line 413
    .line 414
    move-result v0

    .line 415
    if-nez v0, :cond_15

    .line 416
    .line 417
    goto :goto_10

    .line 418
    :cond_15
    sget-object v0, Lmb0/b;->g:Lmb0/b;

    .line 419
    .line 420
    goto :goto_11

    .line 421
    :sswitch_6
    move-object/from16 v19, v1

    .line 422
    .line 423
    const-string v1, "INSUFFICIENT_BATTERY_LEVEL"

    .line 424
    .line 425
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 426
    .line 427
    .line 428
    move-result v0

    .line 429
    if-nez v0, :cond_16

    .line 430
    .line 431
    goto :goto_10

    .line 432
    :cond_16
    sget-object v0, Lmb0/b;->f:Lmb0/b;

    .line 433
    .line 434
    goto :goto_11

    .line 435
    :goto_10
    sget-object v0, Lmb0/b;->d:Lmb0/b;

    .line 436
    .line 437
    :goto_11
    invoke-virtual/range {v19 .. v19}, Lcz/myskoda/api/bff_air_conditioning/v2/ErrorDto;->getDescription()Ljava/lang/String;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    invoke-direct {v3, v0, v1}, Lmb0/a;-><init>(Lmb0/b;Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {v15, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 445
    .line 446
    .line 447
    move-object/from16 v0, v18

    .line 448
    .line 449
    const/16 v3, 0xa

    .line 450
    .line 451
    goto/16 :goto_f

    .line 452
    .line 453
    :cond_17
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getTimers()Ljava/util/List;

    .line 454
    .line 455
    .line 456
    move-result-object v0

    .line 457
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 458
    .line 459
    .line 460
    check-cast v0, Ljava/lang/Iterable;

    .line 461
    .line 462
    new-instance v1, Ljava/util/ArrayList;

    .line 463
    .line 464
    move-object/from16 v18, v4

    .line 465
    .line 466
    const/16 v3, 0xa

    .line 467
    .line 468
    invoke-static {v0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 469
    .line 470
    .line 471
    move-result v4

    .line 472
    invoke-direct {v1, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 473
    .line 474
    .line 475
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 476
    .line 477
    .line 478
    move-result-object v0

    .line 479
    :goto_12
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 480
    .line 481
    .line 482
    move-result v3

    .line 483
    if-eqz v3, :cond_18

    .line 484
    .line 485
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object v3

    .line 489
    check-cast v3, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;

    .line 490
    .line 491
    invoke-static {v3}, Lwn0/c;->b(Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;)Lao0/c;

    .line 492
    .line 493
    .line 494
    move-result-object v3

    .line 495
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 496
    .line 497
    .line 498
    goto :goto_12

    .line 499
    :cond_18
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getRunningRequests()Ljava/util/List;

    .line 500
    .line 501
    .line 502
    move-result-object v0

    .line 503
    if-nez v0, :cond_19

    .line 504
    .line 505
    goto :goto_13

    .line 506
    :cond_19
    move-object/from16 v16, v0

    .line 507
    .line 508
    :goto_13
    move-object/from16 v0, v16

    .line 509
    .line 510
    check-cast v0, Ljava/lang/Iterable;

    .line 511
    .line 512
    new-instance v3, Ljava/util/ArrayList;

    .line 513
    .line 514
    const/16 v4, 0xa

    .line 515
    .line 516
    invoke-static {v0, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 517
    .line 518
    .line 519
    move-result v4

    .line 520
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 521
    .line 522
    .line 523
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 524
    .line 525
    .line 526
    move-result-object v0

    .line 527
    :goto_14
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 528
    .line 529
    .line 530
    move-result v4

    .line 531
    if-eqz v4, :cond_1b

    .line 532
    .line 533
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 534
    .line 535
    .line 536
    move-result-object v4

    .line 537
    check-cast v4, Lcz/myskoda/api/bff_air_conditioning/v2/RunningRequestDto;

    .line 538
    .line 539
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    move-object/from16 v16, v0

    .line 543
    .line 544
    new-instance v0, Lmb0/k;

    .line 545
    .line 546
    move-object/from16 v17, v1

    .line 547
    .line 548
    invoke-virtual {v4}, Lcz/myskoda/api/bff_air_conditioning/v2/RunningRequestDto;->getValue()Ljava/lang/String;

    .line 549
    .line 550
    .line 551
    move-result-object v1

    .line 552
    invoke-virtual {v4}, Lcz/myskoda/api/bff_air_conditioning/v2/RunningRequestDto;->getTargetTemperature()Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;

    .line 553
    .line 554
    .line 555
    move-result-object v4

    .line 556
    if-eqz v4, :cond_1a

    .line 557
    .line 558
    invoke-static {v4}, Ljb0/k;->b(Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;)Lqr0/q;

    .line 559
    .line 560
    .line 561
    move-result-object v4

    .line 562
    goto :goto_15

    .line 563
    :cond_1a
    const/4 v4, 0x0

    .line 564
    :goto_15
    invoke-direct {v0, v1, v4}, Lmb0/k;-><init>(Ljava/lang/String;Lqr0/q;)V

    .line 565
    .line 566
    .line 567
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 568
    .line 569
    .line 570
    move-object/from16 v0, v16

    .line 571
    .line 572
    move-object/from16 v1, v17

    .line 573
    .line 574
    goto :goto_14

    .line 575
    :cond_1b
    move-object/from16 v17, v1

    .line 576
    .line 577
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getCarCapturedTimestamp()Ljava/time/OffsetDateTime;

    .line 578
    .line 579
    .line 580
    move-result-object v0

    .line 581
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;->getOutsideTemperature()Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;

    .line 582
    .line 583
    .line 584
    move-result-object v1

    .line 585
    if-eqz v1, :cond_1c

    .line 586
    .line 587
    invoke-static {v1}, Ljb0/t;->a(Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;)Lmb0/c;

    .line 588
    .line 589
    .line 590
    move-result-object v1

    .line 591
    move-object/from16 v19, v1

    .line 592
    .line 593
    :goto_16
    move-object/from16 v16, v17

    .line 594
    .line 595
    move-object/from16 v17, v3

    .line 596
    .line 597
    goto :goto_17

    .line 598
    :cond_1c
    const/16 v19, 0x0

    .line 599
    .line 600
    goto :goto_16

    .line 601
    :goto_17
    new-instance v3, Lmb0/f;

    .line 602
    .line 603
    move-object/from16 v4, v18

    .line 604
    .line 605
    move-object/from16 v18, v0

    .line 606
    .line 607
    invoke-direct/range {v3 .. v19}, Lmb0/f;-><init>(Lmb0/e;Lmb0/n;Ljava/lang/Boolean;Ljava/time/OffsetDateTime;Lqr0/q;Ljava/lang/Boolean;Ljava/lang/Boolean;Lmb0/m;Lmb0/l;Lmb0/i;Lmb0/g;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/time/OffsetDateTime;Lmb0/c;)V

    .line 608
    .line 609
    .line 610
    return-object v3

    .line 611
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 612
    .line 613
    .line 614
    .line 615
    .line 616
    .line 617
    .line 618
    .line 619
    .line 620
    .line 621
    .line 622
    .line 623
    .line 624
    .line 625
    .line 626
    .line 627
    .line 628
    .line 629
    .line 630
    .line 631
    :sswitch_data_0
    .sparse-switch
        -0x3104ccaa -> :sswitch_6
        -0x2e527d36 -> :sswitch_5
        0x49151ca -> :sswitch_4
        0x517f690b -> :sswitch_3
        0x585b6c37 -> :sswitch_2
        0x74accd08 -> :sswitch_1
        0x7f2c3920 -> :sswitch_0
    .end sparse-switch
.end method

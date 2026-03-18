.class public final synthetic Lpt0/c;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Lpt0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lpt0/c;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDto;)Lcz/skodaauto/myskoda/library/vehiclestatus/model/VehicleStatus;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Lpt0/n;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lpt0/c;->d:Lpt0/c;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    check-cast v2, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDto;

    .line 6
    .line 7
    const-string v0, "p0"

    .line 8
    .line 9
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDto;->getOverall()Lcz/myskoda/api/bff_vehicle_status/v2/OverallVehicleStatusDto;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v3, "<this>"

    .line 17
    .line 18
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/OverallVehicleStatusDto;->getLocked()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    const-string v5, "YES"

    .line 26
    .line 27
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v6

    .line 31
    const-string v7, "NO"

    .line 32
    .line 33
    if-eqz v6, :cond_0

    .line 34
    .line 35
    sget-object v4, Lst0/i;->d:Lst0/i;

    .line 36
    .line 37
    :goto_0
    move-object v11, v4

    .line 38
    goto :goto_1

    .line 39
    :cond_0
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    if-eqz v4, :cond_1

    .line 44
    .line 45
    sget-object v4, Lst0/i;->e:Lst0/i;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    sget-object v4, Lst0/i;->f:Lst0/i;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :goto_1
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/OverallVehicleStatusDto;->getLights()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    const-string v6, "ON"

    .line 56
    .line 57
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    if-eqz v6, :cond_2

    .line 62
    .line 63
    sget-object v4, Lst0/e;->d:Lst0/e;

    .line 64
    .line 65
    :goto_2
    move-object v12, v4

    .line 66
    goto :goto_3

    .line 67
    :cond_2
    const-string v6, "OFF"

    .line 68
    .line 69
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    if-eqz v4, :cond_3

    .line 74
    .line 75
    sget-object v4, Lst0/e;->e:Lst0/e;

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_3
    sget-object v4, Lst0/e;->f:Lst0/e;

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :goto_3
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/OverallVehicleStatusDto;->getDoors()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    const-string v6, "OPEN"

    .line 86
    .line 87
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v8

    .line 91
    const-string v9, "CLOSED"

    .line 92
    .line 93
    if-eqz v8, :cond_4

    .line 94
    .line 95
    sget-object v4, Lst0/b;->d:Lst0/b;

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_4
    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    if-eqz v4, :cond_5

    .line 103
    .line 104
    sget-object v4, Lst0/b;->e:Lst0/b;

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_5
    sget-object v4, Lst0/b;->f:Lst0/b;

    .line 108
    .line 109
    :goto_4
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/OverallVehicleStatusDto;->getWindows()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    invoke-virtual {v8}, Ljava/lang/String;->hashCode()I

    .line 114
    .line 115
    .line 116
    move-result v10

    .line 117
    const-string v13, "UNSUPPORTED"

    .line 118
    .line 119
    const v15, 0x251e4a

    .line 120
    .line 121
    .line 122
    const v14, -0x7cc649eb

    .line 123
    .line 124
    .line 125
    if-eq v10, v14, :cond_9

    .line 126
    .line 127
    const v14, 0x76a8d56c

    .line 128
    .line 129
    .line 130
    if-eq v10, v15, :cond_8

    .line 131
    .line 132
    if-eq v10, v14, :cond_6

    .line 133
    .line 134
    goto :goto_6

    .line 135
    :cond_6
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v8

    .line 139
    if-nez v8, :cond_7

    .line 140
    .line 141
    goto :goto_6

    .line 142
    :cond_7
    sget-object v8, Lst0/q;->e:Lst0/q;

    .line 143
    .line 144
    :goto_5
    move-object v10, v8

    .line 145
    goto :goto_7

    .line 146
    :cond_8
    invoke-virtual {v8, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v8

    .line 150
    if-eqz v8, :cond_a

    .line 151
    .line 152
    sget-object v8, Lst0/q;->d:Lst0/q;

    .line 153
    .line 154
    goto :goto_5

    .line 155
    :cond_9
    const v14, 0x76a8d56c

    .line 156
    .line 157
    .line 158
    invoke-virtual {v8, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v8

    .line 162
    if-nez v8, :cond_b

    .line 163
    .line 164
    :cond_a
    :goto_6
    sget-object v8, Lst0/q;->f:Lst0/q;

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_b
    sget-object v8, Lst0/q;->g:Lst0/q;

    .line 168
    .line 169
    goto :goto_5

    .line 170
    :goto_7
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/OverallVehicleStatusDto;->getDoorsLocked()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v8

    .line 174
    invoke-virtual {v8}, Ljava/lang/String;->hashCode()I

    .line 175
    .line 176
    .line 177
    move-result v14

    .line 178
    const v15, -0x74a94397

    .line 179
    .line 180
    .line 181
    if-eq v14, v15, :cond_12

    .line 182
    .line 183
    const/16 v15, 0x9c1

    .line 184
    .line 185
    if-eq v14, v15, :cond_10

    .line 186
    .line 187
    const v7, 0x156c7

    .line 188
    .line 189
    .line 190
    if-eq v14, v7, :cond_e

    .line 191
    .line 192
    const v5, 0x1c86c574

    .line 193
    .line 194
    .line 195
    if-eq v14, v5, :cond_c

    .line 196
    .line 197
    goto :goto_8

    .line 198
    :cond_c
    const-string v5, "TRUNK_OPENED"

    .line 199
    .line 200
    invoke-virtual {v8, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v5

    .line 204
    if-nez v5, :cond_d

    .line 205
    .line 206
    goto :goto_8

    .line 207
    :cond_d
    sget-object v5, Lst0/c;->g:Lst0/c;

    .line 208
    .line 209
    goto :goto_9

    .line 210
    :cond_e
    invoke-virtual {v8, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v5

    .line 214
    if-nez v5, :cond_f

    .line 215
    .line 216
    goto :goto_8

    .line 217
    :cond_f
    sget-object v5, Lst0/c;->d:Lst0/c;

    .line 218
    .line 219
    goto :goto_9

    .line 220
    :cond_10
    invoke-virtual {v8, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v5

    .line 224
    if-nez v5, :cond_11

    .line 225
    .line 226
    goto :goto_8

    .line 227
    :cond_11
    sget-object v5, Lst0/c;->e:Lst0/c;

    .line 228
    .line 229
    goto :goto_9

    .line 230
    :cond_12
    const-string v5, "OPENED"

    .line 231
    .line 232
    invoke-virtual {v8, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 233
    .line 234
    .line 235
    move-result v5

    .line 236
    if-nez v5, :cond_13

    .line 237
    .line 238
    :goto_8
    sget-object v5, Lst0/c;->h:Lst0/c;

    .line 239
    .line 240
    goto :goto_9

    .line 241
    :cond_13
    sget-object v5, Lst0/c;->f:Lst0/c;

    .line 242
    .line 243
    :goto_9
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/OverallVehicleStatusDto;->getDoors()Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v7

    .line 247
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v8

    .line 251
    if-eqz v8, :cond_14

    .line 252
    .line 253
    sget-object v7, Lst0/d;->d:Lst0/d;

    .line 254
    .line 255
    :goto_a
    move-object v14, v7

    .line 256
    goto :goto_b

    .line 257
    :cond_14
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v7

    .line 261
    if-eqz v7, :cond_15

    .line 262
    .line 263
    sget-object v7, Lst0/d;->e:Lst0/d;

    .line 264
    .line 265
    goto :goto_a

    .line 266
    :cond_15
    sget-object v7, Lst0/d;->f:Lst0/d;

    .line 267
    .line 268
    goto :goto_a

    .line 269
    :goto_b
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/OverallVehicleStatusDto;->getReliableLockStatus()Ljava/lang/String;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    const-string v7, "LOCKED"

    .line 274
    .line 275
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v7

    .line 279
    if-eqz v7, :cond_16

    .line 280
    .line 281
    sget-object v0, Lst0/f;->d:Lst0/f;

    .line 282
    .line 283
    :goto_c
    move-object v15, v0

    .line 284
    goto :goto_d

    .line 285
    :cond_16
    const-string v7, "UNLOCKED"

    .line 286
    .line 287
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 288
    .line 289
    .line 290
    move-result v0

    .line 291
    if-eqz v0, :cond_17

    .line 292
    .line 293
    sget-object v0, Lst0/f;->e:Lst0/f;

    .line 294
    .line 295
    goto :goto_c

    .line 296
    :cond_17
    sget-object v0, Lst0/f;->f:Lst0/f;

    .line 297
    .line 298
    goto :goto_c

    .line 299
    :goto_d
    new-instance v8, Lst0/j;

    .line 300
    .line 301
    move-object v0, v9

    .line 302
    move-object v9, v4

    .line 303
    move-object v4, v0

    .line 304
    move-object v0, v13

    .line 305
    const v7, -0x7cc649eb

    .line 306
    .line 307
    .line 308
    move-object v13, v5

    .line 309
    const v5, 0x251e4a

    .line 310
    .line 311
    .line 312
    invoke-direct/range {v8 .. v15}, Lst0/j;-><init>(Lst0/b;Lst0/q;Lst0/i;Lst0/e;Lst0/c;Lst0/d;Lst0/f;)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {v2}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDto;->getDetail()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDetailDto;

    .line 316
    .line 317
    .line 318
    move-result-object v9

    .line 319
    invoke-static {v9, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 320
    .line 321
    .line 322
    invoke-virtual {v9}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDetailDto;->getBonnet()Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v3

    .line 326
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    move-result v10

    .line 330
    if-eqz v10, :cond_18

    .line 331
    .line 332
    sget-object v3, Lst0/a;->d:Lst0/a;

    .line 333
    .line 334
    goto :goto_e

    .line 335
    :cond_18
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 336
    .line 337
    .line 338
    move-result v3

    .line 339
    if-eqz v3, :cond_19

    .line 340
    .line 341
    sget-object v3, Lst0/a;->e:Lst0/a;

    .line 342
    .line 343
    goto :goto_e

    .line 344
    :cond_19
    sget-object v3, Lst0/a;->f:Lst0/a;

    .line 345
    .line 346
    :goto_e
    invoke-virtual {v9}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDetailDto;->getSunroof()Ljava/lang/String;

    .line 347
    .line 348
    .line 349
    move-result-object v10

    .line 350
    invoke-virtual {v10}, Ljava/lang/String;->hashCode()I

    .line 351
    .line 352
    .line 353
    move-result v11

    .line 354
    if-eq v11, v7, :cond_1d

    .line 355
    .line 356
    if-eq v11, v5, :cond_1c

    .line 357
    .line 358
    const v14, 0x76a8d56c

    .line 359
    .line 360
    .line 361
    if-eq v11, v14, :cond_1a

    .line 362
    .line 363
    goto :goto_f

    .line 364
    :cond_1a
    invoke-virtual {v10, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 365
    .line 366
    .line 367
    move-result v0

    .line 368
    if-nez v0, :cond_1b

    .line 369
    .line 370
    goto :goto_f

    .line 371
    :cond_1b
    sget-object v0, Lst0/k;->e:Lst0/k;

    .line 372
    .line 373
    goto :goto_10

    .line 374
    :cond_1c
    invoke-virtual {v10, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 375
    .line 376
    .line 377
    move-result v0

    .line 378
    if-eqz v0, :cond_1e

    .line 379
    .line 380
    sget-object v0, Lst0/k;->d:Lst0/k;

    .line 381
    .line 382
    goto :goto_10

    .line 383
    :cond_1d
    invoke-virtual {v10, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 384
    .line 385
    .line 386
    move-result v0

    .line 387
    if-nez v0, :cond_1f

    .line 388
    .line 389
    :cond_1e
    :goto_f
    sget-object v0, Lst0/k;->f:Lst0/k;

    .line 390
    .line 391
    goto :goto_10

    .line 392
    :cond_1f
    sget-object v0, Lst0/k;->g:Lst0/k;

    .line 393
    .line 394
    :goto_10
    invoke-virtual {v9}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDetailDto;->getTrunk()Ljava/lang/String;

    .line 395
    .line 396
    .line 397
    move-result-object v5

    .line 398
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    move-result v6

    .line 402
    if-eqz v6, :cond_20

    .line 403
    .line 404
    sget-object v4, Lst0/l;->d:Lst0/l;

    .line 405
    .line 406
    goto :goto_11

    .line 407
    :cond_20
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 408
    .line 409
    .line 410
    move-result v4

    .line 411
    if-eqz v4, :cond_21

    .line 412
    .line 413
    sget-object v4, Lst0/l;->e:Lst0/l;

    .line 414
    .line 415
    goto :goto_11

    .line 416
    :cond_21
    sget-object v4, Lst0/l;->f:Lst0/l;

    .line 417
    .line 418
    :goto_11
    new-instance v5, Lst0/m;

    .line 419
    .line 420
    invoke-direct {v5, v0, v4, v3}, Lst0/m;-><init>(Lst0/k;Lst0/l;Lst0/a;)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v2}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDto;->getRenders()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;

    .line 424
    .line 425
    .line 426
    move-result-object v3

    .line 427
    const/4 v4, 0x0

    .line 428
    if-eqz v3, :cond_2a

    .line 429
    .line 430
    new-instance v6, Lnx0/f;

    .line 431
    .line 432
    invoke-direct {v6}, Lnx0/f;-><init>()V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;->getLightMode()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;->getOneX()Ljava/lang/String;

    .line 440
    .line 441
    .line 442
    move-result-object v7

    .line 443
    :try_start_0
    new-instance v0, Ljava/net/URL;

    .line 444
    .line 445
    invoke-direct {v0, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 446
    .line 447
    .line 448
    sget-object v9, Lbg0/a;->e:Lbg0/a;

    .line 449
    .line 450
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 451
    .line 452
    new-instance v11, Llx0/l;

    .line 453
    .line 454
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 455
    .line 456
    .line 457
    invoke-virtual {v6, v11, v0}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 458
    .line 459
    .line 460
    move-object v0, v1

    .line 461
    goto :goto_12

    .line 462
    :catchall_0
    move-exception v0

    .line 463
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 464
    .line 465
    .line 466
    move-result-object v0

    .line 467
    :goto_12
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 468
    .line 469
    .line 470
    move-result-object v0

    .line 471
    if-eqz v0, :cond_22

    .line 472
    .line 473
    new-instance v9, Lo51/c;

    .line 474
    .line 475
    const/16 v10, 0xa

    .line 476
    .line 477
    invoke-direct {v9, v10, v0, v7}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 478
    .line 479
    .line 480
    invoke-static {v4, v0, v9}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 481
    .line 482
    .line 483
    :cond_22
    invoke-virtual {v3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;->getLightMode()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;

    .line 484
    .line 485
    .line 486
    move-result-object v0

    .line 487
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;->getOneAndHalfX()Ljava/lang/String;

    .line 488
    .line 489
    .line 490
    move-result-object v7

    .line 491
    :try_start_1
    new-instance v0, Ljava/net/URL;

    .line 492
    .line 493
    invoke-direct {v0, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 494
    .line 495
    .line 496
    sget-object v9, Lbg0/a;->f:Lbg0/a;

    .line 497
    .line 498
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 499
    .line 500
    new-instance v11, Llx0/l;

    .line 501
    .line 502
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 503
    .line 504
    .line 505
    invoke-virtual {v6, v11, v0}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 506
    .line 507
    .line 508
    move-object v0, v1

    .line 509
    goto :goto_13

    .line 510
    :catchall_1
    move-exception v0

    .line 511
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    :goto_13
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 516
    .line 517
    .line 518
    move-result-object v0

    .line 519
    if-eqz v0, :cond_23

    .line 520
    .line 521
    new-instance v9, Lo51/c;

    .line 522
    .line 523
    const/16 v10, 0xa

    .line 524
    .line 525
    invoke-direct {v9, v10, v0, v7}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 526
    .line 527
    .line 528
    invoke-static {v4, v0, v9}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 529
    .line 530
    .line 531
    :cond_23
    invoke-virtual {v3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;->getLightMode()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;

    .line 532
    .line 533
    .line 534
    move-result-object v0

    .line 535
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;->getTwoX()Ljava/lang/String;

    .line 536
    .line 537
    .line 538
    move-result-object v7

    .line 539
    :try_start_2
    new-instance v0, Ljava/net/URL;

    .line 540
    .line 541
    invoke-direct {v0, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 542
    .line 543
    .line 544
    sget-object v9, Lbg0/a;->g:Lbg0/a;

    .line 545
    .line 546
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 547
    .line 548
    new-instance v11, Llx0/l;

    .line 549
    .line 550
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 551
    .line 552
    .line 553
    invoke-virtual {v6, v11, v0}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 554
    .line 555
    .line 556
    move-object v0, v1

    .line 557
    goto :goto_14

    .line 558
    :catchall_2
    move-exception v0

    .line 559
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 560
    .line 561
    .line 562
    move-result-object v0

    .line 563
    :goto_14
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 564
    .line 565
    .line 566
    move-result-object v0

    .line 567
    if-eqz v0, :cond_24

    .line 568
    .line 569
    new-instance v9, Lo51/c;

    .line 570
    .line 571
    const/16 v10, 0xa

    .line 572
    .line 573
    invoke-direct {v9, v10, v0, v7}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 574
    .line 575
    .line 576
    invoke-static {v4, v0, v9}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 577
    .line 578
    .line 579
    :cond_24
    invoke-virtual {v3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;->getLightMode()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;

    .line 580
    .line 581
    .line 582
    move-result-object v0

    .line 583
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;->getThreeX()Ljava/lang/String;

    .line 584
    .line 585
    .line 586
    move-result-object v7

    .line 587
    :try_start_3
    new-instance v0, Ljava/net/URL;

    .line 588
    .line 589
    invoke-direct {v0, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 590
    .line 591
    .line 592
    sget-object v9, Lbg0/a;->h:Lbg0/a;

    .line 593
    .line 594
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 595
    .line 596
    new-instance v11, Llx0/l;

    .line 597
    .line 598
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 599
    .line 600
    .line 601
    invoke-virtual {v6, v11, v0}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 602
    .line 603
    .line 604
    move-object v0, v1

    .line 605
    goto :goto_15

    .line 606
    :catchall_3
    move-exception v0

    .line 607
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 608
    .line 609
    .line 610
    move-result-object v0

    .line 611
    :goto_15
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 612
    .line 613
    .line 614
    move-result-object v0

    .line 615
    if-eqz v0, :cond_25

    .line 616
    .line 617
    new-instance v9, Lo51/c;

    .line 618
    .line 619
    const/16 v10, 0xa

    .line 620
    .line 621
    invoke-direct {v9, v10, v0, v7}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 622
    .line 623
    .line 624
    invoke-static {v4, v0, v9}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 625
    .line 626
    .line 627
    :cond_25
    invoke-virtual {v3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;->getDarkMode()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;

    .line 628
    .line 629
    .line 630
    move-result-object v0

    .line 631
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;->getOneX()Ljava/lang/String;

    .line 632
    .line 633
    .line 634
    move-result-object v7

    .line 635
    :try_start_4
    new-instance v0, Ljava/net/URL;

    .line 636
    .line 637
    invoke-direct {v0, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 638
    .line 639
    .line 640
    sget-object v9, Lbg0/a;->e:Lbg0/a;

    .line 641
    .line 642
    sget-object v10, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 643
    .line 644
    new-instance v11, Llx0/l;

    .line 645
    .line 646
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 647
    .line 648
    .line 649
    invoke-virtual {v6, v11, v0}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 650
    .line 651
    .line 652
    move-object v0, v1

    .line 653
    goto :goto_16

    .line 654
    :catchall_4
    move-exception v0

    .line 655
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 656
    .line 657
    .line 658
    move-result-object v0

    .line 659
    :goto_16
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 660
    .line 661
    .line 662
    move-result-object v0

    .line 663
    if-eqz v0, :cond_26

    .line 664
    .line 665
    new-instance v9, Lo51/c;

    .line 666
    .line 667
    const/16 v10, 0xa

    .line 668
    .line 669
    invoke-direct {v9, v10, v0, v7}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 670
    .line 671
    .line 672
    invoke-static {v4, v0, v9}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 673
    .line 674
    .line 675
    :cond_26
    invoke-virtual {v3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;->getDarkMode()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;

    .line 676
    .line 677
    .line 678
    move-result-object v0

    .line 679
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;->getOneAndHalfX()Ljava/lang/String;

    .line 680
    .line 681
    .line 682
    move-result-object v7

    .line 683
    :try_start_5
    new-instance v0, Ljava/net/URL;

    .line 684
    .line 685
    invoke-direct {v0, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 686
    .line 687
    .line 688
    sget-object v9, Lbg0/a;->f:Lbg0/a;

    .line 689
    .line 690
    sget-object v10, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 691
    .line 692
    new-instance v11, Llx0/l;

    .line 693
    .line 694
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 695
    .line 696
    .line 697
    invoke-virtual {v6, v11, v0}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 698
    .line 699
    .line 700
    move-object v0, v1

    .line 701
    goto :goto_17

    .line 702
    :catchall_5
    move-exception v0

    .line 703
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 704
    .line 705
    .line 706
    move-result-object v0

    .line 707
    :goto_17
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 708
    .line 709
    .line 710
    move-result-object v0

    .line 711
    if-eqz v0, :cond_27

    .line 712
    .line 713
    new-instance v9, Lo51/c;

    .line 714
    .line 715
    const/16 v10, 0xa

    .line 716
    .line 717
    invoke-direct {v9, v10, v0, v7}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 718
    .line 719
    .line 720
    invoke-static {v4, v0, v9}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 721
    .line 722
    .line 723
    :cond_27
    invoke-virtual {v3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;->getDarkMode()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;

    .line 724
    .line 725
    .line 726
    move-result-object v0

    .line 727
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;->getTwoX()Ljava/lang/String;

    .line 728
    .line 729
    .line 730
    move-result-object v7

    .line 731
    :try_start_6
    new-instance v0, Ljava/net/URL;

    .line 732
    .line 733
    invoke-direct {v0, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 734
    .line 735
    .line 736
    sget-object v9, Lbg0/a;->g:Lbg0/a;

    .line 737
    .line 738
    sget-object v10, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 739
    .line 740
    new-instance v11, Llx0/l;

    .line 741
    .line 742
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 743
    .line 744
    .line 745
    invoke-virtual {v6, v11, v0}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 746
    .line 747
    .line 748
    move-object v0, v1

    .line 749
    goto :goto_18

    .line 750
    :catchall_6
    move-exception v0

    .line 751
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 752
    .line 753
    .line 754
    move-result-object v0

    .line 755
    :goto_18
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 756
    .line 757
    .line 758
    move-result-object v0

    .line 759
    if-eqz v0, :cond_28

    .line 760
    .line 761
    new-instance v9, Lo51/c;

    .line 762
    .line 763
    const/16 v10, 0xa

    .line 764
    .line 765
    invoke-direct {v9, v10, v0, v7}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 766
    .line 767
    .line 768
    invoke-static {v4, v0, v9}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 769
    .line 770
    .line 771
    :cond_28
    invoke-virtual {v3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRendersDto;->getDarkMode()Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;

    .line 772
    .line 773
    .line 774
    move-result-object v0

    .line 775
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleRenderModeDto;->getThreeX()Ljava/lang/String;

    .line 776
    .line 777
    .line 778
    move-result-object v3

    .line 779
    :try_start_7
    new-instance v0, Ljava/net/URL;

    .line 780
    .line 781
    invoke-direct {v0, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 782
    .line 783
    .line 784
    sget-object v7, Lbg0/a;->h:Lbg0/a;

    .line 785
    .line 786
    sget-object v9, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 787
    .line 788
    new-instance v10, Llx0/l;

    .line 789
    .line 790
    invoke-direct {v10, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 791
    .line 792
    .line 793
    invoke-virtual {v6, v10, v0}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_7

    .line 794
    .line 795
    .line 796
    goto :goto_19

    .line 797
    :catchall_7
    move-exception v0

    .line 798
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 799
    .line 800
    .line 801
    move-result-object v1

    .line 802
    :goto_19
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 803
    .line 804
    .line 805
    move-result-object v0

    .line 806
    if-eqz v0, :cond_29

    .line 807
    .line 808
    new-instance v1, Lo51/c;

    .line 809
    .line 810
    const/16 v7, 0xa

    .line 811
    .line 812
    invoke-direct {v1, v7, v0, v3}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 813
    .line 814
    .line 815
    invoke-static {v4, v0, v1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 816
    .line 817
    .line 818
    :cond_29
    invoke-virtual {v6}, Lnx0/f;->b()Lnx0/f;

    .line 819
    .line 820
    .line 821
    move-result-object v4

    .line 822
    :cond_2a
    if-nez v4, :cond_2b

    .line 823
    .line 824
    sget-object v4, Lmx0/t;->d:Lmx0/t;

    .line 825
    .line 826
    :cond_2b
    invoke-virtual {v2}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDto;->getCarCapturedTimestamp()Ljava/time/OffsetDateTime;

    .line 827
    .line 828
    .line 829
    move-result-object v0

    .line 830
    new-instance v1, Lst0/p;

    .line 831
    .line 832
    invoke-direct {v1, v8, v4, v5, v0}, Lst0/p;-><init>(Lst0/j;Ljava/util/Map;Lst0/m;Ljava/time/OffsetDateTime;)V

    .line 833
    .line 834
    .line 835
    return-object v1
.end method

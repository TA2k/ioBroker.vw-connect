.class public abstract Ljp/te;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;)Lq81/b;
    .locals 27

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 2
    .line 3
    const v25, 0xffffff

    .line 4
    .line 5
    .line 6
    const/16 v26, 0x0

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v4, 0x0

    .line 12
    const/4 v5, 0x0

    .line 13
    const/4 v6, 0x0

    .line 14
    const/4 v7, 0x0

    .line 15
    const/4 v8, 0x0

    .line 16
    const/4 v9, 0x0

    .line 17
    const/4 v10, 0x0

    .line 18
    const/4 v11, 0x0

    .line 19
    const/4 v12, 0x0

    .line 20
    const/4 v13, 0x0

    .line 21
    const/4 v14, 0x0

    .line 22
    const/4 v15, 0x0

    .line 23
    const/16 v16, 0x0

    .line 24
    .line 25
    const/16 v17, 0x0

    .line 26
    .line 27
    const/16 v18, 0x0

    .line 28
    .line 29
    const/16 v19, 0x0

    .line 30
    .line 31
    const/16 v20, 0x0

    .line 32
    .line 33
    const/16 v21, 0x0

    .line 34
    .line 35
    const/16 v22, 0x0

    .line 36
    .line 37
    const/16 v23, 0x0

    .line 38
    .line 39
    const/16 v24, 0x0

    .line 40
    .line 41
    invoke-direct/range {v0 .. v26}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIIIILkotlin/jvm/internal/g;)V

    .line 42
    .line 43
    .line 44
    move-object v1, v0

    .line 45
    move-object/from16 v0, p0

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_0

    .line 52
    .line 53
    const/4 v0, 0x0

    .line 54
    return-object v0

    .line 55
    :cond_0
    new-instance v6, Ljava/util/ArrayList;

    .line 56
    .line 57
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 58
    .line 59
    .line 60
    new-instance v1, Lgy0/j;

    .line 61
    .line 62
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajNumberPoints()I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    const/4 v3, 0x1

    .line 67
    invoke-direct {v1, v3, v2, v3}, Lgy0/h;-><init>(III)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    :goto_0
    move-object v2, v1

    .line 75
    check-cast v2, Lgy0/i;

    .line 76
    .line 77
    iget-boolean v2, v2, Lgy0/i;->f:Z

    .line 78
    .line 79
    const v4, -0x3b001000    # -2047.5f

    .line 80
    .line 81
    .line 82
    const/16 v5, 0x64

    .line 83
    .line 84
    const/4 v7, 0x0

    .line 85
    const/4 v8, 0x2

    .line 86
    if-eqz v2, :cond_1

    .line 87
    .line 88
    move-object v2, v1

    .line 89
    check-cast v2, Lmx0/w;

    .line 90
    .line 91
    invoke-virtual {v2}, Lmx0/w;->nextInt()I

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 96
    .line 97
    .line 98
    move-result-object v7

    .line 99
    packed-switch v2, :pswitch_data_0

    .line 100
    .line 101
    .line 102
    new-instance v2, Llx0/l;

    .line 103
    .line 104
    invoke-direct {v2, v7, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto/16 :goto_1

    .line 108
    .line 109
    :pswitch_0
    new-instance v2, Llx0/l;

    .line 110
    .line 111
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP9PosX()I

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v7

    .line 119
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP9PosY()I

    .line 120
    .line 121
    .line 122
    move-result v9

    .line 123
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 124
    .line 125
    .line 126
    move-result-object v9

    .line 127
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    goto/16 :goto_1

    .line 131
    .line 132
    :pswitch_1
    new-instance v2, Llx0/l;

    .line 133
    .line 134
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP8PosX()I

    .line 135
    .line 136
    .line 137
    move-result v7

    .line 138
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 139
    .line 140
    .line 141
    move-result-object v7

    .line 142
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP8PosY()I

    .line 143
    .line 144
    .line 145
    move-result v9

    .line 146
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 147
    .line 148
    .line 149
    move-result-object v9

    .line 150
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    goto/16 :goto_1

    .line 154
    .line 155
    :pswitch_2
    new-instance v2, Llx0/l;

    .line 156
    .line 157
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP7PosX()I

    .line 158
    .line 159
    .line 160
    move-result v7

    .line 161
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 162
    .line 163
    .line 164
    move-result-object v7

    .line 165
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP7PosY()I

    .line 166
    .line 167
    .line 168
    move-result v9

    .line 169
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 170
    .line 171
    .line 172
    move-result-object v9

    .line 173
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    goto/16 :goto_1

    .line 177
    .line 178
    :pswitch_3
    new-instance v2, Llx0/l;

    .line 179
    .line 180
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP6PosX()I

    .line 181
    .line 182
    .line 183
    move-result v7

    .line 184
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 185
    .line 186
    .line 187
    move-result-object v7

    .line 188
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP6PosY()I

    .line 189
    .line 190
    .line 191
    move-result v9

    .line 192
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object v9

    .line 196
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    goto :goto_1

    .line 200
    :pswitch_4
    new-instance v2, Llx0/l;

    .line 201
    .line 202
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP5PosX()I

    .line 203
    .line 204
    .line 205
    move-result v7

    .line 206
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 207
    .line 208
    .line 209
    move-result-object v7

    .line 210
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP5PosY()I

    .line 211
    .line 212
    .line 213
    move-result v9

    .line 214
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 215
    .line 216
    .line 217
    move-result-object v9

    .line 218
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    goto :goto_1

    .line 222
    :pswitch_5
    new-instance v2, Llx0/l;

    .line 223
    .line 224
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP4PosX()I

    .line 225
    .line 226
    .line 227
    move-result v7

    .line 228
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 229
    .line 230
    .line 231
    move-result-object v7

    .line 232
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP4PosY()I

    .line 233
    .line 234
    .line 235
    move-result v9

    .line 236
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 237
    .line 238
    .line 239
    move-result-object v9

    .line 240
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    goto :goto_1

    .line 244
    :pswitch_6
    new-instance v2, Llx0/l;

    .line 245
    .line 246
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP3PosX()I

    .line 247
    .line 248
    .line 249
    move-result v7

    .line 250
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 251
    .line 252
    .line 253
    move-result-object v7

    .line 254
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP3PosY()I

    .line 255
    .line 256
    .line 257
    move-result v9

    .line 258
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 259
    .line 260
    .line 261
    move-result-object v9

    .line 262
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    goto :goto_1

    .line 266
    :pswitch_7
    new-instance v2, Llx0/l;

    .line 267
    .line 268
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP2PosX()I

    .line 269
    .line 270
    .line 271
    move-result v7

    .line 272
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 273
    .line 274
    .line 275
    move-result-object v7

    .line 276
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP2PosY()I

    .line 277
    .line 278
    .line 279
    move-result v9

    .line 280
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 281
    .line 282
    .line 283
    move-result-object v9

    .line 284
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    goto :goto_1

    .line 288
    :pswitch_8
    new-instance v2, Llx0/l;

    .line 289
    .line 290
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP1PosX()I

    .line 291
    .line 292
    .line 293
    move-result v7

    .line 294
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 295
    .line 296
    .line 297
    move-result-object v7

    .line 298
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajP1PosY()I

    .line 299
    .line 300
    .line 301
    move-result v9

    .line 302
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 303
    .line 304
    .line 305
    move-result-object v9

    .line 306
    invoke-direct {v2, v7, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 307
    .line 308
    .line 309
    :goto_1
    iget-object v7, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v7, Ljava/lang/Number;

    .line 312
    .line 313
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 314
    .line 315
    .line 316
    move-result v7

    .line 317
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 318
    .line 319
    check-cast v2, Ljava/lang/Number;

    .line 320
    .line 321
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 322
    .line 323
    .line 324
    move-result v2

    .line 325
    new-instance v9, Lw71/c;

    .line 326
    .line 327
    int-to-double v10, v7

    .line 328
    int-to-double v7, v8

    .line 329
    div-double/2addr v10, v7

    .line 330
    float-to-double v12, v4

    .line 331
    add-double/2addr v10, v12

    .line 332
    int-to-double v4, v5

    .line 333
    div-double/2addr v10, v4

    .line 334
    int-to-double v14, v2

    .line 335
    div-double/2addr v14, v7

    .line 336
    add-double/2addr v14, v12

    .line 337
    div-double/2addr v14, v4

    .line 338
    invoke-direct {v9, v10, v11, v14, v15}, Lw71/c;-><init>(DD)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    goto/16 :goto_0

    .line 345
    .line 346
    :cond_1
    new-instance v1, Lq81/b;

    .line 347
    .line 348
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajNumberPoints()I

    .line 349
    .line 350
    .line 351
    move-result v2

    .line 352
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajLatestMove()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 353
    .line 354
    .line 355
    move-result-object v9

    .line 356
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;->TARGET_POINT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 357
    .line 358
    if-ne v9, v10, :cond_2

    .line 359
    .line 360
    move v7, v3

    .line 361
    :cond_2
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajDrivingDirection()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 362
    .line 363
    .line 364
    move-result-object v9

    .line 365
    const-string v10, "<this>"

    .line 366
    .line 367
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    sget-object v10, Lr81/a;->e:[I

    .line 371
    .line 372
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 373
    .line 374
    .line 375
    move-result v9

    .line 376
    aget v9, v10, v9

    .line 377
    .line 378
    if-eq v9, v3, :cond_4

    .line 379
    .line 380
    if-ne v9, v8, :cond_3

    .line 381
    .line 382
    sget-object v3, Ls71/o;->e:Ls71/o;

    .line 383
    .line 384
    goto :goto_2

    .line 385
    :cond_3
    new-instance v0, La8/r0;

    .line 386
    .line 387
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 388
    .line 389
    .line 390
    throw v0

    .line 391
    :cond_4
    sget-object v3, Ls71/o;->d:Ls71/o;

    .line 392
    .line 393
    :goto_2
    new-instance v9, Lw71/b;

    .line 394
    .line 395
    new-instance v10, Lw71/c;

    .line 396
    .line 397
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajVehiclePosX()I

    .line 398
    .line 399
    .line 400
    move-result v11

    .line 401
    int-to-double v11, v11

    .line 402
    int-to-double v13, v8

    .line 403
    div-double/2addr v11, v13

    .line 404
    move-object v8, v1

    .line 405
    float-to-double v0, v4

    .line 406
    add-double/2addr v11, v0

    .line 407
    int-to-double v4, v5

    .line 408
    div-double/2addr v11, v4

    .line 409
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajVehiclePosY()I

    .line 410
    .line 411
    .line 412
    move-result v15

    .line 413
    move-wide/from16 v16, v0

    .line 414
    .line 415
    int-to-double v0, v15

    .line 416
    div-double/2addr v0, v13

    .line 417
    add-double v0, v0, v16

    .line 418
    .line 419
    div-double/2addr v0, v4

    .line 420
    invoke-direct {v10, v11, v12, v0, v1}, Lw71/c;-><init>(DD)V

    .line 421
    .line 422
    .line 423
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->getParkingTrajVehicleAngle()I

    .line 424
    .line 425
    .line 426
    move-result v0

    .line 427
    int-to-double v0, v0

    .line 428
    const-wide v4, 0x40767a6000000000L    # 359.6484375

    .line 429
    .line 430
    .line 431
    .line 432
    .line 433
    mul-double/2addr v0, v4

    .line 434
    const/16 v4, 0x3ff

    .line 435
    .line 436
    int-to-double v4, v4

    .line 437
    div-double/2addr v0, v4

    .line 438
    const-wide v4, 0x400921fb54442d18L    # Math.PI

    .line 439
    .line 440
    .line 441
    .line 442
    .line 443
    mul-double/2addr v0, v4

    .line 444
    const/16 v4, 0xb4

    .line 445
    .line 446
    int-to-double v4, v4

    .line 447
    div-double/2addr v0, v4

    .line 448
    invoke-direct {v9, v10, v0, v1}, Lw71/b;-><init>(Lw71/c;D)V

    .line 449
    .line 450
    .line 451
    move-object v4, v3

    .line 452
    move v3, v7

    .line 453
    move-object v1, v8

    .line 454
    move-object v5, v9

    .line 455
    invoke-direct/range {v1 .. v6}, Lq81/b;-><init>(IZLs71/o;Lw71/b;Ljava/util/List;)V

    .line 456
    .line 457
    .line 458
    return-object v1

    .line 459
    :pswitch_data_0
    .packed-switch 0x1
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

.method public static varargs b([Ljava/lang/String;)Ld01/y;
    .locals 6

    .line 1
    array-length v0, p0

    .line 2
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    check-cast p0, [Ljava/lang/String;

    .line 7
    .line 8
    const-string v0, "inputNamesAndValues"

    .line 9
    .line 10
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    array-length v0, p0

    .line 14
    const/4 v1, 0x2

    .line 15
    rem-int/2addr v0, v1

    .line 16
    if-nez v0, :cond_3

    .line 17
    .line 18
    array-length v0, p0

    .line 19
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, [Ljava/lang/String;

    .line 24
    .line 25
    array-length v2, v0

    .line 26
    const/4 v3, 0x0

    .line 27
    move v4, v3

    .line 28
    :goto_0
    if-ge v4, v2, :cond_1

    .line 29
    .line 30
    aget-object v5, v0, v4

    .line 31
    .line 32
    if-eqz v5, :cond_0

    .line 33
    .line 34
    aget-object v5, p0, v4

    .line 35
    .line 36
    invoke-static {v5}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    invoke-virtual {v5}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v5

    .line 44
    aput-object v5, v0, v4

    .line 45
    .line 46
    add-int/lit8 v4, v4, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 50
    .line 51
    const-string v0, "Headers cannot be null"

    .line 52
    .line 53
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_1
    array-length p0, v0

    .line 58
    add-int/lit8 p0, p0, -0x1

    .line 59
    .line 60
    invoke-static {v3, p0, v1}, Llp/o0;->b(III)I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    if-ltz p0, :cond_2

    .line 65
    .line 66
    :goto_1
    aget-object v1, v0, v3

    .line 67
    .line 68
    add-int/lit8 v2, v3, 0x1

    .line 69
    .line 70
    aget-object v2, v0, v2

    .line 71
    .line 72
    invoke-static {v1}, Ljp/yg;->j(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-static {v2, v1}, Ljp/yg;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    if-eq v3, p0, :cond_2

    .line 79
    .line 80
    add-int/lit8 v3, v3, 0x2

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_2
    new-instance p0, Ld01/y;

    .line 84
    .line 85
    invoke-direct {p0, v0}, Ld01/y;-><init>([Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    return-object p0

    .line 89
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 90
    .line 91
    const-string v0, "Expected alternating header names and values"

    .line 92
    .line 93
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0
.end method

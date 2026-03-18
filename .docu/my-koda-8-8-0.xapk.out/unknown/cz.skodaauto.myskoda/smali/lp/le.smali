.class public abstract Llp/le;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(La21/d;[Lhy0/d;)V
    .locals 9

    .line 1
    iget-object v0, p0, La21/d;->b:Lc21/b;

    .line 2
    .line 3
    iget-object v1, v0, Lc21/b;->a:La21/a;

    .line 4
    .line 5
    iget-object v2, v1, La21/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Ljava/util/Collection;

    .line 8
    .line 9
    new-instance v3, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    array-length v5, p1

    .line 16
    add-int/2addr v4, v5

    .line 17
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 21
    .line 22
    .line 23
    invoke-static {v3, p1}, Lmx0/q;->x(Ljava/util/AbstractList;[Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iput-object v3, v1, La21/a;->f:Ljava/lang/Object;

    .line 27
    .line 28
    array-length v2, p1

    .line 29
    const/4 v3, 0x0

    .line 30
    :goto_0
    if-ge v3, v2, :cond_2

    .line 31
    .line 32
    aget-object v4, p1, v3

    .line 33
    .line 34
    iget-object v5, v1, La21/a;->c:Lh21/a;

    .line 35
    .line 36
    iget-object v6, v1, La21/a;->a:Lh21/a;

    .line 37
    .line 38
    new-instance v7, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 41
    .line 42
    .line 43
    const/16 v8, 0x3a

    .line 44
    .line 45
    invoke-static {v4, v7, v8}, Lia/b;->s(Lhy0/d;Ljava/lang/StringBuilder;C)V

    .line 46
    .line 47
    .line 48
    if-eqz v5, :cond_0

    .line 49
    .line 50
    invoke-interface {v5}, Lh21/a;->getValue()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    if-nez v4, :cond_1

    .line 55
    .line 56
    :cond_0
    const-string v4, ""

    .line 57
    .line 58
    :cond_1
    invoke-static {v7, v4, v8, v6}, Lia/b;->h(Ljava/lang/StringBuilder;Ljava/lang/String;CLh21/a;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    iget-object v5, p0, La21/d;->a:Le21/a;

    .line 63
    .line 64
    invoke-virtual {v5, v4, v0}, Le21/a;->b(Ljava/lang/String;Lc21/b;)V

    .line 65
    .line 66
    .line 67
    add-int/lit8 v3, v3, 0x1

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    return-void
.end method

.method public static final b(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;)Lx81/b;
    .locals 26

    .line 1
    if-eqz p1, :cond_c

    .line 2
    .line 3
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajTransId()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->getParkingTrajTransId()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-ne v0, v1, :cond_c

    .line 12
    .line 13
    new-instance v8, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajNumberPoints()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v1, 0x1

    .line 23
    sub-int/2addr v0, v1

    .line 24
    new-instance v2, Lgy0/j;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    invoke-direct {v2, v3, v0, v1}, Lgy0/h;-><init>(III)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v2}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    :goto_0
    move-object v2, v0

    .line 39
    check-cast v2, Lgy0/i;

    .line 40
    .line 41
    iget-boolean v2, v2, Lgy0/i;->f:Z

    .line 42
    .line 43
    const/16 v5, 0xb4

    .line 44
    .line 45
    const-wide v13, -0x3f20004000000000L    # -32767.0

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    const-wide/high16 v15, 0x40e0000000000000L    # 32768.0

    .line 51
    .line 52
    const/16 v3, 0x64

    .line 53
    .line 54
    if-eqz v2, :cond_3

    .line 55
    .line 56
    move-object v2, v0

    .line 57
    check-cast v2, Lmx0/w;

    .line 58
    .line 59
    invoke-virtual {v2}, Lmx0/w;->nextInt()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    packed-switch v2, :pswitch_data_0

    .line 64
    .line 65
    .line 66
    new-instance v2, Llx0/r;

    .line 67
    .line 68
    invoke-direct {v2, v4, v4, v4}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 72
    .line 73
    .line 74
    .line 75
    .line 76
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 77
    .line 78
    .line 79
    .line 80
    .line 81
    goto/16 :goto_1

    .line 82
    .line 83
    :pswitch_0
    new-instance v2, Llx0/r;

    .line 84
    .line 85
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP19PosX()I

    .line 86
    .line 87
    .line 88
    move-result v17

    .line 89
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 90
    .line 91
    .line 92
    .line 93
    .line 94
    invoke-static/range {v17 .. v17}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 95
    .line 96
    .line 97
    move-result-object v6

    .line 98
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP19PosY()I

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 103
    .line 104
    .line 105
    move-result-object v7

    .line 106
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP19Tan()I

    .line 107
    .line 108
    .line 109
    move-result v17

    .line 110
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 111
    .line 112
    .line 113
    .line 114
    .line 115
    invoke-static/range {v17 .. v17}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v9

    .line 119
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    goto/16 :goto_1

    .line 123
    .line 124
    :pswitch_1
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 125
    .line 126
    .line 127
    .line 128
    .line 129
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 130
    .line 131
    .line 132
    .line 133
    .line 134
    new-instance v2, Llx0/r;

    .line 135
    .line 136
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP18PosX()I

    .line 137
    .line 138
    .line 139
    move-result v6

    .line 140
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 141
    .line 142
    .line 143
    move-result-object v6

    .line 144
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP18PosY()I

    .line 145
    .line 146
    .line 147
    move-result v7

    .line 148
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 149
    .line 150
    .line 151
    move-result-object v7

    .line 152
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP18Tan()I

    .line 153
    .line 154
    .line 155
    move-result v9

    .line 156
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 157
    .line 158
    .line 159
    move-result-object v9

    .line 160
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    goto/16 :goto_1

    .line 164
    .line 165
    :pswitch_2
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 166
    .line 167
    .line 168
    .line 169
    .line 170
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 171
    .line 172
    .line 173
    .line 174
    .line 175
    new-instance v2, Llx0/r;

    .line 176
    .line 177
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP17PosX()I

    .line 178
    .line 179
    .line 180
    move-result v6

    .line 181
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 182
    .line 183
    .line 184
    move-result-object v6

    .line 185
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP17PosY()I

    .line 186
    .line 187
    .line 188
    move-result v7

    .line 189
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 190
    .line 191
    .line 192
    move-result-object v7

    .line 193
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP17Tan()I

    .line 194
    .line 195
    .line 196
    move-result v9

    .line 197
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 198
    .line 199
    .line 200
    move-result-object v9

    .line 201
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    goto/16 :goto_1

    .line 205
    .line 206
    :pswitch_3
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 207
    .line 208
    .line 209
    .line 210
    .line 211
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 212
    .line 213
    .line 214
    .line 215
    .line 216
    new-instance v2, Llx0/r;

    .line 217
    .line 218
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP16PosX()I

    .line 219
    .line 220
    .line 221
    move-result v6

    .line 222
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 223
    .line 224
    .line 225
    move-result-object v6

    .line 226
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP16PosY()I

    .line 227
    .line 228
    .line 229
    move-result v7

    .line 230
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 231
    .line 232
    .line 233
    move-result-object v7

    .line 234
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP16Tan()I

    .line 235
    .line 236
    .line 237
    move-result v9

    .line 238
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 239
    .line 240
    .line 241
    move-result-object v9

    .line 242
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    goto/16 :goto_1

    .line 246
    .line 247
    :pswitch_4
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 248
    .line 249
    .line 250
    .line 251
    .line 252
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 253
    .line 254
    .line 255
    .line 256
    .line 257
    new-instance v2, Llx0/r;

    .line 258
    .line 259
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP15PosX()I

    .line 260
    .line 261
    .line 262
    move-result v6

    .line 263
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 264
    .line 265
    .line 266
    move-result-object v6

    .line 267
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP15PosY()I

    .line 268
    .line 269
    .line 270
    move-result v7

    .line 271
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 272
    .line 273
    .line 274
    move-result-object v7

    .line 275
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP15Tan()I

    .line 276
    .line 277
    .line 278
    move-result v9

    .line 279
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 280
    .line 281
    .line 282
    move-result-object v9

    .line 283
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    goto/16 :goto_1

    .line 287
    .line 288
    :pswitch_5
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 289
    .line 290
    .line 291
    .line 292
    .line 293
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 294
    .line 295
    .line 296
    .line 297
    .line 298
    new-instance v2, Llx0/r;

    .line 299
    .line 300
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP14PosX()I

    .line 301
    .line 302
    .line 303
    move-result v6

    .line 304
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 305
    .line 306
    .line 307
    move-result-object v6

    .line 308
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP14PosY()I

    .line 309
    .line 310
    .line 311
    move-result v7

    .line 312
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 313
    .line 314
    .line 315
    move-result-object v7

    .line 316
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP14Tan()I

    .line 317
    .line 318
    .line 319
    move-result v9

    .line 320
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 321
    .line 322
    .line 323
    move-result-object v9

    .line 324
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 325
    .line 326
    .line 327
    goto/16 :goto_1

    .line 328
    .line 329
    :pswitch_6
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 330
    .line 331
    .line 332
    .line 333
    .line 334
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 335
    .line 336
    .line 337
    .line 338
    .line 339
    new-instance v2, Llx0/r;

    .line 340
    .line 341
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP13PosX()I

    .line 342
    .line 343
    .line 344
    move-result v6

    .line 345
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 346
    .line 347
    .line 348
    move-result-object v6

    .line 349
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP13PosY()I

    .line 350
    .line 351
    .line 352
    move-result v7

    .line 353
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 354
    .line 355
    .line 356
    move-result-object v7

    .line 357
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP13Tan()I

    .line 358
    .line 359
    .line 360
    move-result v9

    .line 361
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 362
    .line 363
    .line 364
    move-result-object v9

    .line 365
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 366
    .line 367
    .line 368
    goto/16 :goto_1

    .line 369
    .line 370
    :pswitch_7
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 371
    .line 372
    .line 373
    .line 374
    .line 375
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 376
    .line 377
    .line 378
    .line 379
    .line 380
    new-instance v2, Llx0/r;

    .line 381
    .line 382
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP12PosX()I

    .line 383
    .line 384
    .line 385
    move-result v6

    .line 386
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 387
    .line 388
    .line 389
    move-result-object v6

    .line 390
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP12PosY()I

    .line 391
    .line 392
    .line 393
    move-result v7

    .line 394
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 395
    .line 396
    .line 397
    move-result-object v7

    .line 398
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP12Tan()I

    .line 399
    .line 400
    .line 401
    move-result v9

    .line 402
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 403
    .line 404
    .line 405
    move-result-object v9

    .line 406
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 407
    .line 408
    .line 409
    goto/16 :goto_1

    .line 410
    .line 411
    :pswitch_8
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 412
    .line 413
    .line 414
    .line 415
    .line 416
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 417
    .line 418
    .line 419
    .line 420
    .line 421
    new-instance v2, Llx0/r;

    .line 422
    .line 423
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP11PosX()I

    .line 424
    .line 425
    .line 426
    move-result v6

    .line 427
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 428
    .line 429
    .line 430
    move-result-object v6

    .line 431
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP11PosY()I

    .line 432
    .line 433
    .line 434
    move-result v7

    .line 435
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 436
    .line 437
    .line 438
    move-result-object v7

    .line 439
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP11Tan()I

    .line 440
    .line 441
    .line 442
    move-result v9

    .line 443
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 444
    .line 445
    .line 446
    move-result-object v9

    .line 447
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 448
    .line 449
    .line 450
    goto/16 :goto_1

    .line 451
    .line 452
    :pswitch_9
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 453
    .line 454
    .line 455
    .line 456
    .line 457
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 458
    .line 459
    .line 460
    .line 461
    .line 462
    new-instance v2, Llx0/r;

    .line 463
    .line 464
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP10PosX()I

    .line 465
    .line 466
    .line 467
    move-result v6

    .line 468
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 469
    .line 470
    .line 471
    move-result-object v6

    .line 472
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP10PosY()I

    .line 473
    .line 474
    .line 475
    move-result v7

    .line 476
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 477
    .line 478
    .line 479
    move-result-object v7

    .line 480
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP10Tan()I

    .line 481
    .line 482
    .line 483
    move-result v9

    .line 484
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 485
    .line 486
    .line 487
    move-result-object v9

    .line 488
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 489
    .line 490
    .line 491
    goto/16 :goto_1

    .line 492
    .line 493
    :pswitch_a
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 494
    .line 495
    .line 496
    .line 497
    .line 498
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 499
    .line 500
    .line 501
    .line 502
    .line 503
    new-instance v2, Llx0/r;

    .line 504
    .line 505
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP9PosX()I

    .line 506
    .line 507
    .line 508
    move-result v6

    .line 509
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 510
    .line 511
    .line 512
    move-result-object v6

    .line 513
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP9PosY()I

    .line 514
    .line 515
    .line 516
    move-result v7

    .line 517
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 518
    .line 519
    .line 520
    move-result-object v7

    .line 521
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP9Tan()I

    .line 522
    .line 523
    .line 524
    move-result v9

    .line 525
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 526
    .line 527
    .line 528
    move-result-object v9

    .line 529
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 530
    .line 531
    .line 532
    goto/16 :goto_1

    .line 533
    .line 534
    :pswitch_b
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 535
    .line 536
    .line 537
    .line 538
    .line 539
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 540
    .line 541
    .line 542
    .line 543
    .line 544
    new-instance v2, Llx0/r;

    .line 545
    .line 546
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP8PosX()I

    .line 547
    .line 548
    .line 549
    move-result v6

    .line 550
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 551
    .line 552
    .line 553
    move-result-object v6

    .line 554
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP8PosY()I

    .line 555
    .line 556
    .line 557
    move-result v7

    .line 558
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 559
    .line 560
    .line 561
    move-result-object v7

    .line 562
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP8Tan()I

    .line 563
    .line 564
    .line 565
    move-result v9

    .line 566
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 567
    .line 568
    .line 569
    move-result-object v9

    .line 570
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 571
    .line 572
    .line 573
    goto/16 :goto_1

    .line 574
    .line 575
    :pswitch_c
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 576
    .line 577
    .line 578
    .line 579
    .line 580
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 581
    .line 582
    .line 583
    .line 584
    .line 585
    new-instance v2, Llx0/r;

    .line 586
    .line 587
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP7PosX()I

    .line 588
    .line 589
    .line 590
    move-result v6

    .line 591
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 592
    .line 593
    .line 594
    move-result-object v6

    .line 595
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP7PosY()I

    .line 596
    .line 597
    .line 598
    move-result v7

    .line 599
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 600
    .line 601
    .line 602
    move-result-object v7

    .line 603
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP7Tan()I

    .line 604
    .line 605
    .line 606
    move-result v9

    .line 607
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 608
    .line 609
    .line 610
    move-result-object v9

    .line 611
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 612
    .line 613
    .line 614
    goto/16 :goto_1

    .line 615
    .line 616
    :pswitch_d
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 617
    .line 618
    .line 619
    .line 620
    .line 621
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 622
    .line 623
    .line 624
    .line 625
    .line 626
    new-instance v2, Llx0/r;

    .line 627
    .line 628
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP6PosX()I

    .line 629
    .line 630
    .line 631
    move-result v6

    .line 632
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 633
    .line 634
    .line 635
    move-result-object v6

    .line 636
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP6PosY()I

    .line 637
    .line 638
    .line 639
    move-result v7

    .line 640
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 641
    .line 642
    .line 643
    move-result-object v7

    .line 644
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP6Tan()I

    .line 645
    .line 646
    .line 647
    move-result v9

    .line 648
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 649
    .line 650
    .line 651
    move-result-object v9

    .line 652
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 653
    .line 654
    .line 655
    goto/16 :goto_1

    .line 656
    .line 657
    :pswitch_e
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 658
    .line 659
    .line 660
    .line 661
    .line 662
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 663
    .line 664
    .line 665
    .line 666
    .line 667
    new-instance v2, Llx0/r;

    .line 668
    .line 669
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP5PosX()I

    .line 670
    .line 671
    .line 672
    move-result v6

    .line 673
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 674
    .line 675
    .line 676
    move-result-object v6

    .line 677
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP5PosY()I

    .line 678
    .line 679
    .line 680
    move-result v7

    .line 681
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 682
    .line 683
    .line 684
    move-result-object v7

    .line 685
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP5Tan()I

    .line 686
    .line 687
    .line 688
    move-result v9

    .line 689
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 690
    .line 691
    .line 692
    move-result-object v9

    .line 693
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 694
    .line 695
    .line 696
    goto/16 :goto_1

    .line 697
    .line 698
    :pswitch_f
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 699
    .line 700
    .line 701
    .line 702
    .line 703
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 704
    .line 705
    .line 706
    .line 707
    .line 708
    new-instance v2, Llx0/r;

    .line 709
    .line 710
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP4PosX()I

    .line 711
    .line 712
    .line 713
    move-result v6

    .line 714
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 715
    .line 716
    .line 717
    move-result-object v6

    .line 718
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP4PosY()I

    .line 719
    .line 720
    .line 721
    move-result v7

    .line 722
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 723
    .line 724
    .line 725
    move-result-object v7

    .line 726
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP4Tan()I

    .line 727
    .line 728
    .line 729
    move-result v9

    .line 730
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 731
    .line 732
    .line 733
    move-result-object v9

    .line 734
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 735
    .line 736
    .line 737
    goto/16 :goto_1

    .line 738
    .line 739
    :pswitch_10
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 740
    .line 741
    .line 742
    .line 743
    .line 744
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 745
    .line 746
    .line 747
    .line 748
    .line 749
    new-instance v2, Llx0/r;

    .line 750
    .line 751
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP3PosX()I

    .line 752
    .line 753
    .line 754
    move-result v6

    .line 755
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 756
    .line 757
    .line 758
    move-result-object v6

    .line 759
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP3PosY()I

    .line 760
    .line 761
    .line 762
    move-result v7

    .line 763
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 764
    .line 765
    .line 766
    move-result-object v7

    .line 767
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP3Tan()I

    .line 768
    .line 769
    .line 770
    move-result v9

    .line 771
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 772
    .line 773
    .line 774
    move-result-object v9

    .line 775
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 776
    .line 777
    .line 778
    goto :goto_1

    .line 779
    :pswitch_11
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 780
    .line 781
    .line 782
    .line 783
    .line 784
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 785
    .line 786
    .line 787
    .line 788
    .line 789
    new-instance v2, Llx0/r;

    .line 790
    .line 791
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP2PosX()I

    .line 792
    .line 793
    .line 794
    move-result v6

    .line 795
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 796
    .line 797
    .line 798
    move-result-object v6

    .line 799
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP2PosY()I

    .line 800
    .line 801
    .line 802
    move-result v7

    .line 803
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 804
    .line 805
    .line 806
    move-result-object v7

    .line 807
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP2Tan()I

    .line 808
    .line 809
    .line 810
    move-result v9

    .line 811
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 812
    .line 813
    .line 814
    move-result-object v9

    .line 815
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 816
    .line 817
    .line 818
    goto :goto_1

    .line 819
    :pswitch_12
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 820
    .line 821
    .line 822
    .line 823
    .line 824
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 825
    .line 826
    .line 827
    .line 828
    .line 829
    new-instance v2, Llx0/r;

    .line 830
    .line 831
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP1PosX()I

    .line 832
    .line 833
    .line 834
    move-result v6

    .line 835
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 836
    .line 837
    .line 838
    move-result-object v6

    .line 839
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP1PosY()I

    .line 840
    .line 841
    .line 842
    move-result v7

    .line 843
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 844
    .line 845
    .line 846
    move-result-object v7

    .line 847
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP1Tan()I

    .line 848
    .line 849
    .line 850
    move-result v9

    .line 851
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 852
    .line 853
    .line 854
    move-result-object v9

    .line 855
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 856
    .line 857
    .line 858
    goto :goto_1

    .line 859
    :pswitch_13
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 860
    .line 861
    .line 862
    .line 863
    .line 864
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 865
    .line 866
    .line 867
    .line 868
    .line 869
    new-instance v2, Llx0/r;

    .line 870
    .line 871
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP0PosX()I

    .line 872
    .line 873
    .line 874
    move-result v6

    .line 875
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 876
    .line 877
    .line 878
    move-result-object v6

    .line 879
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP0PosY()I

    .line 880
    .line 881
    .line 882
    move-result v7

    .line 883
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 884
    .line 885
    .line 886
    move-result-object v7

    .line 887
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajP0Tan()I

    .line 888
    .line 889
    .line 890
    move-result v9

    .line 891
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 892
    .line 893
    .line 894
    move-result-object v9

    .line 895
    invoke-direct {v2, v6, v7, v9}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 896
    .line 897
    .line 898
    :goto_1
    iget-object v6, v2, Llx0/r;->d:Ljava/lang/Object;

    .line 899
    .line 900
    check-cast v6, Ljava/lang/Number;

    .line 901
    .line 902
    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    .line 903
    .line 904
    .line 905
    move-result v6

    .line 906
    iget-object v7, v2, Llx0/r;->e:Ljava/lang/Object;

    .line 907
    .line 908
    check-cast v7, Ljava/lang/Number;

    .line 909
    .line 910
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 911
    .line 912
    .line 913
    move-result v7

    .line 914
    iget-object v2, v2, Llx0/r;->f:Ljava/lang/Object;

    .line 915
    .line 916
    check-cast v2, Ljava/lang/Number;

    .line 917
    .line 918
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 919
    .line 920
    .line 921
    move-result v2

    .line 922
    new-instance v9, Lw71/b;

    .line 923
    .line 924
    new-instance v10, Lw71/c;

    .line 925
    .line 926
    const-wide v22, 0x3f76800000000000L    # 0.0054931640625

    .line 927
    .line 928
    .line 929
    .line 930
    .line 931
    int-to-double v11, v6

    .line 932
    if-ltz v6, :cond_0

    .line 933
    .line 934
    add-double/2addr v11, v13

    .line 935
    :goto_2
    move-wide/from16 v24, v13

    .line 936
    .line 937
    goto :goto_3

    .line 938
    :cond_0
    add-double/2addr v11, v15

    .line 939
    goto :goto_2

    .line 940
    :goto_3
    int-to-double v13, v3

    .line 941
    div-double/2addr v11, v13

    .line 942
    if-ltz v7, :cond_1

    .line 943
    .line 944
    int-to-double v6, v7

    .line 945
    add-double v6, v6, v24

    .line 946
    .line 947
    goto :goto_4

    .line 948
    :cond_1
    int-to-double v6, v7

    .line 949
    add-double/2addr v6, v15

    .line 950
    :goto_4
    div-double/2addr v6, v13

    .line 951
    invoke-direct {v10, v11, v12, v6, v7}, Lw71/c;-><init>(DD)V

    .line 952
    .line 953
    .line 954
    int-to-double v6, v2

    .line 955
    mul-double v6, v6, v22

    .line 956
    .line 957
    if-ltz v2, :cond_2

    .line 958
    .line 959
    goto :goto_5

    .line 960
    :cond_2
    add-double v6, v6, v20

    .line 961
    .line 962
    :goto_5
    mul-double v6, v6, v18

    .line 963
    .line 964
    int-to-double v2, v5

    .line 965
    div-double/2addr v6, v2

    .line 966
    invoke-direct {v9, v10, v6, v7}, Lw71/b;-><init>(Lw71/c;D)V

    .line 967
    .line 968
    .line 969
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 970
    .line 971
    .line 972
    const/4 v3, 0x0

    .line 973
    goto/16 :goto_0

    .line 974
    .line 975
    :cond_3
    move-wide/from16 v24, v13

    .line 976
    .line 977
    const-wide v18, 0x400921fb54442d18L    # Math.PI

    .line 978
    .line 979
    .line 980
    .line 981
    .line 982
    const-wide v20, 0x4076800000000000L    # 360.0

    .line 983
    .line 984
    .line 985
    .line 986
    .line 987
    const-wide v22, 0x3f76800000000000L    # 0.0054931640625

    .line 988
    .line 989
    .line 990
    .line 991
    .line 992
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajTransId()I

    .line 993
    .line 994
    .line 995
    move-result v7

    .line 996
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 997
    .line 998
    .line 999
    move-result v0

    .line 1000
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->getParkingTrajLatestMove()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryLastMovePPE;

    .line 1001
    .line 1002
    .line 1003
    move-result-object v2

    .line 1004
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryLastMovePPE;->TARGET_POINT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryLastMovePPE;

    .line 1005
    .line 1006
    if-ne v2, v4, :cond_4

    .line 1007
    .line 1008
    move v4, v1

    .line 1009
    goto :goto_6

    .line 1010
    :cond_4
    const/4 v4, 0x0

    .line 1011
    :goto_6
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->getParkingTrajDrivingDirection()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 1012
    .line 1013
    .line 1014
    move-result-object v2

    .line 1015
    const-string v6, "<this>"

    .line 1016
    .line 1017
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1018
    .line 1019
    .line 1020
    sget-object v6, Ly81/a;->e:[I

    .line 1021
    .line 1022
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 1023
    .line 1024
    .line 1025
    move-result v2

    .line 1026
    aget v2, v6, v2

    .line 1027
    .line 1028
    if-eq v2, v1, :cond_8

    .line 1029
    .line 1030
    const/4 v1, 0x2

    .line 1031
    if-eq v2, v1, :cond_7

    .line 1032
    .line 1033
    const/4 v1, 0x3

    .line 1034
    if-eq v2, v1, :cond_6

    .line 1035
    .line 1036
    const/4 v1, 0x4

    .line 1037
    if-ne v2, v1, :cond_5

    .line 1038
    .line 1039
    sget-object v1, Ls71/o;->g:Ls71/o;

    .line 1040
    .line 1041
    goto :goto_7

    .line 1042
    :cond_5
    new-instance v0, La8/r0;

    .line 1043
    .line 1044
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1045
    .line 1046
    .line 1047
    throw v0

    .line 1048
    :cond_6
    sget-object v1, Ls71/o;->f:Ls71/o;

    .line 1049
    .line 1050
    goto :goto_7

    .line 1051
    :cond_7
    sget-object v1, Ls71/o;->e:Ls71/o;

    .line 1052
    .line 1053
    goto :goto_7

    .line 1054
    :cond_8
    sget-object v1, Ls71/o;->d:Ls71/o;

    .line 1055
    .line 1056
    :goto_7
    new-instance v6, Lw71/b;

    .line 1057
    .line 1058
    new-instance v2, Lw71/c;

    .line 1059
    .line 1060
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->getParkingTrajVehiclePosX()I

    .line 1061
    .line 1062
    .line 1063
    move-result v9

    .line 1064
    if-ltz v9, :cond_9

    .line 1065
    .line 1066
    int-to-double v9, v9

    .line 1067
    add-double v9, v9, v24

    .line 1068
    .line 1069
    goto :goto_8

    .line 1070
    :cond_9
    int-to-double v9, v9

    .line 1071
    add-double/2addr v9, v15

    .line 1072
    :goto_8
    int-to-double v11, v3

    .line 1073
    div-double/2addr v9, v11

    .line 1074
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->getParkingTrajVehiclePosY()I

    .line 1075
    .line 1076
    .line 1077
    move-result v3

    .line 1078
    int-to-double v13, v3

    .line 1079
    if-ltz v3, :cond_a

    .line 1080
    .line 1081
    add-double v13, v13, v24

    .line 1082
    .line 1083
    goto :goto_9

    .line 1084
    :cond_a
    add-double/2addr v13, v15

    .line 1085
    :goto_9
    div-double/2addr v13, v11

    .line 1086
    invoke-direct {v2, v9, v10, v13, v14}, Lw71/c;-><init>(DD)V

    .line 1087
    .line 1088
    .line 1089
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->getParkingTrajVehicleAngle()I

    .line 1090
    .line 1091
    .line 1092
    move-result v3

    .line 1093
    int-to-double v9, v3

    .line 1094
    mul-double v9, v9, v22

    .line 1095
    .line 1096
    if-ltz v3, :cond_b

    .line 1097
    .line 1098
    goto :goto_a

    .line 1099
    :cond_b
    add-double v9, v9, v20

    .line 1100
    .line 1101
    :goto_a
    mul-double v9, v9, v18

    .line 1102
    .line 1103
    int-to-double v11, v5

    .line 1104
    div-double/2addr v9, v11

    .line 1105
    invoke-direct {v6, v2, v9, v10}, Lw71/b;-><init>(Lw71/c;D)V

    .line 1106
    .line 1107
    .line 1108
    new-instance v2, Lx81/b;

    .line 1109
    .line 1110
    move v3, v0

    .line 1111
    move-object v5, v1

    .line 1112
    invoke-direct/range {v2 .. v8}, Lx81/b;-><init>(IZLs71/o;Lw71/b;ILjava/util/ArrayList;)V

    .line 1113
    .line 1114
    .line 1115
    return-object v2

    .line 1116
    :cond_c
    const/4 v0, 0x0

    .line 1117
    return-object v0

    .line 1118
    nop

    .line 1119
    :pswitch_data_0
    .packed-switch 0x0
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

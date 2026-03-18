.class public final synthetic Lac0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Lac0/r;->d:I

    iput-object p1, p0, Lac0/r;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ILjava/lang/Object;)V
    .locals 0

    .line 2
    iput p2, p0, Lac0/r;->d:I

    iput-object p1, p0, Lac0/r;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 40

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lac0/r;->d:I

    .line 4
    .line 5
    const-string v2, "exception"

    .line 6
    .line 7
    const-string v3, "service_label"

    .line 8
    .line 9
    const-string v4, "id"

    .line 10
    .line 11
    const-string v5, "$this$log"

    .line 12
    .line 13
    const-string v6, "$this$sdkViewModel"

    .line 14
    .line 15
    const-string v8, "average_gas_consumption"

    .line 16
    .line 17
    const-string v9, "average_electric_consumption"

    .line 18
    .line 19
    const-string v10, "average_fuel_consumption"

    .line 20
    .line 21
    const-string v11, "end_mileage"

    .line 22
    .line 23
    const-string v12, "vehicle_type"

    .line 24
    .line 25
    const-string v13, "SELECT * FROM trips_overview WHERE vin = ? LIMIT 1"

    .line 26
    .line 27
    const-string v14, "value"

    .line 28
    .line 29
    const-string v15, "type"

    .line 30
    .line 31
    const-string v7, "SELECT * FROM token WHERE type is ? LIMIT 1"

    .line 32
    .line 33
    move/from16 v17, v1

    .line 34
    .line 35
    const-string v1, "vin"

    .line 36
    .line 37
    move-object/from16 v18, v2

    .line 38
    .line 39
    const-string v2, "_connection"

    .line 40
    .line 41
    move-object/from16 v21, v3

    .line 42
    .line 43
    const/4 v3, 0x1

    .line 44
    sget-object v22, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    iget-object v0, v0, Lac0/r;->e:Ljava/lang/String;

    .line 47
    .line 48
    packed-switch v17, :pswitch_data_0

    .line 49
    .line 50
    .line 51
    move-object/from16 v1, p1

    .line 52
    .line 53
    check-cast v1, Lua/a;

    .line 54
    .line 55
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const-string v2, "DELETE FROM token WHERE type is ?"

    .line 59
    .line 60
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    :try_start_0
    invoke-interface {v1, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 68
    .line 69
    .line 70
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 71
    .line 72
    .line 73
    return-object v22

    .line 74
    :catchall_0
    move-exception v0

    .line 75
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 76
    .line 77
    .line 78
    throw v0

    .line 79
    :pswitch_0
    move-object/from16 v1, p1

    .line 80
    .line 81
    check-cast v1, Lua/a;

    .line 82
    .line 83
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-interface {v1, v7}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    :try_start_1
    invoke-interface {v1, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    if-eqz v3, :cond_0

    .line 106
    .line 107
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    new-instance v3, Lic0/f;

    .line 116
    .line 117
    invoke-direct {v3, v0, v2}, Lic0/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 118
    .line 119
    .line 120
    move-object v2, v3

    .line 121
    goto :goto_0

    .line 122
    :catchall_1
    move-exception v0

    .line 123
    goto :goto_1

    .line 124
    :cond_0
    const/4 v2, 0x0

    .line 125
    :goto_0
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 126
    .line 127
    .line 128
    return-object v2

    .line 129
    :goto_1
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 130
    .line 131
    .line 132
    throw v0

    .line 133
    :pswitch_1
    move-object/from16 v1, p1

    .line 134
    .line 135
    check-cast v1, Lua/a;

    .line 136
    .line 137
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    invoke-interface {v1, v7}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    :try_start_2
    invoke-interface {v1, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 152
    .line 153
    .line 154
    move-result v2

    .line 155
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    if-eqz v3, :cond_1

    .line 160
    .line 161
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v2

    .line 169
    new-instance v3, Lic0/f;

    .line 170
    .line 171
    invoke-direct {v3, v0, v2}, Lic0/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 172
    .line 173
    .line 174
    move-object v2, v3

    .line 175
    goto :goto_2

    .line 176
    :catchall_2
    move-exception v0

    .line 177
    goto :goto_3

    .line 178
    :cond_1
    const/4 v2, 0x0

    .line 179
    :goto_2
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 180
    .line 181
    .line 182
    return-object v2

    .line 183
    :goto_3
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 184
    .line 185
    .line 186
    throw v0

    .line 187
    :pswitch_2
    move-object/from16 v4, p1

    .line 188
    .line 189
    check-cast v4, Lua/a;

    .line 190
    .line 191
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    invoke-interface {v4, v13}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    :try_start_3
    invoke-interface {v2, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 199
    .line 200
    .line 201
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 202
    .line 203
    .line 204
    move-result v0

    .line 205
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 206
    .line 207
    .line 208
    move-result v1

    .line 209
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 210
    .line 211
    .line 212
    move-result v3

    .line 213
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 214
    .line 215
    .line 216
    move-result v4

    .line 217
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 218
    .line 219
    .line 220
    move-result v5

    .line 221
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 222
    .line 223
    .line 224
    move-result v6

    .line 225
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 226
    .line 227
    .line 228
    move-result v7

    .line 229
    if-eqz v7, :cond_6

    .line 230
    .line 231
    invoke-interface {v2, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v9

    .line 235
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v10

    .line 239
    invoke-interface {v2, v3}, Lua/c;->isNull(I)Z

    .line 240
    .line 241
    .line 242
    move-result v0

    .line 243
    if-eqz v0, :cond_2

    .line 244
    .line 245
    const/4 v11, 0x0

    .line 246
    goto :goto_4

    .line 247
    :cond_2
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 248
    .line 249
    .line 250
    move-result-wide v0

    .line 251
    long-to-int v0, v0

    .line 252
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    move-object v11, v0

    .line 257
    :goto_4
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 258
    .line 259
    .line 260
    move-result v0

    .line 261
    if-eqz v0, :cond_3

    .line 262
    .line 263
    const/4 v12, 0x0

    .line 264
    goto :goto_5

    .line 265
    :cond_3
    invoke-interface {v2, v4}, Lua/c;->getDouble(I)D

    .line 266
    .line 267
    .line 268
    move-result-wide v0

    .line 269
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    move-object v12, v0

    .line 274
    :goto_5
    invoke-interface {v2, v5}, Lua/c;->isNull(I)Z

    .line 275
    .line 276
    .line 277
    move-result v0

    .line 278
    if-eqz v0, :cond_4

    .line 279
    .line 280
    const/4 v13, 0x0

    .line 281
    goto :goto_6

    .line 282
    :cond_4
    invoke-interface {v2, v5}, Lua/c;->getDouble(I)D

    .line 283
    .line 284
    .line 285
    move-result-wide v0

    .line 286
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    move-object v13, v0

    .line 291
    :goto_6
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 292
    .line 293
    .line 294
    move-result v0

    .line 295
    if-eqz v0, :cond_5

    .line 296
    .line 297
    const/4 v14, 0x0

    .line 298
    goto :goto_7

    .line 299
    :cond_5
    invoke-interface {v2, v6}, Lua/c;->getDouble(I)D

    .line 300
    .line 301
    .line 302
    move-result-wide v0

    .line 303
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    move-object v14, v0

    .line 308
    :goto_7
    new-instance v8, Li70/g0;

    .line 309
    .line 310
    invoke-direct/range {v8 .. v14}, Li70/g0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 311
    .line 312
    .line 313
    move-object/from16 v20, v8

    .line 314
    .line 315
    goto :goto_8

    .line 316
    :catchall_3
    move-exception v0

    .line 317
    goto :goto_9

    .line 318
    :cond_6
    const/16 v20, 0x0

    .line 319
    .line 320
    :goto_8
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 321
    .line 322
    .line 323
    return-object v20

    .line 324
    :goto_9
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 325
    .line 326
    .line 327
    throw v0

    .line 328
    :pswitch_3
    move-object/from16 v4, p1

    .line 329
    .line 330
    check-cast v4, Lua/a;

    .line 331
    .line 332
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    invoke-interface {v4, v13}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 336
    .line 337
    .line 338
    move-result-object v2

    .line 339
    :try_start_4
    invoke-interface {v2, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 340
    .line 341
    .line 342
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 343
    .line 344
    .line 345
    move-result v0

    .line 346
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 347
    .line 348
    .line 349
    move-result v1

    .line 350
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 351
    .line 352
    .line 353
    move-result v3

    .line 354
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 355
    .line 356
    .line 357
    move-result v4

    .line 358
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 359
    .line 360
    .line 361
    move-result v5

    .line 362
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 363
    .line 364
    .line 365
    move-result v6

    .line 366
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 367
    .line 368
    .line 369
    move-result v7

    .line 370
    if-eqz v7, :cond_b

    .line 371
    .line 372
    invoke-interface {v2, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 373
    .line 374
    .line 375
    move-result-object v9

    .line 376
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object v10

    .line 380
    invoke-interface {v2, v3}, Lua/c;->isNull(I)Z

    .line 381
    .line 382
    .line 383
    move-result v0

    .line 384
    if-eqz v0, :cond_7

    .line 385
    .line 386
    const/4 v11, 0x0

    .line 387
    goto :goto_a

    .line 388
    :cond_7
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 389
    .line 390
    .line 391
    move-result-wide v0

    .line 392
    long-to-int v0, v0

    .line 393
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    move-object v11, v0

    .line 398
    :goto_a
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 399
    .line 400
    .line 401
    move-result v0

    .line 402
    if-eqz v0, :cond_8

    .line 403
    .line 404
    const/4 v12, 0x0

    .line 405
    goto :goto_b

    .line 406
    :cond_8
    invoke-interface {v2, v4}, Lua/c;->getDouble(I)D

    .line 407
    .line 408
    .line 409
    move-result-wide v0

    .line 410
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    move-object v12, v0

    .line 415
    :goto_b
    invoke-interface {v2, v5}, Lua/c;->isNull(I)Z

    .line 416
    .line 417
    .line 418
    move-result v0

    .line 419
    if-eqz v0, :cond_9

    .line 420
    .line 421
    const/4 v13, 0x0

    .line 422
    goto :goto_c

    .line 423
    :cond_9
    invoke-interface {v2, v5}, Lua/c;->getDouble(I)D

    .line 424
    .line 425
    .line 426
    move-result-wide v0

    .line 427
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    move-object v13, v0

    .line 432
    :goto_c
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 433
    .line 434
    .line 435
    move-result v0

    .line 436
    if-eqz v0, :cond_a

    .line 437
    .line 438
    const/4 v14, 0x0

    .line 439
    goto :goto_d

    .line 440
    :cond_a
    invoke-interface {v2, v6}, Lua/c;->getDouble(I)D

    .line 441
    .line 442
    .line 443
    move-result-wide v0

    .line 444
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 445
    .line 446
    .line 447
    move-result-object v0

    .line 448
    move-object v14, v0

    .line 449
    :goto_d
    new-instance v8, Li70/g0;

    .line 450
    .line 451
    invoke-direct/range {v8 .. v14}, Li70/g0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 452
    .line 453
    .line 454
    move-object/from16 v20, v8

    .line 455
    .line 456
    goto :goto_e

    .line 457
    :catchall_4
    move-exception v0

    .line 458
    goto :goto_f

    .line 459
    :cond_b
    const/16 v20, 0x0

    .line 460
    .line 461
    :goto_e
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 462
    .line 463
    .line 464
    return-object v20

    .line 465
    :goto_f
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 466
    .line 467
    .line 468
    throw v0

    .line 469
    :pswitch_4
    move-object/from16 v1, p1

    .line 470
    .line 471
    check-cast v1, Ld4/l;

    .line 472
    .line 473
    sget-object v2, Ld4/x;->a:[Lhy0/z;

    .line 474
    .line 475
    sget-object v2, Ld4/v;->K:Ld4/z;

    .line 476
    .line 477
    invoke-virtual {v1, v2, v0}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 478
    .line 479
    .line 480
    return-object v22

    .line 481
    :pswitch_5
    move-object/from16 v1, p1

    .line 482
    .line 483
    check-cast v1, Ld4/l;

    .line 484
    .line 485
    invoke-static {v1, v3}, Ld4/x;->e(Ld4/l;I)V

    .line 486
    .line 487
    .line 488
    invoke-static {v1, v0}, Ld4/x;->f(Ld4/l;Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    return-object v22

    .line 492
    :pswitch_6
    move-object/from16 v1, p1

    .line 493
    .line 494
    check-cast v1, Ld4/l;

    .line 495
    .line 496
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 497
    .line 498
    .line 499
    return-object v22

    .line 500
    :pswitch_7
    move-object/from16 v1, p1

    .line 501
    .line 502
    check-cast v1, Ld4/l;

    .line 503
    .line 504
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 505
    .line 506
    .line 507
    return-object v22

    .line 508
    :pswitch_8
    move-object/from16 v1, p1

    .line 509
    .line 510
    check-cast v1, Ld4/l;

    .line 511
    .line 512
    invoke-static {v1, v0}, Ld4/x;->f(Ld4/l;Ljava/lang/String;)V

    .line 513
    .line 514
    .line 515
    sget-object v0, Ld4/v;->s:Ld4/z;

    .line 516
    .line 517
    sget-object v2, Ld4/x;->a:[Lhy0/z;

    .line 518
    .line 519
    const/16 v3, 0xa

    .line 520
    .line 521
    aget-object v2, v2, v3

    .line 522
    .line 523
    const/4 v2, 0x0

    .line 524
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 525
    .line 526
    .line 527
    move-result-object v2

    .line 528
    invoke-virtual {v0, v1, v2}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 529
    .line 530
    .line 531
    return-object v22

    .line 532
    :pswitch_9
    move-object/from16 v1, p1

    .line 533
    .line 534
    check-cast v1, Ld4/l;

    .line 535
    .line 536
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 537
    .line 538
    .line 539
    const/4 v0, 0x5

    .line 540
    invoke-static {v1, v0}, Ld4/x;->i(Ld4/l;I)V

    .line 541
    .line 542
    .line 543
    return-object v22

    .line 544
    :pswitch_a
    move-object/from16 v1, p1

    .line 545
    .line 546
    check-cast v1, Ld4/l;

    .line 547
    .line 548
    invoke-static {v1, v0}, Ld4/x;->f(Ld4/l;Ljava/lang/String;)V

    .line 549
    .line 550
    .line 551
    return-object v22

    .line 552
    :pswitch_b
    move-object/from16 v1, p1

    .line 553
    .line 554
    check-cast v1, Ld4/l;

    .line 555
    .line 556
    const/4 v2, 0x0

    .line 557
    invoke-static {v1, v2}, Ld4/x;->e(Ld4/l;I)V

    .line 558
    .line 559
    .line 560
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 561
    .line 562
    .line 563
    return-object v22

    .line 564
    :pswitch_c
    move-object/from16 v1, p1

    .line 565
    .line 566
    check-cast v1, Ld4/l;

    .line 567
    .line 568
    invoke-static {v1, v0}, Ld4/x;->f(Ld4/l;Ljava/lang/String;)V

    .line 569
    .line 570
    .line 571
    return-object v22

    .line 572
    :pswitch_d
    const/4 v2, 0x0

    .line 573
    move-object/from16 v1, p1

    .line 574
    .line 575
    check-cast v1, Ld4/l;

    .line 576
    .line 577
    new-instance v3, Lg4/g;

    .line 578
    .line 579
    invoke-direct {v3, v0}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 580
    .line 581
    .line 582
    invoke-static {v1, v3}, Ld4/x;->k(Ld4/l;Lg4/g;)V

    .line 583
    .line 584
    .line 585
    invoke-static {v1, v2}, Ld4/x;->i(Ld4/l;I)V

    .line 586
    .line 587
    .line 588
    return-object v22

    .line 589
    :pswitch_e
    const/4 v2, 0x0

    .line 590
    move-object/from16 v1, p1

    .line 591
    .line 592
    check-cast v1, Ld4/l;

    .line 593
    .line 594
    new-instance v3, Lg4/g;

    .line 595
    .line 596
    invoke-direct {v3, v0}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 597
    .line 598
    .line 599
    invoke-static {v1, v3}, Ld4/x;->k(Ld4/l;Lg4/g;)V

    .line 600
    .line 601
    .line 602
    invoke-static {v1, v2}, Ld4/x;->i(Ld4/l;I)V

    .line 603
    .line 604
    .line 605
    return-object v22

    .line 606
    :pswitch_f
    const/4 v2, 0x0

    .line 607
    move-object/from16 v1, p1

    .line 608
    .line 609
    check-cast v1, Ld4/l;

    .line 610
    .line 611
    invoke-static {v1, v2}, Ld4/x;->e(Ld4/l;I)V

    .line 612
    .line 613
    .line 614
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 615
    .line 616
    .line 617
    return-object v22

    .line 618
    :pswitch_10
    move-object/from16 v1, p1

    .line 619
    .line 620
    check-cast v1, Ld4/l;

    .line 621
    .line 622
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 623
    .line 624
    .line 625
    return-object v22

    .line 626
    :pswitch_11
    move-object/from16 v1, p1

    .line 627
    .line 628
    check-cast v1, Lhi/a;

    .line 629
    .line 630
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 631
    .line 632
    .line 633
    const-class v2, Lkj/c;

    .line 634
    .line 635
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 636
    .line 637
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 638
    .line 639
    .line 640
    move-result-object v2

    .line 641
    check-cast v1, Lii/a;

    .line 642
    .line 643
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 644
    .line 645
    .line 646
    move-result-object v1

    .line 647
    check-cast v1, Lkj/c;

    .line 648
    .line 649
    new-instance v2, Lgg/c;

    .line 650
    .line 651
    new-instance v3, La2/c;

    .line 652
    .line 653
    const/16 v4, 0xe

    .line 654
    .line 655
    const/4 v5, 0x0

    .line 656
    invoke-direct {v3, v4, v1, v0, v5}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 657
    .line 658
    .line 659
    invoke-direct {v2, v3}, Lgg/c;-><init>(La2/c;)V

    .line 660
    .line 661
    .line 662
    return-object v2

    .line 663
    :pswitch_12
    move-object/from16 v1, p1

    .line 664
    .line 665
    check-cast v1, Lgi/c;

    .line 666
    .line 667
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 668
    .line 669
    .line 670
    new-instance v1, Ljava/lang/StringBuilder;

    .line 671
    .line 672
    const-string v2, "Received cookie: "

    .line 673
    .line 674
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 675
    .line 676
    .line 677
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 678
    .line 679
    .line 680
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 681
    .line 682
    .line 683
    move-result-object v0

    .line 684
    return-object v0

    .line 685
    :pswitch_13
    move-object/from16 v1, p1

    .line 686
    .line 687
    check-cast v1, Lgi/c;

    .line 688
    .line 689
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 690
    .line 691
    .line 692
    new-instance v1, Ljava/lang/StringBuilder;

    .line 693
    .line 694
    const-string v2, "Cookie is not null and will be added "

    .line 695
    .line 696
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 697
    .line 698
    .line 699
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 700
    .line 701
    .line 702
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 703
    .line 704
    .line 705
    move-result-object v0

    .line 706
    return-object v0

    .line 707
    :pswitch_14
    move-object/from16 v1, p1

    .line 708
    .line 709
    check-cast v1, Lua/a;

    .line 710
    .line 711
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 712
    .line 713
    .line 714
    const-string v2, "DELETE FROM ordered_vehicle where ? is commissionId"

    .line 715
    .line 716
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 717
    .line 718
    .line 719
    move-result-object v1

    .line 720
    :try_start_5
    invoke-interface {v1, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 721
    .line 722
    .line 723
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 724
    .line 725
    .line 726
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 727
    .line 728
    .line 729
    return-object v22

    .line 730
    :catchall_5
    move-exception v0

    .line 731
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 732
    .line 733
    .line 734
    throw v0

    .line 735
    :pswitch_15
    move-object/from16 v1, p1

    .line 736
    .line 737
    check-cast v1, Lua/a;

    .line 738
    .line 739
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 740
    .line 741
    .line 742
    const-string v2, "DELETE FROM order_checkpoint WHERE commissionId = ?"

    .line 743
    .line 744
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 745
    .line 746
    .line 747
    move-result-object v1

    .line 748
    :try_start_6
    invoke-interface {v1, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 749
    .line 750
    .line 751
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 752
    .line 753
    .line 754
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 755
    .line 756
    .line 757
    return-object v22

    .line 758
    :catchall_6
    move-exception v0

    .line 759
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 760
    .line 761
    .line 762
    throw v0

    .line 763
    :pswitch_16
    move-object/from16 v1, p1

    .line 764
    .line 765
    check-cast v1, Lua/a;

    .line 766
    .line 767
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 768
    .line 769
    .line 770
    const-string v2, "SELECT * from network_log WHERE request_state == ?"

    .line 771
    .line 772
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 773
    .line 774
    .line 775
    move-result-object v1

    .line 776
    :try_start_7
    invoke-interface {v1, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 777
    .line 778
    .line 779
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 780
    .line 781
    .line 782
    move-result v0

    .line 783
    move-object/from16 v5, v21

    .line 784
    .line 785
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 786
    .line 787
    .line 788
    move-result v2

    .line 789
    move-object/from16 v6, v18

    .line 790
    .line 791
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 792
    .line 793
    .line 794
    move-result v3

    .line 795
    const-string v4, "response_body"

    .line 796
    .line 797
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 798
    .line 799
    .line 800
    move-result v4

    .line 801
    const-string v5, "response_code"

    .line 802
    .line 803
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 804
    .line 805
    .line 806
    move-result v5

    .line 807
    const-string v6, "response_headers"

    .line 808
    .line 809
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 810
    .line 811
    .line 812
    move-result v6

    .line 813
    const-string v7, "response_message"

    .line 814
    .line 815
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 816
    .line 817
    .line 818
    move-result v7

    .line 819
    const-string v8, "response_time"

    .line 820
    .line 821
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 822
    .line 823
    .line 824
    move-result v8

    .line 825
    const-string v9, "response_url"

    .line 826
    .line 827
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 828
    .line 829
    .line 830
    move-result v9

    .line 831
    const-string v10, "request_body"

    .line 832
    .line 833
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 834
    .line 835
    .line 836
    move-result v10

    .line 837
    const-string v11, "request_headers"

    .line 838
    .line 839
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 840
    .line 841
    .line 842
    move-result v11

    .line 843
    const-string v12, "request_method"

    .line 844
    .line 845
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 846
    .line 847
    .line 848
    move-result v12

    .line 849
    const-string v13, "request_protocol"

    .line 850
    .line 851
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 852
    .line 853
    .line 854
    move-result v13

    .line 855
    const-string v14, "request_state"

    .line 856
    .line 857
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 858
    .line 859
    .line 860
    move-result v14

    .line 861
    const-string v15, "request_url"

    .line 862
    .line 863
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 864
    .line 865
    .line 866
    move-result v15

    .line 867
    move/from16 p0, v15

    .line 868
    .line 869
    const-string v15, "log_type"

    .line 870
    .line 871
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 872
    .line 873
    .line 874
    move-result v15

    .line 875
    move/from16 p1, v15

    .line 876
    .line 877
    const-string v15, "timestamp"

    .line 878
    .line 879
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 880
    .line 881
    .line 882
    move-result v15

    .line 883
    move/from16 v16, v15

    .line 884
    .line 885
    new-instance v15, Ljava/util/ArrayList;

    .line 886
    .line 887
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 888
    .line 889
    .line 890
    :goto_10
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 891
    .line 892
    .line 893
    move-result v17

    .line 894
    if-eqz v17, :cond_c

    .line 895
    .line 896
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 897
    .line 898
    .line 899
    move-result-wide v19

    .line 900
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 901
    .line 902
    .line 903
    move-result-object v21

    .line 904
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 905
    .line 906
    .line 907
    move-result-object v22

    .line 908
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 909
    .line 910
    .line 911
    move-result-object v23

    .line 912
    move/from16 v17, v2

    .line 913
    .line 914
    move/from16 v39, v3

    .line 915
    .line 916
    invoke-interface {v1, v5}, Lua/c;->getLong(I)J

    .line 917
    .line 918
    .line 919
    move-result-wide v2

    .line 920
    long-to-int v2, v2

    .line 921
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 922
    .line 923
    .line 924
    move-result-object v25

    .line 925
    invoke-interface {v1, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 926
    .line 927
    .line 928
    move-result-object v26

    .line 929
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 930
    .line 931
    .line 932
    move-result-wide v27

    .line 933
    invoke-interface {v1, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 934
    .line 935
    .line 936
    move-result-object v29

    .line 937
    invoke-interface {v1, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 938
    .line 939
    .line 940
    move-result-object v30

    .line 941
    invoke-interface {v1, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 942
    .line 943
    .line 944
    move-result-object v31

    .line 945
    invoke-interface {v1, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 946
    .line 947
    .line 948
    move-result-object v32

    .line 949
    invoke-interface {v1, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 950
    .line 951
    .line 952
    move-result-object v33

    .line 953
    invoke-interface {v1, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 954
    .line 955
    .line 956
    move-result-object v34

    .line 957
    move/from16 v3, p0

    .line 958
    .line 959
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 960
    .line 961
    .line 962
    move-result-object v35

    .line 963
    move/from16 p0, v0

    .line 964
    .line 965
    move/from16 v0, p1

    .line 966
    .line 967
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 968
    .line 969
    .line 970
    move-result-object v18

    .line 971
    invoke-static/range {v18 .. v18}, Lem0/f;->a(Ljava/lang/String;)Lhm0/c;

    .line 972
    .line 973
    .line 974
    move-result-object v36

    .line 975
    move/from16 p1, v0

    .line 976
    .line 977
    move/from16 v0, v16

    .line 978
    .line 979
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 980
    .line 981
    .line 982
    move-result-wide v37

    .line 983
    new-instance v18, Lem0/g;

    .line 984
    .line 985
    move/from16 v24, v2

    .line 986
    .line 987
    invoke-direct/range {v18 .. v38}, Lem0/g;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lhm0/c;J)V

    .line 988
    .line 989
    .line 990
    move-object/from16 v2, v18

    .line 991
    .line 992
    invoke-virtual {v15, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_7

    .line 993
    .line 994
    .line 995
    move/from16 v16, v0

    .line 996
    .line 997
    move/from16 v2, v17

    .line 998
    .line 999
    move/from16 v0, p0

    .line 1000
    .line 1001
    move/from16 p0, v3

    .line 1002
    .line 1003
    move/from16 v3, v39

    .line 1004
    .line 1005
    goto :goto_10

    .line 1006
    :catchall_7
    move-exception v0

    .line 1007
    goto :goto_11

    .line 1008
    :cond_c
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1009
    .line 1010
    .line 1011
    return-object v15

    .line 1012
    :goto_11
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1013
    .line 1014
    .line 1015
    throw v0

    .line 1016
    :pswitch_17
    move-object/from16 v6, v18

    .line 1017
    .line 1018
    move-object/from16 v5, v21

    .line 1019
    .line 1020
    move-object/from16 v1, p1

    .line 1021
    .line 1022
    check-cast v1, Lua/a;

    .line 1023
    .line 1024
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1025
    .line 1026
    .line 1027
    const-string v2, "SELECT * from network_log WHERE service_label == ?"

    .line 1028
    .line 1029
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1030
    .line 1031
    .line 1032
    move-result-object v1

    .line 1033
    :try_start_8
    invoke-interface {v1, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 1034
    .line 1035
    .line 1036
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1037
    .line 1038
    .line 1039
    move-result v0

    .line 1040
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1041
    .line 1042
    .line 1043
    move-result v2

    .line 1044
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1045
    .line 1046
    .line 1047
    move-result v3

    .line 1048
    const-string v4, "response_body"

    .line 1049
    .line 1050
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1051
    .line 1052
    .line 1053
    move-result v4

    .line 1054
    const-string v5, "response_code"

    .line 1055
    .line 1056
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1057
    .line 1058
    .line 1059
    move-result v5

    .line 1060
    const-string v6, "response_headers"

    .line 1061
    .line 1062
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1063
    .line 1064
    .line 1065
    move-result v6

    .line 1066
    const-string v7, "response_message"

    .line 1067
    .line 1068
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1069
    .line 1070
    .line 1071
    move-result v7

    .line 1072
    const-string v8, "response_time"

    .line 1073
    .line 1074
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1075
    .line 1076
    .line 1077
    move-result v8

    .line 1078
    const-string v9, "response_url"

    .line 1079
    .line 1080
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1081
    .line 1082
    .line 1083
    move-result v9

    .line 1084
    const-string v10, "request_body"

    .line 1085
    .line 1086
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1087
    .line 1088
    .line 1089
    move-result v10

    .line 1090
    const-string v11, "request_headers"

    .line 1091
    .line 1092
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1093
    .line 1094
    .line 1095
    move-result v11

    .line 1096
    const-string v12, "request_method"

    .line 1097
    .line 1098
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1099
    .line 1100
    .line 1101
    move-result v12

    .line 1102
    const-string v13, "request_protocol"

    .line 1103
    .line 1104
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1105
    .line 1106
    .line 1107
    move-result v13

    .line 1108
    const-string v14, "request_state"

    .line 1109
    .line 1110
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1111
    .line 1112
    .line 1113
    move-result v14

    .line 1114
    const-string v15, "request_url"

    .line 1115
    .line 1116
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1117
    .line 1118
    .line 1119
    move-result v15

    .line 1120
    move/from16 p0, v15

    .line 1121
    .line 1122
    const-string v15, "log_type"

    .line 1123
    .line 1124
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1125
    .line 1126
    .line 1127
    move-result v15

    .line 1128
    move/from16 p1, v15

    .line 1129
    .line 1130
    const-string v15, "timestamp"

    .line 1131
    .line 1132
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1133
    .line 1134
    .line 1135
    move-result v15

    .line 1136
    move/from16 v16, v15

    .line 1137
    .line 1138
    new-instance v15, Ljava/util/ArrayList;

    .line 1139
    .line 1140
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 1141
    .line 1142
    .line 1143
    :goto_12
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1144
    .line 1145
    .line 1146
    move-result v17

    .line 1147
    if-eqz v17, :cond_d

    .line 1148
    .line 1149
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1150
    .line 1151
    .line 1152
    move-result-wide v19

    .line 1153
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v21

    .line 1157
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1158
    .line 1159
    .line 1160
    move-result-object v22

    .line 1161
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1162
    .line 1163
    .line 1164
    move-result-object v23

    .line 1165
    move/from16 v17, v2

    .line 1166
    .line 1167
    move/from16 v39, v3

    .line 1168
    .line 1169
    invoke-interface {v1, v5}, Lua/c;->getLong(I)J

    .line 1170
    .line 1171
    .line 1172
    move-result-wide v2

    .line 1173
    long-to-int v2, v2

    .line 1174
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1175
    .line 1176
    .line 1177
    move-result-object v25

    .line 1178
    invoke-interface {v1, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1179
    .line 1180
    .line 1181
    move-result-object v26

    .line 1182
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 1183
    .line 1184
    .line 1185
    move-result-wide v27

    .line 1186
    invoke-interface {v1, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1187
    .line 1188
    .line 1189
    move-result-object v29

    .line 1190
    invoke-interface {v1, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1191
    .line 1192
    .line 1193
    move-result-object v30

    .line 1194
    invoke-interface {v1, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1195
    .line 1196
    .line 1197
    move-result-object v31

    .line 1198
    invoke-interface {v1, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1199
    .line 1200
    .line 1201
    move-result-object v32

    .line 1202
    invoke-interface {v1, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1203
    .line 1204
    .line 1205
    move-result-object v33

    .line 1206
    invoke-interface {v1, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1207
    .line 1208
    .line 1209
    move-result-object v34

    .line 1210
    move/from16 v3, p0

    .line 1211
    .line 1212
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1213
    .line 1214
    .line 1215
    move-result-object v35

    .line 1216
    move/from16 p0, v0

    .line 1217
    .line 1218
    move/from16 v0, p1

    .line 1219
    .line 1220
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1221
    .line 1222
    .line 1223
    move-result-object v18

    .line 1224
    invoke-static/range {v18 .. v18}, Lem0/f;->a(Ljava/lang/String;)Lhm0/c;

    .line 1225
    .line 1226
    .line 1227
    move-result-object v36

    .line 1228
    move/from16 p1, v0

    .line 1229
    .line 1230
    move/from16 v0, v16

    .line 1231
    .line 1232
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1233
    .line 1234
    .line 1235
    move-result-wide v37

    .line 1236
    new-instance v18, Lem0/g;

    .line 1237
    .line 1238
    move/from16 v24, v2

    .line 1239
    .line 1240
    invoke-direct/range {v18 .. v38}, Lem0/g;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lhm0/c;J)V

    .line 1241
    .line 1242
    .line 1243
    move-object/from16 v2, v18

    .line 1244
    .line 1245
    invoke-virtual {v15, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_8

    .line 1246
    .line 1247
    .line 1248
    move/from16 v16, v0

    .line 1249
    .line 1250
    move/from16 v2, v17

    .line 1251
    .line 1252
    move/from16 v0, p0

    .line 1253
    .line 1254
    move/from16 p0, v3

    .line 1255
    .line 1256
    move/from16 v3, v39

    .line 1257
    .line 1258
    goto :goto_12

    .line 1259
    :catchall_8
    move-exception v0

    .line 1260
    goto :goto_13

    .line 1261
    :cond_d
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1262
    .line 1263
    .line 1264
    return-object v15

    .line 1265
    :goto_13
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1266
    .line 1267
    .line 1268
    throw v0

    .line 1269
    :pswitch_18
    move-object/from16 v1, p1

    .line 1270
    .line 1271
    check-cast v1, Ld4/l;

    .line 1272
    .line 1273
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 1274
    .line 1275
    .line 1276
    const/4 v0, 0x5

    .line 1277
    invoke-static {v1, v0}, Ld4/x;->i(Ld4/l;I)V

    .line 1278
    .line 1279
    .line 1280
    return-object v22

    .line 1281
    :pswitch_19
    const/4 v5, 0x0

    .line 1282
    move-object/from16 v4, p1

    .line 1283
    .line 1284
    check-cast v4, Lua/a;

    .line 1285
    .line 1286
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1287
    .line 1288
    .line 1289
    const-string v2, "SELECT * FROM range_ice WHERE vin = ? LIMIT 1"

    .line 1290
    .line 1291
    invoke-interface {v4, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1292
    .line 1293
    .line 1294
    move-result-object v2

    .line 1295
    :try_start_9
    invoke-interface {v2, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 1296
    .line 1297
    .line 1298
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1299
    .line 1300
    .line 1301
    move-result v0

    .line 1302
    const-string v1, "car_type"

    .line 1303
    .line 1304
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1305
    .line 1306
    .line 1307
    move-result v1

    .line 1308
    const-string v3, "ad_blue_range"

    .line 1309
    .line 1310
    invoke-static {v2, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1311
    .line 1312
    .line 1313
    move-result v3

    .line 1314
    const-string v4, "total_range"

    .line 1315
    .line 1316
    invoke-static {v2, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1317
    .line 1318
    .line 1319
    move-result v4

    .line 1320
    const-string v6, "car_captured_timestamp"

    .line 1321
    .line 1322
    invoke-static {v2, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1323
    .line 1324
    .line 1325
    move-result v6

    .line 1326
    const-string v7, "primary_engine_engine_type"

    .line 1327
    .line 1328
    invoke-static {v2, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1329
    .line 1330
    .line 1331
    move-result v7

    .line 1332
    const-string v8, "primary_engine_current_soc_in_pct"

    .line 1333
    .line 1334
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1335
    .line 1336
    .line 1337
    move-result v8

    .line 1338
    const-string v9, "primary_engine_current_fuel_level_pct"

    .line 1339
    .line 1340
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1341
    .line 1342
    .line 1343
    move-result v9

    .line 1344
    const-string v10, "primary_engine_remaining_range"

    .line 1345
    .line 1346
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1347
    .line 1348
    .line 1349
    move-result v10

    .line 1350
    const-string v11, "secondary_engine_engine_type"

    .line 1351
    .line 1352
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1353
    .line 1354
    .line 1355
    move-result v11

    .line 1356
    const-string v12, "secondary_engine_current_soc_in_pct"

    .line 1357
    .line 1358
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1359
    .line 1360
    .line 1361
    move-result v12

    .line 1362
    const-string v13, "secondary_engine_current_fuel_level_pct"

    .line 1363
    .line 1364
    invoke-static {v2, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1365
    .line 1366
    .line 1367
    move-result v13

    .line 1368
    const-string v14, "secondary_engine_remaining_range"

    .line 1369
    .line 1370
    invoke-static {v2, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1371
    .line 1372
    .line 1373
    move-result v14

    .line 1374
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 1375
    .line 1376
    .line 1377
    move-result v15

    .line 1378
    if-eqz v15, :cond_19

    .line 1379
    .line 1380
    invoke-interface {v2, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1381
    .line 1382
    .line 1383
    move-result-object v17

    .line 1384
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1385
    .line 1386
    .line 1387
    move-result-object v18

    .line 1388
    invoke-interface {v2, v3}, Lua/c;->isNull(I)Z

    .line 1389
    .line 1390
    .line 1391
    move-result v0

    .line 1392
    if-eqz v0, :cond_e

    .line 1393
    .line 1394
    move-object/from16 v19, v5

    .line 1395
    .line 1396
    goto :goto_14

    .line 1397
    :cond_e
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 1398
    .line 1399
    .line 1400
    move-result-wide v0

    .line 1401
    long-to-int v0, v0

    .line 1402
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1403
    .line 1404
    .line 1405
    move-result-object v0

    .line 1406
    move-object/from16 v19, v0

    .line 1407
    .line 1408
    :goto_14
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 1409
    .line 1410
    .line 1411
    move-result v0

    .line 1412
    if-eqz v0, :cond_f

    .line 1413
    .line 1414
    move-object/from16 v20, v5

    .line 1415
    .line 1416
    goto :goto_15

    .line 1417
    :cond_f
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 1418
    .line 1419
    .line 1420
    move-result-wide v0

    .line 1421
    long-to-int v0, v0

    .line 1422
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1423
    .line 1424
    .line 1425
    move-result-object v0

    .line 1426
    move-object/from16 v20, v0

    .line 1427
    .line 1428
    :goto_15
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 1429
    .line 1430
    .line 1431
    move-result v0

    .line 1432
    if-eqz v0, :cond_10

    .line 1433
    .line 1434
    move-object v0, v5

    .line 1435
    goto :goto_16

    .line 1436
    :cond_10
    invoke-interface {v2, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1437
    .line 1438
    .line 1439
    move-result-object v0

    .line 1440
    :goto_16
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v23

    .line 1444
    invoke-interface {v2, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1445
    .line 1446
    .line 1447
    move-result-object v0

    .line 1448
    invoke-interface {v2, v8}, Lua/c;->isNull(I)Z

    .line 1449
    .line 1450
    .line 1451
    move-result v1

    .line 1452
    if-eqz v1, :cond_11

    .line 1453
    .line 1454
    move-object v1, v5

    .line 1455
    goto :goto_17

    .line 1456
    :cond_11
    invoke-interface {v2, v8}, Lua/c;->getLong(I)J

    .line 1457
    .line 1458
    .line 1459
    move-result-wide v3

    .line 1460
    long-to-int v1, v3

    .line 1461
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1462
    .line 1463
    .line 1464
    move-result-object v1

    .line 1465
    :goto_17
    invoke-interface {v2, v9}, Lua/c;->isNull(I)Z

    .line 1466
    .line 1467
    .line 1468
    move-result v3

    .line 1469
    if-eqz v3, :cond_12

    .line 1470
    .line 1471
    move-object v3, v5

    .line 1472
    goto :goto_18

    .line 1473
    :cond_12
    invoke-interface {v2, v9}, Lua/c;->getLong(I)J

    .line 1474
    .line 1475
    .line 1476
    move-result-wide v3

    .line 1477
    long-to-int v3, v3

    .line 1478
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1479
    .line 1480
    .line 1481
    move-result-object v3

    .line 1482
    :goto_18
    invoke-interface {v2, v10}, Lua/c;->isNull(I)Z

    .line 1483
    .line 1484
    .line 1485
    move-result v4

    .line 1486
    if-eqz v4, :cond_13

    .line 1487
    .line 1488
    move-object v4, v5

    .line 1489
    goto :goto_19

    .line 1490
    :cond_13
    invoke-interface {v2, v10}, Lua/c;->getLong(I)J

    .line 1491
    .line 1492
    .line 1493
    move-result-wide v6

    .line 1494
    long-to-int v4, v6

    .line 1495
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1496
    .line 1497
    .line 1498
    move-result-object v4

    .line 1499
    :goto_19
    new-instance v6, Lcp0/a;

    .line 1500
    .line 1501
    invoke-direct {v6, v0, v1, v3, v4}, Lcp0/a;-><init>(Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 1502
    .line 1503
    .line 1504
    invoke-interface {v2, v11}, Lua/c;->isNull(I)Z

    .line 1505
    .line 1506
    .line 1507
    move-result v0

    .line 1508
    if-eqz v0, :cond_15

    .line 1509
    .line 1510
    invoke-interface {v2, v12}, Lua/c;->isNull(I)Z

    .line 1511
    .line 1512
    .line 1513
    move-result v0

    .line 1514
    if-eqz v0, :cond_15

    .line 1515
    .line 1516
    invoke-interface {v2, v13}, Lua/c;->isNull(I)Z

    .line 1517
    .line 1518
    .line 1519
    move-result v0

    .line 1520
    if-eqz v0, :cond_15

    .line 1521
    .line 1522
    invoke-interface {v2, v14}, Lua/c;->isNull(I)Z

    .line 1523
    .line 1524
    .line 1525
    move-result v0

    .line 1526
    if-nez v0, :cond_14

    .line 1527
    .line 1528
    goto :goto_1b

    .line 1529
    :cond_14
    :goto_1a
    move-object/from16 v22, v5

    .line 1530
    .line 1531
    goto :goto_1f

    .line 1532
    :catchall_9
    move-exception v0

    .line 1533
    goto :goto_21

    .line 1534
    :cond_15
    :goto_1b
    invoke-interface {v2, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1535
    .line 1536
    .line 1537
    move-result-object v0

    .line 1538
    invoke-interface {v2, v12}, Lua/c;->isNull(I)Z

    .line 1539
    .line 1540
    .line 1541
    move-result v1

    .line 1542
    if-eqz v1, :cond_16

    .line 1543
    .line 1544
    move-object v1, v5

    .line 1545
    goto :goto_1c

    .line 1546
    :cond_16
    invoke-interface {v2, v12}, Lua/c;->getLong(I)J

    .line 1547
    .line 1548
    .line 1549
    move-result-wide v3

    .line 1550
    long-to-int v1, v3

    .line 1551
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1552
    .line 1553
    .line 1554
    move-result-object v1

    .line 1555
    :goto_1c
    invoke-interface {v2, v13}, Lua/c;->isNull(I)Z

    .line 1556
    .line 1557
    .line 1558
    move-result v3

    .line 1559
    if-eqz v3, :cond_17

    .line 1560
    .line 1561
    move-object v3, v5

    .line 1562
    goto :goto_1d

    .line 1563
    :cond_17
    invoke-interface {v2, v13}, Lua/c;->getLong(I)J

    .line 1564
    .line 1565
    .line 1566
    move-result-wide v3

    .line 1567
    long-to-int v3, v3

    .line 1568
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1569
    .line 1570
    .line 1571
    move-result-object v3

    .line 1572
    :goto_1d
    invoke-interface {v2, v14}, Lua/c;->isNull(I)Z

    .line 1573
    .line 1574
    .line 1575
    move-result v4

    .line 1576
    if-eqz v4, :cond_18

    .line 1577
    .line 1578
    move-object v4, v5

    .line 1579
    goto :goto_1e

    .line 1580
    :cond_18
    invoke-interface {v2, v14}, Lua/c;->getLong(I)J

    .line 1581
    .line 1582
    .line 1583
    move-result-wide v4

    .line 1584
    long-to-int v4, v4

    .line 1585
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1586
    .line 1587
    .line 1588
    move-result-object v4

    .line 1589
    :goto_1e
    new-instance v5, Lcp0/a;

    .line 1590
    .line 1591
    invoke-direct {v5, v0, v1, v3, v4}, Lcp0/a;-><init>(Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 1592
    .line 1593
    .line 1594
    goto :goto_1a

    .line 1595
    :goto_1f
    new-instance v16, Lcp0/c;

    .line 1596
    .line 1597
    move-object/from16 v21, v6

    .line 1598
    .line 1599
    invoke-direct/range {v16 .. v23}, Lcp0/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Lcp0/a;Lcp0/a;Ljava/time/OffsetDateTime;)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_9

    .line 1600
    .line 1601
    .line 1602
    goto :goto_20

    .line 1603
    :cond_19
    move-object/from16 v16, v5

    .line 1604
    .line 1605
    :goto_20
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 1606
    .line 1607
    .line 1608
    return-object v16

    .line 1609
    :goto_21
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 1610
    .line 1611
    .line 1612
    throw v0

    .line 1613
    :pswitch_1a
    const/4 v5, 0x0

    .line 1614
    move-object/from16 v4, p1

    .line 1615
    .line 1616
    check-cast v4, Lua/a;

    .line 1617
    .line 1618
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1619
    .line 1620
    .line 1621
    const-string v2, "SELECT * FROM range_ice WHERE vin = ? LIMIT 1"

    .line 1622
    .line 1623
    invoke-interface {v4, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1624
    .line 1625
    .line 1626
    move-result-object v2

    .line 1627
    :try_start_a
    invoke-interface {v2, v3, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 1628
    .line 1629
    .line 1630
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1631
    .line 1632
    .line 1633
    move-result v0

    .line 1634
    const-string v1, "car_type"

    .line 1635
    .line 1636
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1637
    .line 1638
    .line 1639
    move-result v1

    .line 1640
    const-string v3, "ad_blue_range"

    .line 1641
    .line 1642
    invoke-static {v2, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1643
    .line 1644
    .line 1645
    move-result v3

    .line 1646
    const-string v4, "total_range"

    .line 1647
    .line 1648
    invoke-static {v2, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1649
    .line 1650
    .line 1651
    move-result v4

    .line 1652
    const-string v6, "car_captured_timestamp"

    .line 1653
    .line 1654
    invoke-static {v2, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1655
    .line 1656
    .line 1657
    move-result v6

    .line 1658
    const-string v7, "primary_engine_engine_type"

    .line 1659
    .line 1660
    invoke-static {v2, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1661
    .line 1662
    .line 1663
    move-result v7

    .line 1664
    const-string v8, "primary_engine_current_soc_in_pct"

    .line 1665
    .line 1666
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1667
    .line 1668
    .line 1669
    move-result v8

    .line 1670
    const-string v9, "primary_engine_current_fuel_level_pct"

    .line 1671
    .line 1672
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1673
    .line 1674
    .line 1675
    move-result v9

    .line 1676
    const-string v10, "primary_engine_remaining_range"

    .line 1677
    .line 1678
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1679
    .line 1680
    .line 1681
    move-result v10

    .line 1682
    const-string v11, "secondary_engine_engine_type"

    .line 1683
    .line 1684
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1685
    .line 1686
    .line 1687
    move-result v11

    .line 1688
    const-string v12, "secondary_engine_current_soc_in_pct"

    .line 1689
    .line 1690
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1691
    .line 1692
    .line 1693
    move-result v12

    .line 1694
    const-string v13, "secondary_engine_current_fuel_level_pct"

    .line 1695
    .line 1696
    invoke-static {v2, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1697
    .line 1698
    .line 1699
    move-result v13

    .line 1700
    const-string v14, "secondary_engine_remaining_range"

    .line 1701
    .line 1702
    invoke-static {v2, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1703
    .line 1704
    .line 1705
    move-result v14

    .line 1706
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 1707
    .line 1708
    .line 1709
    move-result v15

    .line 1710
    if-eqz v15, :cond_25

    .line 1711
    .line 1712
    invoke-interface {v2, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1713
    .line 1714
    .line 1715
    move-result-object v17

    .line 1716
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1717
    .line 1718
    .line 1719
    move-result-object v18

    .line 1720
    invoke-interface {v2, v3}, Lua/c;->isNull(I)Z

    .line 1721
    .line 1722
    .line 1723
    move-result v0

    .line 1724
    if-eqz v0, :cond_1a

    .line 1725
    .line 1726
    move-object/from16 v19, v5

    .line 1727
    .line 1728
    goto :goto_22

    .line 1729
    :cond_1a
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 1730
    .line 1731
    .line 1732
    move-result-wide v0

    .line 1733
    long-to-int v0, v0

    .line 1734
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1735
    .line 1736
    .line 1737
    move-result-object v0

    .line 1738
    move-object/from16 v19, v0

    .line 1739
    .line 1740
    :goto_22
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 1741
    .line 1742
    .line 1743
    move-result v0

    .line 1744
    if-eqz v0, :cond_1b

    .line 1745
    .line 1746
    move-object/from16 v20, v5

    .line 1747
    .line 1748
    goto :goto_23

    .line 1749
    :cond_1b
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 1750
    .line 1751
    .line 1752
    move-result-wide v0

    .line 1753
    long-to-int v0, v0

    .line 1754
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1755
    .line 1756
    .line 1757
    move-result-object v0

    .line 1758
    move-object/from16 v20, v0

    .line 1759
    .line 1760
    :goto_23
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 1761
    .line 1762
    .line 1763
    move-result v0

    .line 1764
    if-eqz v0, :cond_1c

    .line 1765
    .line 1766
    move-object v0, v5

    .line 1767
    goto :goto_24

    .line 1768
    :cond_1c
    invoke-interface {v2, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1769
    .line 1770
    .line 1771
    move-result-object v0

    .line 1772
    :goto_24
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 1773
    .line 1774
    .line 1775
    move-result-object v23

    .line 1776
    invoke-interface {v2, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1777
    .line 1778
    .line 1779
    move-result-object v0

    .line 1780
    invoke-interface {v2, v8}, Lua/c;->isNull(I)Z

    .line 1781
    .line 1782
    .line 1783
    move-result v1

    .line 1784
    if-eqz v1, :cond_1d

    .line 1785
    .line 1786
    move-object v1, v5

    .line 1787
    goto :goto_25

    .line 1788
    :cond_1d
    invoke-interface {v2, v8}, Lua/c;->getLong(I)J

    .line 1789
    .line 1790
    .line 1791
    move-result-wide v3

    .line 1792
    long-to-int v1, v3

    .line 1793
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1794
    .line 1795
    .line 1796
    move-result-object v1

    .line 1797
    :goto_25
    invoke-interface {v2, v9}, Lua/c;->isNull(I)Z

    .line 1798
    .line 1799
    .line 1800
    move-result v3

    .line 1801
    if-eqz v3, :cond_1e

    .line 1802
    .line 1803
    move-object v3, v5

    .line 1804
    goto :goto_26

    .line 1805
    :cond_1e
    invoke-interface {v2, v9}, Lua/c;->getLong(I)J

    .line 1806
    .line 1807
    .line 1808
    move-result-wide v3

    .line 1809
    long-to-int v3, v3

    .line 1810
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1811
    .line 1812
    .line 1813
    move-result-object v3

    .line 1814
    :goto_26
    invoke-interface {v2, v10}, Lua/c;->isNull(I)Z

    .line 1815
    .line 1816
    .line 1817
    move-result v4

    .line 1818
    if-eqz v4, :cond_1f

    .line 1819
    .line 1820
    move-object v4, v5

    .line 1821
    goto :goto_27

    .line 1822
    :cond_1f
    invoke-interface {v2, v10}, Lua/c;->getLong(I)J

    .line 1823
    .line 1824
    .line 1825
    move-result-wide v6

    .line 1826
    long-to-int v4, v6

    .line 1827
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1828
    .line 1829
    .line 1830
    move-result-object v4

    .line 1831
    :goto_27
    new-instance v6, Lcp0/a;

    .line 1832
    .line 1833
    invoke-direct {v6, v0, v1, v3, v4}, Lcp0/a;-><init>(Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 1834
    .line 1835
    .line 1836
    invoke-interface {v2, v11}, Lua/c;->isNull(I)Z

    .line 1837
    .line 1838
    .line 1839
    move-result v0

    .line 1840
    if-eqz v0, :cond_21

    .line 1841
    .line 1842
    invoke-interface {v2, v12}, Lua/c;->isNull(I)Z

    .line 1843
    .line 1844
    .line 1845
    move-result v0

    .line 1846
    if-eqz v0, :cond_21

    .line 1847
    .line 1848
    invoke-interface {v2, v13}, Lua/c;->isNull(I)Z

    .line 1849
    .line 1850
    .line 1851
    move-result v0

    .line 1852
    if-eqz v0, :cond_21

    .line 1853
    .line 1854
    invoke-interface {v2, v14}, Lua/c;->isNull(I)Z

    .line 1855
    .line 1856
    .line 1857
    move-result v0

    .line 1858
    if-nez v0, :cond_20

    .line 1859
    .line 1860
    goto :goto_29

    .line 1861
    :cond_20
    :goto_28
    move-object/from16 v22, v5

    .line 1862
    .line 1863
    goto :goto_2d

    .line 1864
    :catchall_a
    move-exception v0

    .line 1865
    goto :goto_2f

    .line 1866
    :cond_21
    :goto_29
    invoke-interface {v2, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1867
    .line 1868
    .line 1869
    move-result-object v0

    .line 1870
    invoke-interface {v2, v12}, Lua/c;->isNull(I)Z

    .line 1871
    .line 1872
    .line 1873
    move-result v1

    .line 1874
    if-eqz v1, :cond_22

    .line 1875
    .line 1876
    move-object v1, v5

    .line 1877
    goto :goto_2a

    .line 1878
    :cond_22
    invoke-interface {v2, v12}, Lua/c;->getLong(I)J

    .line 1879
    .line 1880
    .line 1881
    move-result-wide v3

    .line 1882
    long-to-int v1, v3

    .line 1883
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1884
    .line 1885
    .line 1886
    move-result-object v1

    .line 1887
    :goto_2a
    invoke-interface {v2, v13}, Lua/c;->isNull(I)Z

    .line 1888
    .line 1889
    .line 1890
    move-result v3

    .line 1891
    if-eqz v3, :cond_23

    .line 1892
    .line 1893
    move-object v3, v5

    .line 1894
    goto :goto_2b

    .line 1895
    :cond_23
    invoke-interface {v2, v13}, Lua/c;->getLong(I)J

    .line 1896
    .line 1897
    .line 1898
    move-result-wide v3

    .line 1899
    long-to-int v3, v3

    .line 1900
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1901
    .line 1902
    .line 1903
    move-result-object v3

    .line 1904
    :goto_2b
    invoke-interface {v2, v14}, Lua/c;->isNull(I)Z

    .line 1905
    .line 1906
    .line 1907
    move-result v4

    .line 1908
    if-eqz v4, :cond_24

    .line 1909
    .line 1910
    move-object v4, v5

    .line 1911
    goto :goto_2c

    .line 1912
    :cond_24
    invoke-interface {v2, v14}, Lua/c;->getLong(I)J

    .line 1913
    .line 1914
    .line 1915
    move-result-wide v4

    .line 1916
    long-to-int v4, v4

    .line 1917
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1918
    .line 1919
    .line 1920
    move-result-object v4

    .line 1921
    :goto_2c
    new-instance v5, Lcp0/a;

    .line 1922
    .line 1923
    invoke-direct {v5, v0, v1, v3, v4}, Lcp0/a;-><init>(Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 1924
    .line 1925
    .line 1926
    goto :goto_28

    .line 1927
    :goto_2d
    new-instance v16, Lcp0/c;

    .line 1928
    .line 1929
    move-object/from16 v21, v6

    .line 1930
    .line 1931
    invoke-direct/range {v16 .. v23}, Lcp0/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Lcp0/a;Lcp0/a;Ljava/time/OffsetDateTime;)V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_a

    .line 1932
    .line 1933
    .line 1934
    goto :goto_2e

    .line 1935
    :cond_25
    move-object/from16 v16, v5

    .line 1936
    .line 1937
    :goto_2e
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 1938
    .line 1939
    .line 1940
    return-object v16

    .line 1941
    :goto_2f
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 1942
    .line 1943
    .line 1944
    throw v0

    .line 1945
    :pswitch_1b
    move-object/from16 v1, p1

    .line 1946
    .line 1947
    check-cast v1, Lhi/a;

    .line 1948
    .line 1949
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1950
    .line 1951
    .line 1952
    const-class v2, Lyf/d;

    .line 1953
    .line 1954
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1955
    .line 1956
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1957
    .line 1958
    .line 1959
    move-result-object v2

    .line 1960
    check-cast v1, Lii/a;

    .line 1961
    .line 1962
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 1963
    .line 1964
    .line 1965
    move-result-object v1

    .line 1966
    move-object v4, v1

    .line 1967
    check-cast v4, Lyf/d;

    .line 1968
    .line 1969
    new-instance v1, Lag/u;

    .line 1970
    .line 1971
    new-instance v2, Lag/c;

    .line 1972
    .line 1973
    const/4 v8, 0x0

    .line 1974
    const/4 v9, 0x0

    .line 1975
    const/4 v3, 0x2

    .line 1976
    const-class v5, Lyf/d;

    .line 1977
    .line 1978
    const-string v6, "getOverview"

    .line 1979
    .line 1980
    const-string v7, "getOverview-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 1981
    .line 1982
    invoke-direct/range {v2 .. v9}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 1983
    .line 1984
    .line 1985
    move-object v10, v2

    .line 1986
    new-instance v2, Lag/c;

    .line 1987
    .line 1988
    const/4 v9, 0x1

    .line 1989
    const-class v5, Lyf/d;

    .line 1990
    .line 1991
    const-string v6, "postActivateContract"

    .line 1992
    .line 1993
    const-string v7, "postActivateContract-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 1994
    .line 1995
    invoke-direct/range {v2 .. v9}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 1996
    .line 1997
    .line 1998
    move-object v11, v2

    .line 1999
    new-instance v2, Lag/c;

    .line 2000
    .line 2001
    const/4 v9, 0x2

    .line 2002
    const-class v5, Lyf/d;

    .line 2003
    .line 2004
    const-string v6, "postDeactivateContract"

    .line 2005
    .line 2006
    const-string v7, "postDeactivateContract-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 2007
    .line 2008
    invoke-direct/range {v2 .. v9}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 2009
    .line 2010
    .line 2011
    invoke-direct {v1, v0, v10, v11, v2}, Lag/u;-><init>(Ljava/lang/String;Lag/c;Lag/c;Lag/c;)V

    .line 2012
    .line 2013
    .line 2014
    return-object v1

    .line 2015
    :pswitch_1c
    const/4 v2, 0x0

    .line 2016
    move-object/from16 v1, p1

    .line 2017
    .line 2018
    check-cast v1, Lac0/k;

    .line 2019
    .line 2020
    instance-of v4, v1, Lac0/i;

    .line 2021
    .line 2022
    if-eqz v4, :cond_26

    .line 2023
    .line 2024
    check-cast v1, Lac0/i;

    .line 2025
    .line 2026
    iget-object v1, v1, Lac0/i;->a:Ljava/lang/String;

    .line 2027
    .line 2028
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2029
    .line 2030
    .line 2031
    move-result v0

    .line 2032
    if-eqz v0, :cond_26

    .line 2033
    .line 2034
    move v2, v3

    .line 2035
    :cond_26
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2036
    .line 2037
    .line 2038
    move-result-object v0

    .line 2039
    return-object v0

    .line 2040
    nop

    .line 2041
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

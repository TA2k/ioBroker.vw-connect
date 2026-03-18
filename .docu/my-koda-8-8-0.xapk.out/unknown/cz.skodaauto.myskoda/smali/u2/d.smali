.class public final synthetic Lu2/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lu2/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lu2/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 41

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lu2/d;->d:I

    .line 4
    .line 5
    const-string v1, "phone"

    .line 6
    .line 7
    const-string v2, "dateOfBirth"

    .line 8
    .line 9
    const-string v3, "preferredLanguageCode"

    .line 10
    .line 11
    const-string v4, "countryOfResidenceCode"

    .line 12
    .line 13
    const-string v5, "countryCode"

    .line 14
    .line 15
    const-string v6, "nickname"

    .line 16
    .line 17
    const-string v7, "lastName"

    .line 18
    .line 19
    const-string v8, "firstName"

    .line 20
    .line 21
    const-string v9, "email"

    .line 22
    .line 23
    const-string v10, "userId"

    .line 24
    .line 25
    const-string v11, "SELECT * FROM user LIMIT 1"

    .line 26
    .line 27
    const-string v12, "SELECT userId FROM user LIMIT 1"

    .line 28
    .line 29
    const-string v13, "$this$log"

    .line 30
    .line 31
    const-string v15, "it"

    .line 32
    .line 33
    const-string v14, "id"

    .line 34
    .line 35
    const/16 v16, 0x1

    .line 36
    .line 37
    move/from16 v17, v0

    .line 38
    .line 39
    const-string v0, "$this$request"

    .line 40
    .line 41
    sget-object v19, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    move-object/from16 v20, v13

    .line 44
    .line 45
    const-string v13, "_connection"

    .line 46
    .line 47
    packed-switch v17, :pswitch_data_0

    .line 48
    .line 49
    .line 50
    move-object/from16 v0, p1

    .line 51
    .line 52
    check-cast v0, Lsp/e;

    .line 53
    .line 54
    invoke-static {v0, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    return-object v19

    .line 58
    :pswitch_0
    move-object/from16 v0, p1

    .line 59
    .line 60
    check-cast v0, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 61
    .line 62
    invoke-static {v0, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    new-instance v1, Luu/g;

    .line 66
    .line 67
    invoke-direct {v1, v0}, Luu/g;-><init>(Lcom/google/android/gms/maps/model/CameraPosition;)V

    .line 68
    .line 69
    .line 70
    return-object v1

    .line 71
    :pswitch_1
    move-object/from16 v0, p1

    .line 72
    .line 73
    check-cast v0, Lua/a;

    .line 74
    .line 75
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string v1, "DELETE FROM vehicle_backups_notice"

    .line 79
    .line 80
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    :try_start_0
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    .line 86
    .line 87
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 88
    .line 89
    .line 90
    return-object v19

    .line 91
    :catchall_0
    move-exception v0

    .line 92
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 93
    .line 94
    .line 95
    throw v0

    .line 96
    :pswitch_2
    move-object/from16 v1, p1

    .line 97
    .line 98
    check-cast v1, Lcz/myskoda/api/bff/v1/VehicleServicesBackupsDto;

    .line 99
    .line 100
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/VehicleServicesBackupsDto;->getVehicleServicesBackups()Ljava/util/List;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    check-cast v0, Ljava/util/Collection;

    .line 108
    .line 109
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    xor-int/lit8 v0, v0, 0x1

    .line 114
    .line 115
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    return-object v0

    .line 120
    :pswitch_3
    move-object/from16 v0, p1

    .line 121
    .line 122
    check-cast v0, Lyr0/f;

    .line 123
    .line 124
    invoke-static {v0, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    return-object v0

    .line 132
    :pswitch_4
    move-object/from16 v0, p1

    .line 133
    .line 134
    check-cast v0, Lua/a;

    .line 135
    .line 136
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    const-string v1, "DELETE from user"

    .line 140
    .line 141
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    :try_start_1
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 146
    .line 147
    .line 148
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 149
    .line 150
    .line 151
    return-object v19

    .line 152
    :catchall_1
    move-exception v0

    .line 153
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 154
    .line 155
    .line 156
    throw v0

    .line 157
    :pswitch_5
    move-object/from16 v0, p1

    .line 158
    .line 159
    check-cast v0, Lua/a;

    .line 160
    .line 161
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    invoke-interface {v0, v12}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    :try_start_2
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 169
    .line 170
    .line 171
    move-result v0

    .line 172
    if-eqz v0, :cond_0

    .line 173
    .line 174
    const/4 v0, 0x0

    .line 175
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 176
    .line 177
    .line 178
    move-result v2

    .line 179
    if-eqz v2, :cond_1

    .line 180
    .line 181
    :cond_0
    const/4 v13, 0x0

    .line 182
    goto :goto_0

    .line 183
    :cond_1
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v13
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 187
    goto :goto_0

    .line 188
    :catchall_2
    move-exception v0

    .line 189
    goto :goto_1

    .line 190
    :goto_0
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 191
    .line 192
    .line 193
    return-object v13

    .line 194
    :goto_1
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 195
    .line 196
    .line 197
    throw v0

    .line 198
    :pswitch_6
    move-object/from16 v0, p1

    .line 199
    .line 200
    check-cast v0, Lua/a;

    .line 201
    .line 202
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    invoke-interface {v0, v11}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 206
    .line 207
    .line 208
    move-result-object v11

    .line 209
    :try_start_3
    invoke-static {v11, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 210
    .line 211
    .line 212
    move-result v0

    .line 213
    invoke-static {v11, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 214
    .line 215
    .line 216
    move-result v10

    .line 217
    invoke-static {v11, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 218
    .line 219
    .line 220
    move-result v9

    .line 221
    invoke-static {v11, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 222
    .line 223
    .line 224
    move-result v8

    .line 225
    invoke-static {v11, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 226
    .line 227
    .line 228
    move-result v7

    .line 229
    invoke-static {v11, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 230
    .line 231
    .line 232
    move-result v6

    .line 233
    invoke-static {v11, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 234
    .line 235
    .line 236
    move-result v5

    .line 237
    invoke-static {v11, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 238
    .line 239
    .line 240
    move-result v4

    .line 241
    invoke-static {v11, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 242
    .line 243
    .line 244
    move-result v3

    .line 245
    invoke-static {v11, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 246
    .line 247
    .line 248
    move-result v2

    .line 249
    invoke-static {v11, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    const-string v12, "preferredContactChannel"

    .line 254
    .line 255
    invoke-static {v11, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 256
    .line 257
    .line 258
    move-result v12

    .line 259
    const-string v13, "profilePictureUrl"

    .line 260
    .line 261
    invoke-static {v11, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 262
    .line 263
    .line 264
    move-result v13

    .line 265
    const-string v14, "billingAddressCountry"

    .line 266
    .line 267
    invoke-static {v11, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 268
    .line 269
    .line 270
    move-result v14

    .line 271
    const-string v15, "billingAddressCity"

    .line 272
    .line 273
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 274
    .line 275
    .line 276
    move-result v15

    .line 277
    move/from16 p0, v15

    .line 278
    .line 279
    const-string v15, "billingAddressStreet"

    .line 280
    .line 281
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 282
    .line 283
    .line 284
    move-result v15

    .line 285
    move/from16 p1, v15

    .line 286
    .line 287
    const-string v15, "billingAddressHouseNumber"

    .line 288
    .line 289
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 290
    .line 291
    .line 292
    move-result v15

    .line 293
    move/from16 v16, v15

    .line 294
    .line 295
    const-string v15, "billingAddressZipCode"

    .line 296
    .line 297
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 298
    .line 299
    .line 300
    move-result v15

    .line 301
    move/from16 v17, v15

    .line 302
    .line 303
    const-string v15, "capabilityIds"

    .line 304
    .line 305
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 306
    .line 307
    .line 308
    move-result v15

    .line 309
    invoke-interface {v11}, Lua/c;->s0()Z

    .line 310
    .line 311
    .line 312
    move-result v18

    .line 313
    if-eqz v18, :cond_12

    .line 314
    .line 315
    move/from16 v18, v14

    .line 316
    .line 317
    move/from16 v19, v15

    .line 318
    .line 319
    invoke-interface {v11, v0}, Lua/c;->getLong(I)J

    .line 320
    .line 321
    .line 322
    move-result-wide v14

    .line 323
    long-to-int v0, v14

    .line 324
    invoke-interface {v11, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 325
    .line 326
    .line 327
    move-result-object v23

    .line 328
    invoke-interface {v11, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 329
    .line 330
    .line 331
    move-result-object v24

    .line 332
    invoke-interface {v11, v8}, Lua/c;->isNull(I)Z

    .line 333
    .line 334
    .line 335
    move-result v9

    .line 336
    if-eqz v9, :cond_2

    .line 337
    .line 338
    const/16 v25, 0x0

    .line 339
    .line 340
    goto :goto_2

    .line 341
    :cond_2
    invoke-interface {v11, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v8

    .line 345
    move-object/from16 v25, v8

    .line 346
    .line 347
    :goto_2
    invoke-interface {v11, v7}, Lua/c;->isNull(I)Z

    .line 348
    .line 349
    .line 350
    move-result v8

    .line 351
    if-eqz v8, :cond_3

    .line 352
    .line 353
    const/16 v26, 0x0

    .line 354
    .line 355
    goto :goto_3

    .line 356
    :cond_3
    invoke-interface {v11, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object v7

    .line 360
    move-object/from16 v26, v7

    .line 361
    .line 362
    :goto_3
    invoke-interface {v11, v6}, Lua/c;->isNull(I)Z

    .line 363
    .line 364
    .line 365
    move-result v7

    .line 366
    if-eqz v7, :cond_4

    .line 367
    .line 368
    const/16 v27, 0x0

    .line 369
    .line 370
    goto :goto_4

    .line 371
    :cond_4
    invoke-interface {v11, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 372
    .line 373
    .line 374
    move-result-object v6

    .line 375
    move-object/from16 v27, v6

    .line 376
    .line 377
    :goto_4
    invoke-interface {v11, v5}, Lua/c;->isNull(I)Z

    .line 378
    .line 379
    .line 380
    move-result v6

    .line 381
    if-eqz v6, :cond_5

    .line 382
    .line 383
    const/16 v28, 0x0

    .line 384
    .line 385
    goto :goto_5

    .line 386
    :cond_5
    invoke-interface {v11, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 387
    .line 388
    .line 389
    move-result-object v5

    .line 390
    move-object/from16 v28, v5

    .line 391
    .line 392
    :goto_5
    invoke-interface {v11, v4}, Lua/c;->isNull(I)Z

    .line 393
    .line 394
    .line 395
    move-result v5

    .line 396
    if-eqz v5, :cond_6

    .line 397
    .line 398
    const/16 v29, 0x0

    .line 399
    .line 400
    goto :goto_6

    .line 401
    :cond_6
    invoke-interface {v11, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object v4

    .line 405
    move-object/from16 v29, v4

    .line 406
    .line 407
    :goto_6
    invoke-interface {v11, v3}, Lua/c;->isNull(I)Z

    .line 408
    .line 409
    .line 410
    move-result v4

    .line 411
    if-eqz v4, :cond_7

    .line 412
    .line 413
    const/16 v30, 0x0

    .line 414
    .line 415
    goto :goto_7

    .line 416
    :cond_7
    invoke-interface {v11, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 417
    .line 418
    .line 419
    move-result-object v3

    .line 420
    move-object/from16 v30, v3

    .line 421
    .line 422
    :goto_7
    invoke-interface {v11, v2}, Lua/c;->isNull(I)Z

    .line 423
    .line 424
    .line 425
    move-result v3

    .line 426
    if-eqz v3, :cond_8

    .line 427
    .line 428
    const/4 v2, 0x0

    .line 429
    goto :goto_8

    .line 430
    :cond_8
    invoke-interface {v11, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 431
    .line 432
    .line 433
    move-result-object v2

    .line 434
    :goto_8
    invoke-static {v2}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 435
    .line 436
    .line 437
    move-result-object v31

    .line 438
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 439
    .line 440
    .line 441
    move-result v2

    .line 442
    if-eqz v2, :cond_9

    .line 443
    .line 444
    const/16 v32, 0x0

    .line 445
    .line 446
    goto :goto_9

    .line 447
    :cond_9
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 448
    .line 449
    .line 450
    move-result-object v1

    .line 451
    move-object/from16 v32, v1

    .line 452
    .line 453
    :goto_9
    invoke-interface {v11, v12}, Lua/c;->isNull(I)Z

    .line 454
    .line 455
    .line 456
    move-result v1

    .line 457
    if-eqz v1, :cond_a

    .line 458
    .line 459
    const/16 v33, 0x0

    .line 460
    .line 461
    goto :goto_a

    .line 462
    :cond_a
    invoke-interface {v11, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 463
    .line 464
    .line 465
    move-result-object v1

    .line 466
    invoke-static {v1}, Lur0/h;->a(Ljava/lang/String;)Lyr0/c;

    .line 467
    .line 468
    .line 469
    move-result-object v1

    .line 470
    move-object/from16 v33, v1

    .line 471
    .line 472
    :goto_a
    invoke-interface {v11, v13}, Lua/c;->isNull(I)Z

    .line 473
    .line 474
    .line 475
    move-result v1

    .line 476
    if-eqz v1, :cond_b

    .line 477
    .line 478
    const/16 v34, 0x0

    .line 479
    .line 480
    :goto_b
    move/from16 v1, v18

    .line 481
    .line 482
    goto :goto_c

    .line 483
    :cond_b
    invoke-interface {v11, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 484
    .line 485
    .line 486
    move-result-object v1

    .line 487
    move-object/from16 v34, v1

    .line 488
    .line 489
    goto :goto_b

    .line 490
    :goto_c
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 491
    .line 492
    .line 493
    move-result v2

    .line 494
    if-eqz v2, :cond_c

    .line 495
    .line 496
    const/16 v35, 0x0

    .line 497
    .line 498
    :goto_d
    move/from16 v1, p0

    .line 499
    .line 500
    goto :goto_e

    .line 501
    :cond_c
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 502
    .line 503
    .line 504
    move-result-object v1

    .line 505
    move-object/from16 v35, v1

    .line 506
    .line 507
    goto :goto_d

    .line 508
    :goto_e
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 509
    .line 510
    .line 511
    move-result v2

    .line 512
    if-eqz v2, :cond_d

    .line 513
    .line 514
    const/16 v36, 0x0

    .line 515
    .line 516
    :goto_f
    move/from16 v1, p1

    .line 517
    .line 518
    goto :goto_10

    .line 519
    :cond_d
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 520
    .line 521
    .line 522
    move-result-object v1

    .line 523
    move-object/from16 v36, v1

    .line 524
    .line 525
    goto :goto_f

    .line 526
    :goto_10
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 527
    .line 528
    .line 529
    move-result v2

    .line 530
    if-eqz v2, :cond_e

    .line 531
    .line 532
    const/16 v37, 0x0

    .line 533
    .line 534
    :goto_11
    move/from16 v1, v16

    .line 535
    .line 536
    goto :goto_12

    .line 537
    :cond_e
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 538
    .line 539
    .line 540
    move-result-object v1

    .line 541
    move-object/from16 v37, v1

    .line 542
    .line 543
    goto :goto_11

    .line 544
    :goto_12
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 545
    .line 546
    .line 547
    move-result v2

    .line 548
    if-eqz v2, :cond_f

    .line 549
    .line 550
    const/16 v38, 0x0

    .line 551
    .line 552
    :goto_13
    move/from16 v1, v17

    .line 553
    .line 554
    goto :goto_14

    .line 555
    :cond_f
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 556
    .line 557
    .line 558
    move-result-object v1

    .line 559
    move-object/from16 v38, v1

    .line 560
    .line 561
    goto :goto_13

    .line 562
    :goto_14
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 563
    .line 564
    .line 565
    move-result v2

    .line 566
    if-eqz v2, :cond_10

    .line 567
    .line 568
    const/16 v39, 0x0

    .line 569
    .line 570
    :goto_15
    move/from16 v1, v19

    .line 571
    .line 572
    goto :goto_16

    .line 573
    :cond_10
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 574
    .line 575
    .line 576
    move-result-object v1

    .line 577
    move-object/from16 v39, v1

    .line 578
    .line 579
    goto :goto_15

    .line 580
    :goto_16
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 581
    .line 582
    .line 583
    move-result v2

    .line 584
    if-eqz v2, :cond_11

    .line 585
    .line 586
    const/16 v40, 0x0

    .line 587
    .line 588
    goto :goto_17

    .line 589
    :cond_11
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 590
    .line 591
    .line 592
    move-result-object v13

    .line 593
    move-object/from16 v40, v13

    .line 594
    .line 595
    :goto_17
    new-instance v21, Lur0/i;

    .line 596
    .line 597
    move/from16 v22, v0

    .line 598
    .line 599
    invoke-direct/range {v21 .. v40}, Lur0/i;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Lyr0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 600
    .line 601
    .line 602
    move-object/from16 v13, v21

    .line 603
    .line 604
    goto :goto_18

    .line 605
    :catchall_3
    move-exception v0

    .line 606
    goto :goto_19

    .line 607
    :cond_12
    const/4 v13, 0x0

    .line 608
    :goto_18
    invoke-interface {v11}, Ljava/lang/AutoCloseable;->close()V

    .line 609
    .line 610
    .line 611
    return-object v13

    .line 612
    :goto_19
    invoke-interface {v11}, Ljava/lang/AutoCloseable;->close()V

    .line 613
    .line 614
    .line 615
    throw v0

    .line 616
    :pswitch_7
    move-object/from16 v0, p1

    .line 617
    .line 618
    check-cast v0, Lua/a;

    .line 619
    .line 620
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 621
    .line 622
    .line 623
    invoke-interface {v0, v11}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 624
    .line 625
    .line 626
    move-result-object v11

    .line 627
    :try_start_4
    invoke-static {v11, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 628
    .line 629
    .line 630
    move-result v0

    .line 631
    invoke-static {v11, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 632
    .line 633
    .line 634
    move-result v10

    .line 635
    invoke-static {v11, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 636
    .line 637
    .line 638
    move-result v9

    .line 639
    invoke-static {v11, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 640
    .line 641
    .line 642
    move-result v8

    .line 643
    invoke-static {v11, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 644
    .line 645
    .line 646
    move-result v7

    .line 647
    invoke-static {v11, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 648
    .line 649
    .line 650
    move-result v6

    .line 651
    invoke-static {v11, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 652
    .line 653
    .line 654
    move-result v5

    .line 655
    invoke-static {v11, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 656
    .line 657
    .line 658
    move-result v4

    .line 659
    invoke-static {v11, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 660
    .line 661
    .line 662
    move-result v3

    .line 663
    invoke-static {v11, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 664
    .line 665
    .line 666
    move-result v2

    .line 667
    invoke-static {v11, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 668
    .line 669
    .line 670
    move-result v1

    .line 671
    const-string v12, "preferredContactChannel"

    .line 672
    .line 673
    invoke-static {v11, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 674
    .line 675
    .line 676
    move-result v12

    .line 677
    const-string v13, "profilePictureUrl"

    .line 678
    .line 679
    invoke-static {v11, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 680
    .line 681
    .line 682
    move-result v13

    .line 683
    const-string v14, "billingAddressCountry"

    .line 684
    .line 685
    invoke-static {v11, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 686
    .line 687
    .line 688
    move-result v14

    .line 689
    const-string v15, "billingAddressCity"

    .line 690
    .line 691
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 692
    .line 693
    .line 694
    move-result v15

    .line 695
    move/from16 p0, v15

    .line 696
    .line 697
    const-string v15, "billingAddressStreet"

    .line 698
    .line 699
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 700
    .line 701
    .line 702
    move-result v15

    .line 703
    move/from16 p1, v15

    .line 704
    .line 705
    const-string v15, "billingAddressHouseNumber"

    .line 706
    .line 707
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 708
    .line 709
    .line 710
    move-result v15

    .line 711
    move/from16 v16, v15

    .line 712
    .line 713
    const-string v15, "billingAddressZipCode"

    .line 714
    .line 715
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 716
    .line 717
    .line 718
    move-result v15

    .line 719
    move/from16 v17, v15

    .line 720
    .line 721
    const-string v15, "capabilityIds"

    .line 722
    .line 723
    invoke-static {v11, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 724
    .line 725
    .line 726
    move-result v15

    .line 727
    invoke-interface {v11}, Lua/c;->s0()Z

    .line 728
    .line 729
    .line 730
    move-result v18

    .line 731
    if-eqz v18, :cond_23

    .line 732
    .line 733
    move/from16 v18, v14

    .line 734
    .line 735
    move/from16 v19, v15

    .line 736
    .line 737
    invoke-interface {v11, v0}, Lua/c;->getLong(I)J

    .line 738
    .line 739
    .line 740
    move-result-wide v14

    .line 741
    long-to-int v0, v14

    .line 742
    invoke-interface {v11, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 743
    .line 744
    .line 745
    move-result-object v23

    .line 746
    invoke-interface {v11, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 747
    .line 748
    .line 749
    move-result-object v24

    .line 750
    invoke-interface {v11, v8}, Lua/c;->isNull(I)Z

    .line 751
    .line 752
    .line 753
    move-result v9

    .line 754
    if-eqz v9, :cond_13

    .line 755
    .line 756
    const/16 v25, 0x0

    .line 757
    .line 758
    goto :goto_1a

    .line 759
    :cond_13
    invoke-interface {v11, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 760
    .line 761
    .line 762
    move-result-object v8

    .line 763
    move-object/from16 v25, v8

    .line 764
    .line 765
    :goto_1a
    invoke-interface {v11, v7}, Lua/c;->isNull(I)Z

    .line 766
    .line 767
    .line 768
    move-result v8

    .line 769
    if-eqz v8, :cond_14

    .line 770
    .line 771
    const/16 v26, 0x0

    .line 772
    .line 773
    goto :goto_1b

    .line 774
    :cond_14
    invoke-interface {v11, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 775
    .line 776
    .line 777
    move-result-object v7

    .line 778
    move-object/from16 v26, v7

    .line 779
    .line 780
    :goto_1b
    invoke-interface {v11, v6}, Lua/c;->isNull(I)Z

    .line 781
    .line 782
    .line 783
    move-result v7

    .line 784
    if-eqz v7, :cond_15

    .line 785
    .line 786
    const/16 v27, 0x0

    .line 787
    .line 788
    goto :goto_1c

    .line 789
    :cond_15
    invoke-interface {v11, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 790
    .line 791
    .line 792
    move-result-object v6

    .line 793
    move-object/from16 v27, v6

    .line 794
    .line 795
    :goto_1c
    invoke-interface {v11, v5}, Lua/c;->isNull(I)Z

    .line 796
    .line 797
    .line 798
    move-result v6

    .line 799
    if-eqz v6, :cond_16

    .line 800
    .line 801
    const/16 v28, 0x0

    .line 802
    .line 803
    goto :goto_1d

    .line 804
    :cond_16
    invoke-interface {v11, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 805
    .line 806
    .line 807
    move-result-object v5

    .line 808
    move-object/from16 v28, v5

    .line 809
    .line 810
    :goto_1d
    invoke-interface {v11, v4}, Lua/c;->isNull(I)Z

    .line 811
    .line 812
    .line 813
    move-result v5

    .line 814
    if-eqz v5, :cond_17

    .line 815
    .line 816
    const/16 v29, 0x0

    .line 817
    .line 818
    goto :goto_1e

    .line 819
    :cond_17
    invoke-interface {v11, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 820
    .line 821
    .line 822
    move-result-object v4

    .line 823
    move-object/from16 v29, v4

    .line 824
    .line 825
    :goto_1e
    invoke-interface {v11, v3}, Lua/c;->isNull(I)Z

    .line 826
    .line 827
    .line 828
    move-result v4

    .line 829
    if-eqz v4, :cond_18

    .line 830
    .line 831
    const/16 v30, 0x0

    .line 832
    .line 833
    goto :goto_1f

    .line 834
    :cond_18
    invoke-interface {v11, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 835
    .line 836
    .line 837
    move-result-object v3

    .line 838
    move-object/from16 v30, v3

    .line 839
    .line 840
    :goto_1f
    invoke-interface {v11, v2}, Lua/c;->isNull(I)Z

    .line 841
    .line 842
    .line 843
    move-result v3

    .line 844
    if-eqz v3, :cond_19

    .line 845
    .line 846
    const/4 v2, 0x0

    .line 847
    goto :goto_20

    .line 848
    :cond_19
    invoke-interface {v11, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 849
    .line 850
    .line 851
    move-result-object v2

    .line 852
    :goto_20
    invoke-static {v2}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 853
    .line 854
    .line 855
    move-result-object v31

    .line 856
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 857
    .line 858
    .line 859
    move-result v2

    .line 860
    if-eqz v2, :cond_1a

    .line 861
    .line 862
    const/16 v32, 0x0

    .line 863
    .line 864
    goto :goto_21

    .line 865
    :cond_1a
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 866
    .line 867
    .line 868
    move-result-object v1

    .line 869
    move-object/from16 v32, v1

    .line 870
    .line 871
    :goto_21
    invoke-interface {v11, v12}, Lua/c;->isNull(I)Z

    .line 872
    .line 873
    .line 874
    move-result v1

    .line 875
    if-eqz v1, :cond_1b

    .line 876
    .line 877
    const/16 v33, 0x0

    .line 878
    .line 879
    goto :goto_22

    .line 880
    :cond_1b
    invoke-interface {v11, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 881
    .line 882
    .line 883
    move-result-object v1

    .line 884
    invoke-static {v1}, Lur0/h;->a(Ljava/lang/String;)Lyr0/c;

    .line 885
    .line 886
    .line 887
    move-result-object v1

    .line 888
    move-object/from16 v33, v1

    .line 889
    .line 890
    :goto_22
    invoke-interface {v11, v13}, Lua/c;->isNull(I)Z

    .line 891
    .line 892
    .line 893
    move-result v1

    .line 894
    if-eqz v1, :cond_1c

    .line 895
    .line 896
    const/16 v34, 0x0

    .line 897
    .line 898
    :goto_23
    move/from16 v1, v18

    .line 899
    .line 900
    goto :goto_24

    .line 901
    :cond_1c
    invoke-interface {v11, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 902
    .line 903
    .line 904
    move-result-object v1

    .line 905
    move-object/from16 v34, v1

    .line 906
    .line 907
    goto :goto_23

    .line 908
    :goto_24
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 909
    .line 910
    .line 911
    move-result v2

    .line 912
    if-eqz v2, :cond_1d

    .line 913
    .line 914
    const/16 v35, 0x0

    .line 915
    .line 916
    :goto_25
    move/from16 v1, p0

    .line 917
    .line 918
    goto :goto_26

    .line 919
    :cond_1d
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 920
    .line 921
    .line 922
    move-result-object v1

    .line 923
    move-object/from16 v35, v1

    .line 924
    .line 925
    goto :goto_25

    .line 926
    :goto_26
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 927
    .line 928
    .line 929
    move-result v2

    .line 930
    if-eqz v2, :cond_1e

    .line 931
    .line 932
    const/16 v36, 0x0

    .line 933
    .line 934
    :goto_27
    move/from16 v1, p1

    .line 935
    .line 936
    goto :goto_28

    .line 937
    :cond_1e
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 938
    .line 939
    .line 940
    move-result-object v1

    .line 941
    move-object/from16 v36, v1

    .line 942
    .line 943
    goto :goto_27

    .line 944
    :goto_28
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 945
    .line 946
    .line 947
    move-result v2

    .line 948
    if-eqz v2, :cond_1f

    .line 949
    .line 950
    const/16 v37, 0x0

    .line 951
    .line 952
    :goto_29
    move/from16 v1, v16

    .line 953
    .line 954
    goto :goto_2a

    .line 955
    :cond_1f
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 956
    .line 957
    .line 958
    move-result-object v1

    .line 959
    move-object/from16 v37, v1

    .line 960
    .line 961
    goto :goto_29

    .line 962
    :goto_2a
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 963
    .line 964
    .line 965
    move-result v2

    .line 966
    if-eqz v2, :cond_20

    .line 967
    .line 968
    const/16 v38, 0x0

    .line 969
    .line 970
    :goto_2b
    move/from16 v1, v17

    .line 971
    .line 972
    goto :goto_2c

    .line 973
    :cond_20
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 974
    .line 975
    .line 976
    move-result-object v1

    .line 977
    move-object/from16 v38, v1

    .line 978
    .line 979
    goto :goto_2b

    .line 980
    :goto_2c
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 981
    .line 982
    .line 983
    move-result v2

    .line 984
    if-eqz v2, :cond_21

    .line 985
    .line 986
    const/16 v39, 0x0

    .line 987
    .line 988
    :goto_2d
    move/from16 v1, v19

    .line 989
    .line 990
    goto :goto_2e

    .line 991
    :cond_21
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 992
    .line 993
    .line 994
    move-result-object v1

    .line 995
    move-object/from16 v39, v1

    .line 996
    .line 997
    goto :goto_2d

    .line 998
    :goto_2e
    invoke-interface {v11, v1}, Lua/c;->isNull(I)Z

    .line 999
    .line 1000
    .line 1001
    move-result v2

    .line 1002
    if-eqz v2, :cond_22

    .line 1003
    .line 1004
    const/16 v40, 0x0

    .line 1005
    .line 1006
    goto :goto_2f

    .line 1007
    :cond_22
    invoke-interface {v11, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v13

    .line 1011
    move-object/from16 v40, v13

    .line 1012
    .line 1013
    :goto_2f
    new-instance v21, Lur0/i;

    .line 1014
    .line 1015
    move/from16 v22, v0

    .line 1016
    .line 1017
    invoke-direct/range {v21 .. v40}, Lur0/i;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Lyr0/c;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 1018
    .line 1019
    .line 1020
    move-object/from16 v13, v21

    .line 1021
    .line 1022
    goto :goto_30

    .line 1023
    :catchall_4
    move-exception v0

    .line 1024
    goto :goto_31

    .line 1025
    :cond_23
    const/4 v13, 0x0

    .line 1026
    :goto_30
    invoke-interface {v11}, Ljava/lang/AutoCloseable;->close()V

    .line 1027
    .line 1028
    .line 1029
    return-object v13

    .line 1030
    :goto_31
    invoke-interface {v11}, Ljava/lang/AutoCloseable;->close()V

    .line 1031
    .line 1032
    .line 1033
    throw v0

    .line 1034
    :pswitch_8
    move-object/from16 v0, p1

    .line 1035
    .line 1036
    check-cast v0, Lua/a;

    .line 1037
    .line 1038
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1039
    .line 1040
    .line 1041
    invoke-interface {v0, v12}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1042
    .line 1043
    .line 1044
    move-result-object v1

    .line 1045
    :try_start_5
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1046
    .line 1047
    .line 1048
    move-result v0

    .line 1049
    if-eqz v0, :cond_24

    .line 1050
    .line 1051
    const/4 v0, 0x0

    .line 1052
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 1053
    .line 1054
    .line 1055
    move-result v2

    .line 1056
    if-eqz v2, :cond_25

    .line 1057
    .line 1058
    :cond_24
    const/4 v13, 0x0

    .line 1059
    goto :goto_32

    .line 1060
    :cond_25
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1061
    .line 1062
    .line 1063
    move-result-object v13
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 1064
    goto :goto_32

    .line 1065
    :catchall_5
    move-exception v0

    .line 1066
    goto :goto_33

    .line 1067
    :goto_32
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1068
    .line 1069
    .line 1070
    return-object v13

    .line 1071
    :goto_33
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1072
    .line 1073
    .line 1074
    throw v0

    .line 1075
    :pswitch_9
    move-object/from16 v1, p1

    .line 1076
    .line 1077
    check-cast v1, Lcz/myskoda/api/bff/v1/UserDto;

    .line 1078
    .line 1079
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1080
    .line 1081
    .line 1082
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getId()Ljava/lang/String;

    .line 1083
    .line 1084
    .line 1085
    move-result-object v3

    .line 1086
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getEmail()Ljava/lang/String;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v4

    .line 1090
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getFirstName()Ljava/lang/String;

    .line 1091
    .line 1092
    .line 1093
    move-result-object v5

    .line 1094
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getLastName()Ljava/lang/String;

    .line 1095
    .line 1096
    .line 1097
    move-result-object v6

    .line 1098
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getNickname()Ljava/lang/String;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v7

    .line 1102
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getCountry()Ljava/lang/String;

    .line 1103
    .line 1104
    .line 1105
    move-result-object v0

    .line 1106
    const-string v2, "Iso code doesn\'t match ISO 3166-1 Alpha-2"

    .line 1107
    .line 1108
    const-string v8, "toUpperCase(...)"

    .line 1109
    .line 1110
    const/4 v9, 0x2

    .line 1111
    if-eqz v0, :cond_27

    .line 1112
    .line 1113
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 1114
    .line 1115
    .line 1116
    move-result v10

    .line 1117
    if-ne v10, v9, :cond_26

    .line 1118
    .line 1119
    sget-object v10, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 1120
    .line 1121
    invoke-virtual {v0, v10}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1122
    .line 1123
    .line 1124
    move-result-object v0

    .line 1125
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1126
    .line 1127
    .line 1128
    goto :goto_34

    .line 1129
    :cond_26
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1130
    .line 1131
    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1132
    .line 1133
    .line 1134
    throw v0

    .line 1135
    :cond_27
    const/4 v0, 0x0

    .line 1136
    :goto_34
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getCountryOfResidence()Ljava/lang/String;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v10

    .line 1140
    if-eqz v10, :cond_29

    .line 1141
    .line 1142
    invoke-virtual {v10}, Ljava/lang/String;->length()I

    .line 1143
    .line 1144
    .line 1145
    move-result v11

    .line 1146
    if-ne v11, v9, :cond_28

    .line 1147
    .line 1148
    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 1149
    .line 1150
    invoke-virtual {v10, v2}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1151
    .line 1152
    .line 1153
    move-result-object v2

    .line 1154
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1155
    .line 1156
    .line 1157
    goto :goto_35

    .line 1158
    :cond_28
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1159
    .line 1160
    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1161
    .line 1162
    .line 1163
    throw v0

    .line 1164
    :cond_29
    const/4 v2, 0x0

    .line 1165
    :goto_35
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getPreferredLanguage()Ljava/lang/String;

    .line 1166
    .line 1167
    .line 1168
    move-result-object v8

    .line 1169
    if-eqz v8, :cond_2b

    .line 1170
    .line 1171
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 1172
    .line 1173
    .line 1174
    move-result v10

    .line 1175
    if-ne v10, v9, :cond_2a

    .line 1176
    .line 1177
    sget-object v9, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 1178
    .line 1179
    invoke-virtual {v8, v9}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1180
    .line 1181
    .line 1182
    move-result-object v8

    .line 1183
    const-string v9, "toLowerCase(...)"

    .line 1184
    .line 1185
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1186
    .line 1187
    .line 1188
    move-object v10, v8

    .line 1189
    goto :goto_36

    .line 1190
    :cond_2a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1191
    .line 1192
    const-string v1, "Iso code doesn\'t match ISO 639-1 code"

    .line 1193
    .line 1194
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1195
    .line 1196
    .line 1197
    throw v0

    .line 1198
    :cond_2b
    const/4 v10, 0x0

    .line 1199
    :goto_36
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getDateOfBirth()Ljava/time/LocalDate;

    .line 1200
    .line 1201
    .line 1202
    move-result-object v11

    .line 1203
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getPhone()Ljava/lang/String;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v12

    .line 1207
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getBillingAddress()Lcz/myskoda/api/bff/v1/BillingAddressDto;

    .line 1208
    .line 1209
    .line 1210
    move-result-object v8

    .line 1211
    if-eqz v8, :cond_2c

    .line 1212
    .line 1213
    new-instance v21, Lyr0/a;

    .line 1214
    .line 1215
    invoke-virtual {v8}, Lcz/myskoda/api/bff/v1/BillingAddressDto;->getCountry()Ljava/lang/String;

    .line 1216
    .line 1217
    .line 1218
    move-result-object v22

    .line 1219
    invoke-virtual {v8}, Lcz/myskoda/api/bff/v1/BillingAddressDto;->getCity()Ljava/lang/String;

    .line 1220
    .line 1221
    .line 1222
    move-result-object v23

    .line 1223
    invoke-virtual {v8}, Lcz/myskoda/api/bff/v1/BillingAddressDto;->getStreet()Ljava/lang/String;

    .line 1224
    .line 1225
    .line 1226
    move-result-object v24

    .line 1227
    invoke-virtual {v8}, Lcz/myskoda/api/bff/v1/BillingAddressDto;->getHouseNumber()Ljava/lang/String;

    .line 1228
    .line 1229
    .line 1230
    move-result-object v25

    .line 1231
    invoke-virtual {v8}, Lcz/myskoda/api/bff/v1/BillingAddressDto;->getZipCode()Ljava/lang/String;

    .line 1232
    .line 1233
    .line 1234
    move-result-object v26

    .line 1235
    invoke-direct/range {v21 .. v26}, Lyr0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 1236
    .line 1237
    .line 1238
    move-object/from16 v13, v21

    .line 1239
    .line 1240
    goto :goto_37

    .line 1241
    :cond_2c
    const/4 v13, 0x0

    .line 1242
    :goto_37
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/UserDto;->getPreferredContactChannel()Ljava/lang/String;

    .line 1243
    .line 1244
    .line 1245
    move-result-object v8

    .line 1246
    if-eqz v8, :cond_30

    .line 1247
    .line 1248
    sget-object v9, Lyr0/c;->e:Lmb/e;

    .line 1249
    .line 1250
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1251
    .line 1252
    .line 1253
    invoke-static {}, Lyr0/c;->values()[Lyr0/c;

    .line 1254
    .line 1255
    .line 1256
    move-result-object v14

    .line 1257
    array-length v15, v14

    .line 1258
    move-object/from16 p0, v0

    .line 1259
    .line 1260
    const/4 v0, 0x0

    .line 1261
    :goto_38
    if-ge v0, v15, :cond_2e

    .line 1262
    .line 1263
    move/from16 v16, v0

    .line 1264
    .line 1265
    aget-object v0, v14, v16

    .line 1266
    .line 1267
    move-object/from16 p1, v1

    .line 1268
    .line 1269
    iget-object v1, v0, Lyr0/c;->d:Ljava/lang/String;

    .line 1270
    .line 1271
    invoke-virtual {v1, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1272
    .line 1273
    .line 1274
    move-result v1

    .line 1275
    if-eqz v1, :cond_2d

    .line 1276
    .line 1277
    goto :goto_39

    .line 1278
    :cond_2d
    add-int/lit8 v0, v16, 0x1

    .line 1279
    .line 1280
    move-object/from16 v1, p1

    .line 1281
    .line 1282
    goto :goto_38

    .line 1283
    :cond_2e
    move-object/from16 p1, v1

    .line 1284
    .line 1285
    const/4 v0, 0x0

    .line 1286
    :goto_39
    if-nez v0, :cond_2f

    .line 1287
    .line 1288
    new-instance v0, Lq61/c;

    .line 1289
    .line 1290
    const/16 v1, 0x14

    .line 1291
    .line 1292
    invoke-direct {v0, v8, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 1293
    .line 1294
    .line 1295
    const/4 v1, 0x0

    .line 1296
    invoke-static {v1, v9, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 1297
    .line 1298
    .line 1299
    const/4 v0, 0x0

    .line 1300
    :cond_2f
    move-object v14, v0

    .line 1301
    goto :goto_3a

    .line 1302
    :cond_30
    move-object/from16 p0, v0

    .line 1303
    .line 1304
    move-object/from16 p1, v1

    .line 1305
    .line 1306
    const/4 v14, 0x0

    .line 1307
    :goto_3a
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff/v1/UserDto;->getProfilePictureUrl()Ljava/lang/String;

    .line 1308
    .line 1309
    .line 1310
    move-result-object v15

    .line 1311
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff/v1/UserDto;->getCapabilities()Ljava/util/List;

    .line 1312
    .line 1313
    .line 1314
    move-result-object v0

    .line 1315
    check-cast v0, Ljava/lang/Iterable;

    .line 1316
    .line 1317
    new-instance v1, Ljava/util/ArrayList;

    .line 1318
    .line 1319
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 1320
    .line 1321
    .line 1322
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1323
    .line 1324
    .line 1325
    move-result-object v0

    .line 1326
    :cond_31
    :goto_3b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1327
    .line 1328
    .line 1329
    move-result v8

    .line 1330
    if-eqz v8, :cond_3b

    .line 1331
    .line 1332
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1333
    .line 1334
    .line 1335
    move-result-object v8

    .line 1336
    check-cast v8, Lcz/myskoda/api/bff/v1/UserCapabilityDto;

    .line 1337
    .line 1338
    invoke-virtual {v8}, Lcz/myskoda/api/bff/v1/UserCapabilityDto;->getId()Ljava/lang/String;

    .line 1339
    .line 1340
    .line 1341
    move-result-object v8

    .line 1342
    invoke-virtual {v8}, Ljava/lang/String;->hashCode()I

    .line 1343
    .line 1344
    .line 1345
    move-result v9

    .line 1346
    sparse-switch v9, :sswitch_data_0

    .line 1347
    .line 1348
    .line 1349
    goto/16 :goto_3c

    .line 1350
    .line 1351
    :sswitch_0
    const-string v9, "MARKETING_CONSENT_SAD_DEALERS"

    .line 1352
    .line 1353
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1354
    .line 1355
    .line 1356
    move-result v8

    .line 1357
    if-nez v8, :cond_32

    .line 1358
    .line 1359
    goto/16 :goto_3c

    .line 1360
    .line 1361
    :cond_32
    sget-object v8, Lyr0/f;->h:Lyr0/f;

    .line 1362
    .line 1363
    goto/16 :goto_3d

    .line 1364
    .line 1365
    :sswitch_1
    const-string v9, "MARKETING_CONSENT_SAD"

    .line 1366
    .line 1367
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1368
    .line 1369
    .line 1370
    move-result v8

    .line 1371
    if-nez v8, :cond_33

    .line 1372
    .line 1373
    goto :goto_3c

    .line 1374
    :cond_33
    sget-object v8, Lyr0/f;->g:Lyr0/f;

    .line 1375
    .line 1376
    goto :goto_3d

    .line 1377
    :sswitch_2
    const-string v9, "MARKETING_CONSENT_GENERIC"

    .line 1378
    .line 1379
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1380
    .line 1381
    .line 1382
    move-result v8

    .line 1383
    if-nez v8, :cond_34

    .line 1384
    .line 1385
    goto :goto_3c

    .line 1386
    :cond_34
    sget-object v8, Lyr0/f;->f:Lyr0/f;

    .line 1387
    .line 1388
    goto :goto_3d

    .line 1389
    :sswitch_3
    const-string v9, "THIRD_PARTY_OFFERS"

    .line 1390
    .line 1391
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1392
    .line 1393
    .line 1394
    move-result v8

    .line 1395
    if-nez v8, :cond_35

    .line 1396
    .line 1397
    goto :goto_3c

    .line 1398
    :cond_35
    sget-object v8, Lyr0/f;->e:Lyr0/f;

    .line 1399
    .line 1400
    goto :goto_3d

    .line 1401
    :sswitch_4
    const-string v9, "SPIN_MANAGEMENT"

    .line 1402
    .line 1403
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1404
    .line 1405
    .line 1406
    move-result v8

    .line 1407
    if-eqz v8, :cond_39

    .line 1408
    .line 1409
    sget-object v8, Lyr0/f;->d:Lyr0/f;

    .line 1410
    .line 1411
    goto :goto_3d

    .line 1412
    :sswitch_5
    const-string v9, "TEST_DRIVE"

    .line 1413
    .line 1414
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1415
    .line 1416
    .line 1417
    move-result v8

    .line 1418
    if-nez v8, :cond_36

    .line 1419
    .line 1420
    goto :goto_3c

    .line 1421
    :cond_36
    sget-object v8, Lyr0/f;->j:Lyr0/f;

    .line 1422
    .line 1423
    goto :goto_3d

    .line 1424
    :sswitch_6
    const-string v9, "LOYALTY_PROGRAM"

    .line 1425
    .line 1426
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1427
    .line 1428
    .line 1429
    move-result v8

    .line 1430
    if-nez v8, :cond_37

    .line 1431
    .line 1432
    goto :goto_3c

    .line 1433
    :cond_37
    sget-object v8, Lyr0/f;->k:Lyr0/f;

    .line 1434
    .line 1435
    goto :goto_3d

    .line 1436
    :sswitch_7
    const-string v9, "MARKETING_CONSENT_SAD_THIRDPARTY"

    .line 1437
    .line 1438
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1439
    .line 1440
    .line 1441
    move-result v8

    .line 1442
    if-nez v8, :cond_38

    .line 1443
    .line 1444
    goto :goto_3c

    .line 1445
    :cond_38
    sget-object v8, Lyr0/f;->i:Lyr0/f;

    .line 1446
    .line 1447
    goto :goto_3d

    .line 1448
    :sswitch_8
    const-string v9, "LOYALTY_PROGRAM_GAMES"

    .line 1449
    .line 1450
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1451
    .line 1452
    .line 1453
    move-result v8

    .line 1454
    if-nez v8, :cond_3a

    .line 1455
    .line 1456
    :cond_39
    :goto_3c
    const/4 v8, 0x0

    .line 1457
    goto :goto_3d

    .line 1458
    :cond_3a
    sget-object v8, Lyr0/f;->l:Lyr0/f;

    .line 1459
    .line 1460
    :goto_3d
    if-eqz v8, :cond_31

    .line 1461
    .line 1462
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1463
    .line 1464
    .line 1465
    goto/16 :goto_3b

    .line 1466
    .line 1467
    :cond_3b
    new-instance v0, Lyr0/e;

    .line 1468
    .line 1469
    move-object/from16 v8, p0

    .line 1470
    .line 1471
    move-object/from16 v16, v1

    .line 1472
    .line 1473
    move-object v9, v2

    .line 1474
    move-object v2, v0

    .line 1475
    invoke-direct/range {v2 .. v16}, Lyr0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Lyr0/a;Lyr0/c;Ljava/lang/String;Ljava/util/List;)V

    .line 1476
    .line 1477
    .line 1478
    return-object v2

    .line 1479
    :pswitch_a
    move-object/from16 v0, p1

    .line 1480
    .line 1481
    check-cast v0, Le21/a;

    .line 1482
    .line 1483
    const-string v1, "$this$module"

    .line 1484
    .line 1485
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1486
    .line 1487
    .line 1488
    new-instance v6, Lth0/a;

    .line 1489
    .line 1490
    const/16 v1, 0x18

    .line 1491
    .line 1492
    invoke-direct {v6, v1}, Lth0/a;-><init>(I)V

    .line 1493
    .line 1494
    .line 1495
    sget-object v8, Li21/b;->e:Lh21/b;

    .line 1496
    .line 1497
    sget-object v12, La21/c;->e:La21/c;

    .line 1498
    .line 1499
    new-instance v2, La21/a;

    .line 1500
    .line 1501
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1502
    .line 1503
    const-class v3, Lvm0/a;

    .line 1504
    .line 1505
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1506
    .line 1507
    .line 1508
    move-result-object v4

    .line 1509
    const/4 v5, 0x0

    .line 1510
    move-object v3, v8

    .line 1511
    move-object v7, v12

    .line 1512
    invoke-direct/range {v2 .. v7}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 1513
    .line 1514
    .line 1515
    new-instance v3, Lc21/a;

    .line 1516
    .line 1517
    invoke-direct {v3, v2}, Lc21/b;-><init>(La21/a;)V

    .line 1518
    .line 1519
    .line 1520
    invoke-virtual {v0, v3}, Le21/a;->a(Lc21/b;)V

    .line 1521
    .line 1522
    .line 1523
    new-instance v11, Lth0/a;

    .line 1524
    .line 1525
    const/16 v2, 0x19

    .line 1526
    .line 1527
    invoke-direct {v11, v2}, Lth0/a;-><init>(I)V

    .line 1528
    .line 1529
    .line 1530
    new-instance v7, La21/a;

    .line 1531
    .line 1532
    const-class v2, Lvm0/c;

    .line 1533
    .line 1534
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1535
    .line 1536
    .line 1537
    move-result-object v9

    .line 1538
    const/4 v10, 0x0

    .line 1539
    invoke-direct/range {v7 .. v12}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 1540
    .line 1541
    .line 1542
    new-instance v2, Lc21/a;

    .line 1543
    .line 1544
    invoke-direct {v2, v7}, Lc21/b;-><init>(La21/a;)V

    .line 1545
    .line 1546
    .line 1547
    invoke-virtual {v0, v2}, Le21/a;->a(Lc21/b;)V

    .line 1548
    .line 1549
    .line 1550
    new-instance v11, Lth0/a;

    .line 1551
    .line 1552
    const/16 v2, 0x1a

    .line 1553
    .line 1554
    invoke-direct {v11, v2}, Lth0/a;-><init>(I)V

    .line 1555
    .line 1556
    .line 1557
    new-instance v7, La21/a;

    .line 1558
    .line 1559
    const-class v2, Lvm0/e;

    .line 1560
    .line 1561
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1562
    .line 1563
    .line 1564
    move-result-object v9

    .line 1565
    invoke-direct/range {v7 .. v12}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 1566
    .line 1567
    .line 1568
    new-instance v2, Lc21/a;

    .line 1569
    .line 1570
    invoke-direct {v2, v7}, Lc21/b;-><init>(La21/a;)V

    .line 1571
    .line 1572
    .line 1573
    invoke-virtual {v0, v2}, Le21/a;->a(Lc21/b;)V

    .line 1574
    .line 1575
    .line 1576
    new-instance v11, Lth0/a;

    .line 1577
    .line 1578
    const/16 v2, 0x1c

    .line 1579
    .line 1580
    invoke-direct {v11, v2}, Lth0/a;-><init>(I)V

    .line 1581
    .line 1582
    .line 1583
    new-instance v7, La21/a;

    .line 1584
    .line 1585
    const-class v2, Lxm0/h;

    .line 1586
    .line 1587
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1588
    .line 1589
    .line 1590
    move-result-object v9

    .line 1591
    invoke-direct/range {v7 .. v12}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 1592
    .line 1593
    .line 1594
    new-instance v2, Lc21/a;

    .line 1595
    .line 1596
    invoke-direct {v2, v7}, Lc21/b;-><init>(La21/a;)V

    .line 1597
    .line 1598
    .line 1599
    invoke-virtual {v0, v2}, Le21/a;->a(Lc21/b;)V

    .line 1600
    .line 1601
    .line 1602
    new-instance v11, Lth0/a;

    .line 1603
    .line 1604
    const/16 v2, 0x1d

    .line 1605
    .line 1606
    invoke-direct {v11, v2}, Lth0/a;-><init>(I)V

    .line 1607
    .line 1608
    .line 1609
    new-instance v7, La21/a;

    .line 1610
    .line 1611
    const-class v2, Lxm0/c;

    .line 1612
    .line 1613
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1614
    .line 1615
    .line 1616
    move-result-object v9

    .line 1617
    invoke-direct/range {v7 .. v12}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 1618
    .line 1619
    .line 1620
    new-instance v2, Lc21/a;

    .line 1621
    .line 1622
    invoke-direct {v2, v7}, Lc21/b;-><init>(La21/a;)V

    .line 1623
    .line 1624
    .line 1625
    invoke-virtual {v0, v2}, Le21/a;->a(Lc21/b;)V

    .line 1626
    .line 1627
    .line 1628
    new-instance v11, Ltf0/a;

    .line 1629
    .line 1630
    const/16 v2, 0x1c

    .line 1631
    .line 1632
    invoke-direct {v11, v2}, Ltf0/a;-><init>(I)V

    .line 1633
    .line 1634
    .line 1635
    sget-object v12, La21/c;->d:La21/c;

    .line 1636
    .line 1637
    new-instance v7, La21/a;

    .line 1638
    .line 1639
    const-class v2, Ltm0/c;

    .line 1640
    .line 1641
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1642
    .line 1643
    .line 1644
    move-result-object v9

    .line 1645
    invoke-direct/range {v7 .. v12}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 1646
    .line 1647
    .line 1648
    new-instance v2, Lc21/d;

    .line 1649
    .line 1650
    invoke-direct {v2, v7}, Lc21/b;-><init>(La21/a;)V

    .line 1651
    .line 1652
    .line 1653
    invoke-virtual {v0, v2}, Le21/a;->a(Lc21/b;)V

    .line 1654
    .line 1655
    .line 1656
    new-instance v11, Lth0/a;

    .line 1657
    .line 1658
    const/16 v2, 0x1b

    .line 1659
    .line 1660
    invoke-direct {v11, v2}, Lth0/a;-><init>(I)V

    .line 1661
    .line 1662
    .line 1663
    new-instance v7, La21/a;

    .line 1664
    .line 1665
    const-class v2, Ltm0/a;

    .line 1666
    .line 1667
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1668
    .line 1669
    .line 1670
    move-result-object v9

    .line 1671
    invoke-direct/range {v7 .. v12}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 1672
    .line 1673
    .line 1674
    invoke-static {v7, v0}, Lia/b;->d(La21/a;Le21/a;)Lc21/d;

    .line 1675
    .line 1676
    .line 1677
    move-result-object v2

    .line 1678
    new-instance v3, La21/d;

    .line 1679
    .line 1680
    invoke-direct {v3, v0, v2}, La21/d;-><init>(Le21/a;Lc21/b;)V

    .line 1681
    .line 1682
    .line 1683
    const-class v0, Lvm0/b;

    .line 1684
    .line 1685
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1686
    .line 1687
    .line 1688
    move-result-object v0

    .line 1689
    const-class v2, Lme0/b;

    .line 1690
    .line 1691
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1692
    .line 1693
    .line 1694
    move-result-object v2

    .line 1695
    const-class v4, Lme0/a;

    .line 1696
    .line 1697
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1698
    .line 1699
    .line 1700
    move-result-object v1

    .line 1701
    const/4 v4, 0x3

    .line 1702
    new-array v4, v4, [Lhy0/d;

    .line 1703
    .line 1704
    const/16 v18, 0x0

    .line 1705
    .line 1706
    aput-object v0, v4, v18

    .line 1707
    .line 1708
    aput-object v2, v4, v16

    .line 1709
    .line 1710
    const/4 v0, 0x2

    .line 1711
    aput-object v1, v4, v0

    .line 1712
    .line 1713
    invoke-static {v3, v4}, Llp/le;->a(La21/d;[Lhy0/d;)V

    .line 1714
    .line 1715
    .line 1716
    return-object v19

    .line 1717
    :pswitch_b
    move-object/from16 v0, p1

    .line 1718
    .line 1719
    check-cast v0, Lua/a;

    .line 1720
    .line 1721
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1722
    .line 1723
    .line 1724
    const-string v1, "SELECT * FROM map_tile_type LIMIT 1"

    .line 1725
    .line 1726
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1727
    .line 1728
    .line 1729
    move-result-object v1

    .line 1730
    :try_start_6
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1731
    .line 1732
    .line 1733
    move-result v0

    .line 1734
    const-string v2, "type"

    .line 1735
    .line 1736
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1737
    .line 1738
    .line 1739
    move-result v2

    .line 1740
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 1741
    .line 1742
    .line 1743
    move-result v3

    .line 1744
    if-eqz v3, :cond_3c

    .line 1745
    .line 1746
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 1747
    .line 1748
    .line 1749
    move-result-wide v3

    .line 1750
    long-to-int v0, v3

    .line 1751
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1752
    .line 1753
    .line 1754
    move-result-object v2

    .line 1755
    new-instance v13, Luj0/b;

    .line 1756
    .line 1757
    invoke-direct {v13, v0, v2}, Luj0/b;-><init>(ILjava/lang/String;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 1758
    .line 1759
    .line 1760
    goto :goto_3e

    .line 1761
    :catchall_6
    move-exception v0

    .line 1762
    goto :goto_3f

    .line 1763
    :cond_3c
    const/4 v13, 0x0

    .line 1764
    :goto_3e
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1765
    .line 1766
    .line 1767
    return-object v13

    .line 1768
    :goto_3f
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1769
    .line 1770
    .line 1771
    throw v0

    .line 1772
    :pswitch_c
    move-object/from16 v0, p1

    .line 1773
    .line 1774
    check-cast v0, Lua/a;

    .line 1775
    .line 1776
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1777
    .line 1778
    .line 1779
    const-string v1, "DELETE from map_tile_type"

    .line 1780
    .line 1781
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1782
    .line 1783
    .line 1784
    move-result-object v1

    .line 1785
    :try_start_7
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_7

    .line 1786
    .line 1787
    .line 1788
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1789
    .line 1790
    .line 1791
    return-object v19

    .line 1792
    :catchall_7
    move-exception v0

    .line 1793
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1794
    .line 1795
    .line 1796
    throw v0

    .line 1797
    :pswitch_d
    move-object/from16 v0, p1

    .line 1798
    .line 1799
    check-cast v0, Lcz/myskoda/api/bff_consents/v2/MandatoryConsentDto;

    .line 1800
    .line 1801
    const-string v1, "$this$requestSynchronous"

    .line 1802
    .line 1803
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1804
    .line 1805
    .line 1806
    new-instance v1, Lyi0/f;

    .line 1807
    .line 1808
    invoke-virtual {v0}, Lcz/myskoda/api/bff_consents/v2/MandatoryConsentDto;->getConsented()Z

    .line 1809
    .line 1810
    .line 1811
    move-result v2

    .line 1812
    invoke-virtual {v0}, Lcz/myskoda/api/bff_consents/v2/MandatoryConsentDto;->getTermsAndConditionsLink()Ljava/lang/String;

    .line 1813
    .line 1814
    .line 1815
    move-result-object v3

    .line 1816
    invoke-virtual {v0}, Lcz/myskoda/api/bff_consents/v2/MandatoryConsentDto;->getDataPrivacyLink()Ljava/lang/String;

    .line 1817
    .line 1818
    .line 1819
    move-result-object v0

    .line 1820
    invoke-direct {v1, v2, v3, v0}, Lyi0/f;-><init>(ZLjava/lang/String;Ljava/lang/String;)V

    .line 1821
    .line 1822
    .line 1823
    return-object v1

    .line 1824
    :pswitch_e
    move-object/from16 v0, p1

    .line 1825
    .line 1826
    check-cast v0, Lhi/a;

    .line 1827
    .line 1828
    const-string v1, "$this$sdkViewModel"

    .line 1829
    .line 1830
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1831
    .line 1832
    .line 1833
    new-instance v0, Luh/g;

    .line 1834
    .line 1835
    invoke-direct {v0}, Luh/g;-><init>()V

    .line 1836
    .line 1837
    .line 1838
    return-object v0

    .line 1839
    :pswitch_f
    move-object/from16 v0, p1

    .line 1840
    .line 1841
    check-cast v0, Luf/l;

    .line 1842
    .line 1843
    const-string v1, "currentState"

    .line 1844
    .line 1845
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1846
    .line 1847
    .line 1848
    iget-object v1, v0, Luf/l;->b:Luf/a;

    .line 1849
    .line 1850
    if-eqz v1, :cond_3d

    .line 1851
    .line 1852
    const/4 v2, 0x0

    .line 1853
    invoke-static {v1, v2, v2}, Luf/a;->a(Luf/a;ZZ)Luf/a;

    .line 1854
    .line 1855
    .line 1856
    move-result-object v13

    .line 1857
    goto :goto_40

    .line 1858
    :cond_3d
    const/4 v13, 0x0

    .line 1859
    :goto_40
    iget-object v1, v0, Luf/l;->c:Ljava/util/List;

    .line 1860
    .line 1861
    check-cast v1, Ljava/lang/Iterable;

    .line 1862
    .line 1863
    new-instance v2, Ljava/util/ArrayList;

    .line 1864
    .line 1865
    const/16 v3, 0xa

    .line 1866
    .line 1867
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1868
    .line 1869
    .line 1870
    move-result v3

    .line 1871
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 1872
    .line 1873
    .line 1874
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1875
    .line 1876
    .line 1877
    move-result-object v1

    .line 1878
    :goto_41
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1879
    .line 1880
    .line 1881
    move-result v3

    .line 1882
    if-eqz v3, :cond_3e

    .line 1883
    .line 1884
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1885
    .line 1886
    .line 1887
    move-result-object v3

    .line 1888
    check-cast v3, Luf/a;

    .line 1889
    .line 1890
    const/4 v4, 0x0

    .line 1891
    invoke-static {v3, v4, v4}, Luf/a;->a(Luf/a;ZZ)Luf/a;

    .line 1892
    .line 1893
    .line 1894
    move-result-object v3

    .line 1895
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1896
    .line 1897
    .line 1898
    goto :goto_41

    .line 1899
    :cond_3e
    const/4 v4, 0x0

    .line 1900
    const/16 v1, 0x79

    .line 1901
    .line 1902
    invoke-static {v0, v13, v2, v4, v1}, Luf/l;->a(Luf/l;Luf/a;Ljava/util/ArrayList;ZI)Luf/l;

    .line 1903
    .line 1904
    .line 1905
    move-result-object v0

    .line 1906
    return-object v0

    .line 1907
    :pswitch_10
    move-object/from16 v0, p1

    .line 1908
    .line 1909
    check-cast v0, Lgi/c;

    .line 1910
    .line 1911
    move-object/from16 v1, v20

    .line 1912
    .line 1913
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1914
    .line 1915
    .line 1916
    const-string v0, " popUp closePopUp called "

    .line 1917
    .line 1918
    return-object v0

    .line 1919
    :pswitch_11
    move-object/from16 v0, p1

    .line 1920
    .line 1921
    check-cast v0, Luf/l;

    .line 1922
    .line 1923
    const-string v1, "currentState"

    .line 1924
    .line 1925
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1926
    .line 1927
    .line 1928
    iget-boolean v1, v0, Luf/l;->f:Z

    .line 1929
    .line 1930
    xor-int/lit8 v1, v1, 0x1

    .line 1931
    .line 1932
    const/16 v2, 0x5f

    .line 1933
    .line 1934
    const/4 v3, 0x0

    .line 1935
    invoke-static {v0, v3, v3, v1, v2}, Luf/l;->a(Luf/l;Luf/a;Ljava/util/ArrayList;ZI)Luf/l;

    .line 1936
    .line 1937
    .line 1938
    move-result-object v0

    .line 1939
    return-object v0

    .line 1940
    :pswitch_12
    move-object/from16 v1, v20

    .line 1941
    .line 1942
    move-object/from16 v0, p1

    .line 1943
    .line 1944
    check-cast v0, Lgi/c;

    .line 1945
    .line 1946
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1947
    .line 1948
    .line 1949
    const-string v0, "A certificate is being uninstalled. Going to uninstallation screen"

    .line 1950
    .line 1951
    return-object v0

    .line 1952
    :pswitch_13
    move-object/from16 v1, v20

    .line 1953
    .line 1954
    move-object/from16 v0, p1

    .line 1955
    .line 1956
    check-cast v0, Lgi/c;

    .line 1957
    .line 1958
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1959
    .line 1960
    .line 1961
    const-string v0, "A certificate is being installed. Going to installation screen"

    .line 1962
    .line 1963
    return-object v0

    .line 1964
    :pswitch_14
    move-object/from16 v0, p1

    .line 1965
    .line 1966
    check-cast v0, Lhi/a;

    .line 1967
    .line 1968
    const-string v1, "$this$single"

    .line 1969
    .line 1970
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1971
    .line 1972
    .line 1973
    const-class v1, Lretrofit2/Retrofit;

    .line 1974
    .line 1975
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1976
    .line 1977
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1978
    .line 1979
    .line 1980
    move-result-object v1

    .line 1981
    check-cast v0, Lii/a;

    .line 1982
    .line 1983
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 1984
    .line 1985
    .line 1986
    move-result-object v0

    .line 1987
    check-cast v0, Lretrofit2/Retrofit;

    .line 1988
    .line 1989
    const-class v1, Lwd/e;

    .line 1990
    .line 1991
    invoke-virtual {v0, v1}, Lretrofit2/Retrofit;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 1992
    .line 1993
    .line 1994
    move-result-object v0

    .line 1995
    check-cast v0, Lwd/e;

    .line 1996
    .line 1997
    new-instance v1, Lwd/d;

    .line 1998
    .line 1999
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2000
    .line 2001
    .line 2002
    invoke-direct {v1, v0}, Lwd/d;-><init>(Lwd/e;)V

    .line 2003
    .line 2004
    .line 2005
    return-object v1

    .line 2006
    :pswitch_15
    move-object/from16 v0, p1

    .line 2007
    .line 2008
    check-cast v0, Lua/a;

    .line 2009
    .line 2010
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2011
    .line 2012
    .line 2013
    const-string v1, "DELETE from widget"

    .line 2014
    .line 2015
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2016
    .line 2017
    .line 2018
    move-result-object v1

    .line 2019
    :try_start_8
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_8

    .line 2020
    .line 2021
    .line 2022
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2023
    .line 2024
    .line 2025
    return-object v19

    .line 2026
    :catchall_8
    move-exception v0

    .line 2027
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2028
    .line 2029
    .line 2030
    throw v0

    .line 2031
    :pswitch_16
    const/4 v3, 0x0

    .line 2032
    const/4 v4, 0x0

    .line 2033
    move-object/from16 v0, p1

    .line 2034
    .line 2035
    check-cast v0, Lua/a;

    .line 2036
    .line 2037
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2038
    .line 2039
    .line 2040
    const-string v1, "SELECT * FROM widget LIMIT 1"

    .line 2041
    .line 2042
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2043
    .line 2044
    .line 2045
    move-result-object v1

    .line 2046
    :try_start_9
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2047
    .line 2048
    .line 2049
    move-result v0

    .line 2050
    const-string v2, "name"

    .line 2051
    .line 2052
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2053
    .line 2054
    .line 2055
    move-result v2

    .line 2056
    const-string v5, "render"

    .line 2057
    .line 2058
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2059
    .line 2060
    .line 2061
    move-result v5

    .line 2062
    const-string v6, "licencePlate"

    .line 2063
    .line 2064
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2065
    .line 2066
    .line 2067
    move-result v6

    .line 2068
    const-string v7, "isDoorLocked"

    .line 2069
    .line 2070
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2071
    .line 2072
    .line 2073
    move-result v7

    .line 2074
    const-string v8, "isCharging"

    .line 2075
    .line 2076
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2077
    .line 2078
    .line 2079
    move-result v8

    .line 2080
    const-string v9, "drivingRange"

    .line 2081
    .line 2082
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2083
    .line 2084
    .line 2085
    move-result v9

    .line 2086
    const-string v10, "remainingCharging"

    .line 2087
    .line 2088
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2089
    .line 2090
    .line 2091
    move-result v10

    .line 2092
    const-string v11, "battery"

    .line 2093
    .line 2094
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2095
    .line 2096
    .line 2097
    move-result v11

    .line 2098
    const-string v12, "parkingAddress"

    .line 2099
    .line 2100
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2101
    .line 2102
    .line 2103
    move-result v12

    .line 2104
    const-string v13, "parkingMapUrl"

    .line 2105
    .line 2106
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2107
    .line 2108
    .line 2109
    move-result v13

    .line 2110
    const-string v14, "isInMotion"

    .line 2111
    .line 2112
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2113
    .line 2114
    .line 2115
    move-result v14

    .line 2116
    const-string v15, "updated"

    .line 2117
    .line 2118
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 2119
    .line 2120
    .line 2121
    move-result v15

    .line 2122
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 2123
    .line 2124
    .line 2125
    move-result v17

    .line 2126
    if-eqz v17, :cond_4d

    .line 2127
    .line 2128
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 2129
    .line 2130
    .line 2131
    move-result-wide v3

    .line 2132
    long-to-int v0, v3

    .line 2133
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2134
    .line 2135
    .line 2136
    move-result-object v23

    .line 2137
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 2138
    .line 2139
    .line 2140
    move-result v2

    .line 2141
    if-eqz v2, :cond_3f

    .line 2142
    .line 2143
    const/16 v24, 0x0

    .line 2144
    .line 2145
    goto :goto_42

    .line 2146
    :cond_3f
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2147
    .line 2148
    .line 2149
    move-result-object v2

    .line 2150
    move-object/from16 v24, v2

    .line 2151
    .line 2152
    :goto_42
    invoke-interface {v1, v6}, Lua/c;->isNull(I)Z

    .line 2153
    .line 2154
    .line 2155
    move-result v2

    .line 2156
    if-eqz v2, :cond_40

    .line 2157
    .line 2158
    const/16 v25, 0x0

    .line 2159
    .line 2160
    goto :goto_43

    .line 2161
    :cond_40
    invoke-interface {v1, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2162
    .line 2163
    .line 2164
    move-result-object v2

    .line 2165
    move-object/from16 v25, v2

    .line 2166
    .line 2167
    :goto_43
    invoke-interface {v1, v7}, Lua/c;->isNull(I)Z

    .line 2168
    .line 2169
    .line 2170
    move-result v2

    .line 2171
    if-eqz v2, :cond_41

    .line 2172
    .line 2173
    const/4 v2, 0x0

    .line 2174
    goto :goto_44

    .line 2175
    :cond_41
    invoke-interface {v1, v7}, Lua/c;->getLong(I)J

    .line 2176
    .line 2177
    .line 2178
    move-result-wide v2

    .line 2179
    long-to-int v2, v2

    .line 2180
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2181
    .line 2182
    .line 2183
    move-result-object v2

    .line 2184
    :goto_44
    if-eqz v2, :cond_43

    .line 2185
    .line 2186
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 2187
    .line 2188
    .line 2189
    move-result v2

    .line 2190
    if-eqz v2, :cond_42

    .line 2191
    .line 2192
    move/from16 v2, v16

    .line 2193
    .line 2194
    goto :goto_45

    .line 2195
    :cond_42
    const/4 v2, 0x0

    .line 2196
    :goto_45
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2197
    .line 2198
    .line 2199
    move-result-object v2

    .line 2200
    move-object/from16 v26, v2

    .line 2201
    .line 2202
    goto :goto_46

    .line 2203
    :catchall_9
    move-exception v0

    .line 2204
    goto/16 :goto_50

    .line 2205
    .line 2206
    :cond_43
    const/16 v26, 0x0

    .line 2207
    .line 2208
    :goto_46
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 2209
    .line 2210
    .line 2211
    move-result-wide v2

    .line 2212
    long-to-int v2, v2

    .line 2213
    if-eqz v2, :cond_44

    .line 2214
    .line 2215
    move/from16 v27, v16

    .line 2216
    .line 2217
    goto :goto_47

    .line 2218
    :cond_44
    const/16 v27, 0x0

    .line 2219
    .line 2220
    :goto_47
    invoke-interface {v1, v9}, Lua/c;->isNull(I)Z

    .line 2221
    .line 2222
    .line 2223
    move-result v2

    .line 2224
    if-eqz v2, :cond_45

    .line 2225
    .line 2226
    const/16 v28, 0x0

    .line 2227
    .line 2228
    goto :goto_48

    .line 2229
    :cond_45
    invoke-interface {v1, v9}, Lua/c;->getLong(I)J

    .line 2230
    .line 2231
    .line 2232
    move-result-wide v2

    .line 2233
    long-to-int v2, v2

    .line 2234
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2235
    .line 2236
    .line 2237
    move-result-object v2

    .line 2238
    move-object/from16 v28, v2

    .line 2239
    .line 2240
    :goto_48
    invoke-interface {v1, v10}, Lua/c;->isNull(I)Z

    .line 2241
    .line 2242
    .line 2243
    move-result v2

    .line 2244
    if-eqz v2, :cond_46

    .line 2245
    .line 2246
    const/16 v29, 0x0

    .line 2247
    .line 2248
    goto :goto_49

    .line 2249
    :cond_46
    invoke-interface {v1, v10}, Lua/c;->getLong(I)J

    .line 2250
    .line 2251
    .line 2252
    move-result-wide v2

    .line 2253
    long-to-int v2, v2

    .line 2254
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2255
    .line 2256
    .line 2257
    move-result-object v2

    .line 2258
    move-object/from16 v29, v2

    .line 2259
    .line 2260
    :goto_49
    invoke-interface {v1, v11}, Lua/c;->isNull(I)Z

    .line 2261
    .line 2262
    .line 2263
    move-result v2

    .line 2264
    if-eqz v2, :cond_47

    .line 2265
    .line 2266
    const/16 v30, 0x0

    .line 2267
    .line 2268
    goto :goto_4a

    .line 2269
    :cond_47
    invoke-interface {v1, v11}, Lua/c;->getLong(I)J

    .line 2270
    .line 2271
    .line 2272
    move-result-wide v2

    .line 2273
    long-to-int v2, v2

    .line 2274
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2275
    .line 2276
    .line 2277
    move-result-object v2

    .line 2278
    move-object/from16 v30, v2

    .line 2279
    .line 2280
    :goto_4a
    invoke-interface {v1, v12}, Lua/c;->isNull(I)Z

    .line 2281
    .line 2282
    .line 2283
    move-result v2

    .line 2284
    if-eqz v2, :cond_48

    .line 2285
    .line 2286
    const/16 v31, 0x0

    .line 2287
    .line 2288
    goto :goto_4b

    .line 2289
    :cond_48
    invoke-interface {v1, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2290
    .line 2291
    .line 2292
    move-result-object v2

    .line 2293
    move-object/from16 v31, v2

    .line 2294
    .line 2295
    :goto_4b
    invoke-interface {v1, v13}, Lua/c;->isNull(I)Z

    .line 2296
    .line 2297
    .line 2298
    move-result v2

    .line 2299
    if-eqz v2, :cond_49

    .line 2300
    .line 2301
    const/16 v32, 0x0

    .line 2302
    .line 2303
    goto :goto_4c

    .line 2304
    :cond_49
    invoke-interface {v1, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2305
    .line 2306
    .line 2307
    move-result-object v2

    .line 2308
    move-object/from16 v32, v2

    .line 2309
    .line 2310
    :goto_4c
    invoke-interface {v1, v14}, Lua/c;->getLong(I)J

    .line 2311
    .line 2312
    .line 2313
    move-result-wide v2

    .line 2314
    long-to-int v2, v2

    .line 2315
    if-eqz v2, :cond_4a

    .line 2316
    .line 2317
    move/from16 v33, v16

    .line 2318
    .line 2319
    goto :goto_4d

    .line 2320
    :cond_4a
    const/16 v33, 0x0

    .line 2321
    .line 2322
    :goto_4d
    invoke-interface {v1, v15}, Lua/c;->isNull(I)Z

    .line 2323
    .line 2324
    .line 2325
    move-result v2

    .line 2326
    if-eqz v2, :cond_4b

    .line 2327
    .line 2328
    const/4 v13, 0x0

    .line 2329
    goto :goto_4e

    .line 2330
    :cond_4b
    invoke-interface {v1, v15}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2331
    .line 2332
    .line 2333
    move-result-object v13

    .line 2334
    :goto_4e
    invoke-static {v13}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 2335
    .line 2336
    .line 2337
    move-result-object v34

    .line 2338
    if-eqz v34, :cond_4c

    .line 2339
    .line 2340
    new-instance v21, Lua0/i;

    .line 2341
    .line 2342
    move/from16 v22, v0

    .line 2343
    .line 2344
    invoke-direct/range {v21 .. v34}, Lua0/i;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;ZLjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;ZLjava/time/OffsetDateTime;)V

    .line 2345
    .line 2346
    .line 2347
    move-object/from16 v13, v21

    .line 2348
    .line 2349
    goto :goto_4f

    .line 2350
    :cond_4c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2351
    .line 2352
    const-string v2, "Expected NON-NULL \'java.time.OffsetDateTime\', but it was NULL."

    .line 2353
    .line 2354
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2355
    .line 2356
    .line 2357
    throw v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_9

    .line 2358
    :cond_4d
    const/4 v13, 0x0

    .line 2359
    :goto_4f
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2360
    .line 2361
    .line 2362
    return-object v13

    .line 2363
    :goto_50
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2364
    .line 2365
    .line 2366
    throw v0

    .line 2367
    :pswitch_17
    move-object/from16 v1, p1

    .line 2368
    .line 2369
    check-cast v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 2370
    .line 2371
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2372
    .line 2373
    .line 2374
    invoke-static {v1}, Lmx0/n;->f0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;)Lcq0/n;

    .line 2375
    .line 2376
    .line 2377
    move-result-object v0

    .line 2378
    return-object v0

    .line 2379
    :pswitch_18
    move-object/from16 v1, p1

    .line 2380
    .line 2381
    check-cast v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerEncodedUrlDto;

    .line 2382
    .line 2383
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2384
    .line 2385
    .line 2386
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerEncodedUrlDto;->getUrl()Ljava/lang/String;

    .line 2387
    .line 2388
    .line 2389
    move-result-object v0

    .line 2390
    return-object v0

    .line 2391
    :pswitch_19
    move-object/from16 v1, p1

    .line 2392
    .line 2393
    check-cast v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnersDto;

    .line 2394
    .line 2395
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2396
    .line 2397
    .line 2398
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnersDto;->getServicePartners()Ljava/util/List;

    .line 2399
    .line 2400
    .line 2401
    move-result-object v0

    .line 2402
    check-cast v0, Ljava/lang/Iterable;

    .line 2403
    .line 2404
    new-instance v1, Ljava/util/ArrayList;

    .line 2405
    .line 2406
    const/16 v3, 0xa

    .line 2407
    .line 2408
    invoke-static {v0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2409
    .line 2410
    .line 2411
    move-result v2

    .line 2412
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 2413
    .line 2414
    .line 2415
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2416
    .line 2417
    .line 2418
    move-result-object v0

    .line 2419
    :goto_51
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2420
    .line 2421
    .line 2422
    move-result v2

    .line 2423
    if-eqz v2, :cond_4e

    .line 2424
    .line 2425
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2426
    .line 2427
    .line 2428
    move-result-object v2

    .line 2429
    check-cast v2, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 2430
    .line 2431
    invoke-static {v2}, Lmx0/n;->f0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;)Lcq0/n;

    .line 2432
    .line 2433
    .line 2434
    move-result-object v2

    .line 2435
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2436
    .line 2437
    .line 2438
    goto :goto_51

    .line 2439
    :cond_4e
    return-object v1

    .line 2440
    :pswitch_1a
    move-object/from16 v1, p1

    .line 2441
    .line 2442
    check-cast v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnersDto;

    .line 2443
    .line 2444
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2445
    .line 2446
    .line 2447
    invoke-virtual {v1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnersDto;->getServicePartners()Ljava/util/List;

    .line 2448
    .line 2449
    .line 2450
    move-result-object v0

    .line 2451
    check-cast v0, Ljava/lang/Iterable;

    .line 2452
    .line 2453
    new-instance v1, Ljava/util/ArrayList;

    .line 2454
    .line 2455
    const/16 v3, 0xa

    .line 2456
    .line 2457
    invoke-static {v0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2458
    .line 2459
    .line 2460
    move-result v2

    .line 2461
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 2462
    .line 2463
    .line 2464
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2465
    .line 2466
    .line 2467
    move-result-object v0

    .line 2468
    :goto_52
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2469
    .line 2470
    .line 2471
    move-result v2

    .line 2472
    if-eqz v2, :cond_4f

    .line 2473
    .line 2474
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2475
    .line 2476
    .line 2477
    move-result-object v2

    .line 2478
    check-cast v2, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;

    .line 2479
    .line 2480
    invoke-static {v2}, Lmx0/n;->f0(Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;)Lcq0/n;

    .line 2481
    .line 2482
    .line 2483
    move-result-object v2

    .line 2484
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2485
    .line 2486
    .line 2487
    goto :goto_52

    .line 2488
    :cond_4f
    return-object v1

    .line 2489
    :pswitch_1b
    return-object p1

    .line 2490
    :pswitch_1c
    move-object/from16 v0, p1

    .line 2491
    .line 2492
    check-cast v0, Ljava/util/Map;

    .line 2493
    .line 2494
    new-instance v1, Lu2/e;

    .line 2495
    .line 2496
    invoke-direct {v1, v0}, Lu2/e;-><init>(Ljava/util/Map;)V

    .line 2497
    .line 2498
    .line 2499
    return-object v1

    .line 2500
    nop

    .line 2501
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

    .line 2502
    .line 2503
    .line 2504
    .line 2505
    .line 2506
    .line 2507
    .line 2508
    .line 2509
    .line 2510
    .line 2511
    .line 2512
    .line 2513
    .line 2514
    .line 2515
    .line 2516
    .line 2517
    .line 2518
    .line 2519
    .line 2520
    .line 2521
    .line 2522
    .line 2523
    .line 2524
    .line 2525
    .line 2526
    .line 2527
    .line 2528
    .line 2529
    .line 2530
    .line 2531
    .line 2532
    .line 2533
    .line 2534
    .line 2535
    .line 2536
    .line 2537
    .line 2538
    .line 2539
    .line 2540
    .line 2541
    .line 2542
    .line 2543
    .line 2544
    .line 2545
    .line 2546
    .line 2547
    .line 2548
    .line 2549
    .line 2550
    .line 2551
    .line 2552
    .line 2553
    .line 2554
    .line 2555
    .line 2556
    .line 2557
    .line 2558
    .line 2559
    .line 2560
    .line 2561
    .line 2562
    .line 2563
    :sswitch_data_0
    .sparse-switch
        -0x39392b53 -> :sswitch_8
        -0x36fe60ba -> :sswitch_7
        -0x330fe4b5 -> :sswitch_6
        -0x31e6f483 -> :sswitch_5
        0x56e6c60 -> :sswitch_4
        0x31205d28 -> :sswitch_3
        0x3c085239 -> :sswitch_2
        0x46cb8d38 -> :sswitch_1
        0x7f142d53 -> :sswitch_0
    .end sparse-switch
.end method

.class public Lxo/e;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Laq/k;

.field public final e:Lxo/a;


# direct methods
.method public constructor <init>(Laq/k;Lxo/a;)V
    .locals 2

    .line 1
    const-string v0, "com.google.android.gms.dck.internal.IDigitalKeyCallback"

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {p0, v0, v1}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lxo/e;->d:Laq/k;

    .line 8
    .line 9
    iput-object p2, p0, Lxo/e;->e:Lxo/a;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final S(Landroid/os/Parcel;I)Z
    .locals 8

    .line 1
    iget-object v0, p0, Lxo/e;->d:Laq/k;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eq p2, v1, :cond_7

    .line 5
    .line 6
    const/4 p0, 0x2

    .line 7
    const/4 v2, 0x0

    .line 8
    if-eq p2, p0, :cond_0

    .line 9
    .line 10
    return v2

    .line 11
    :cond_0
    sget-object p0, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 12
    .line 13
    invoke-static {p1, p0}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Landroid/os/Bundle;

    .line 18
    .line 19
    sget-object p2, Lko/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 20
    .line 21
    invoke-static {p1, p2}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    check-cast p2, Lko/f;

    .line 26
    .line 27
    invoke-static {p1}, Lfp/a;->b(Landroid/os/Parcel;)V

    .line 28
    .line 29
    .line 30
    const-string p1, "ErrorInfo"

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Landroid/os/Bundle;->getByteArray(Ljava/lang/String;)[B

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    const/4 p2, 0x0

    .line 37
    if-eqz p1, :cond_1

    .line 38
    .line 39
    sget-object v3, Lxo/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 40
    .line 41
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    array-length v5, p1

    .line 49
    invoke-virtual {v4, p1, v2, v5}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v4, v2}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 53
    .line 54
    .line 55
    invoke-interface {v3, v4}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    check-cast p1, Loo/c;

    .line 60
    .line 61
    invoke-virtual {v4}, Landroid/os/Parcel;->recycle()V

    .line 62
    .line 63
    .line 64
    check-cast p1, Lxo/j;

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    move-object p1, p2

    .line 68
    :goto_0
    if-eqz p1, :cond_4

    .line 69
    .line 70
    new-instance p0, Lko/e;

    .line 71
    .line 72
    new-instance v3, Lcom/google/android/gms/common/api/Status;

    .line 73
    .line 74
    const/16 v4, 0xd

    .line 75
    .line 76
    invoke-direct {v3, v4, p2, p2, p2}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 77
    .line 78
    .line 79
    invoke-direct {p0, v3}, Lko/e;-><init>(Lcom/google/android/gms/common/api/Status;)V

    .line 80
    .line 81
    .line 82
    iget-object v3, p1, Lxo/j;->d:[I

    .line 83
    .line 84
    array-length v4, v3

    .line 85
    :goto_1
    if-ge v2, v4, :cond_5

    .line 86
    .line 87
    aget p0, v3, v2

    .line 88
    .line 89
    iget-object v5, p1, Lxo/j;->e:Ljava/lang/String;

    .line 90
    .line 91
    if-nez v5, :cond_2

    .line 92
    .line 93
    const-string v5, ""

    .line 94
    .line 95
    :cond_2
    packed-switch p0, :pswitch_data_0

    .line 96
    .line 97
    .line 98
    new-instance v6, Lko/e;

    .line 99
    .line 100
    new-instance v7, Lcom/google/android/gms/common/api/Status;

    .line 101
    .line 102
    invoke-direct {v7, p0, v5, p2, p2}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 103
    .line 104
    .line 105
    invoke-direct {v6, v7}, Lko/e;-><init>(Lcom/google/android/gms/common/api/Status;)V

    .line 106
    .line 107
    .line 108
    move-object p0, v6

    .line 109
    goto/16 :goto_2

    .line 110
    .line 111
    :pswitch_0
    new-instance p0, Lwo/e;

    .line 112
    .line 113
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    goto/16 :goto_2

    .line 117
    .line 118
    :pswitch_1
    new-instance p0, Lwo/e;

    .line 119
    .line 120
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    goto/16 :goto_2

    .line 124
    .line 125
    :pswitch_2
    new-instance p0, Lwo/e;

    .line 126
    .line 127
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    goto/16 :goto_2

    .line 131
    .line 132
    :pswitch_3
    new-instance p0, Lwo/e;

    .line 133
    .line 134
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    goto/16 :goto_2

    .line 138
    .line 139
    :pswitch_4
    new-instance p0, Lwo/e;

    .line 140
    .line 141
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    goto/16 :goto_2

    .line 145
    .line 146
    :pswitch_5
    new-instance p0, Lwo/e;

    .line 147
    .line 148
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    goto/16 :goto_2

    .line 152
    .line 153
    :pswitch_6
    new-instance p0, Lwo/e;

    .line 154
    .line 155
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    goto/16 :goto_2

    .line 159
    .line 160
    :pswitch_7
    new-instance p0, Lwo/e;

    .line 161
    .line 162
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    goto/16 :goto_2

    .line 166
    .line 167
    :pswitch_8
    new-instance p0, Lwo/e;

    .line 168
    .line 169
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    goto/16 :goto_2

    .line 173
    .line 174
    :pswitch_9
    new-instance p0, Lwo/e;

    .line 175
    .line 176
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    goto/16 :goto_2

    .line 180
    .line 181
    :pswitch_a
    new-instance p0, Lwo/d;

    .line 182
    .line 183
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    goto/16 :goto_2

    .line 187
    .line 188
    :pswitch_b
    new-instance p0, Lwo/d;

    .line 189
    .line 190
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    goto/16 :goto_2

    .line 194
    .line 195
    :pswitch_c
    new-instance p0, Lb0/l;

    .line 196
    .line 197
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    goto/16 :goto_2

    .line 201
    .line 202
    :pswitch_d
    new-instance p0, Lwo/e;

    .line 203
    .line 204
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    goto/16 :goto_2

    .line 208
    .line 209
    :pswitch_e
    new-instance p0, Lwo/e;

    .line 210
    .line 211
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    goto/16 :goto_2

    .line 215
    .line 216
    :pswitch_f
    new-instance p0, Lwo/d;

    .line 217
    .line 218
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    goto/16 :goto_2

    .line 222
    .line 223
    :pswitch_10
    new-instance p0, Lwo/d;

    .line 224
    .line 225
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    goto/16 :goto_2

    .line 229
    .line 230
    :pswitch_11
    new-instance p0, Lwo/d;

    .line 231
    .line 232
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    goto/16 :goto_2

    .line 236
    .line 237
    :pswitch_12
    new-instance p0, Lwo/d;

    .line 238
    .line 239
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    goto/16 :goto_2

    .line 243
    .line 244
    :pswitch_13
    new-instance p0, Lwo/d;

    .line 245
    .line 246
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    goto/16 :goto_2

    .line 250
    .line 251
    :pswitch_14
    new-instance p0, Lwo/d;

    .line 252
    .line 253
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    goto/16 :goto_2

    .line 257
    .line 258
    :pswitch_15
    new-instance p0, Lwo/d;

    .line 259
    .line 260
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    goto/16 :goto_2

    .line 264
    .line 265
    :pswitch_16
    new-instance p0, Lwo/d;

    .line 266
    .line 267
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    goto/16 :goto_2

    .line 271
    .line 272
    :pswitch_17
    new-instance p0, Lwo/d;

    .line 273
    .line 274
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    goto/16 :goto_2

    .line 278
    .line 279
    :pswitch_18
    new-instance p0, Lwo/d;

    .line 280
    .line 281
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    goto/16 :goto_2

    .line 285
    .line 286
    :pswitch_19
    new-instance p0, Lwo/d;

    .line 287
    .line 288
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    goto/16 :goto_2

    .line 292
    .line 293
    :pswitch_1a
    new-instance p0, Lwo/e;

    .line 294
    .line 295
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    goto/16 :goto_2

    .line 299
    .line 300
    :pswitch_1b
    new-instance p0, Lwo/e;

    .line 301
    .line 302
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    goto/16 :goto_2

    .line 306
    .line 307
    :pswitch_1c
    new-instance p0, Lwo/e;

    .line 308
    .line 309
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    goto/16 :goto_2

    .line 313
    .line 314
    :pswitch_1d
    new-instance p0, Lwo/e;

    .line 315
    .line 316
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    goto/16 :goto_2

    .line 320
    .line 321
    :pswitch_1e
    new-instance p0, Lwo/e;

    .line 322
    .line 323
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    goto/16 :goto_2

    .line 327
    .line 328
    :pswitch_1f
    new-instance p0, Lwo/e;

    .line 329
    .line 330
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 331
    .line 332
    .line 333
    goto/16 :goto_2

    .line 334
    .line 335
    :pswitch_20
    new-instance p0, Lwo/e;

    .line 336
    .line 337
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    goto/16 :goto_2

    .line 341
    .line 342
    :pswitch_21
    new-instance p0, Lb0/l;

    .line 343
    .line 344
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    goto/16 :goto_2

    .line 348
    .line 349
    :pswitch_22
    new-instance p0, Lwo/d;

    .line 350
    .line 351
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    goto/16 :goto_2

    .line 355
    .line 356
    :pswitch_23
    new-instance p0, Lwo/d;

    .line 357
    .line 358
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    goto/16 :goto_2

    .line 362
    .line 363
    :pswitch_24
    new-instance p0, Lwo/d;

    .line 364
    .line 365
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    goto/16 :goto_2

    .line 369
    .line 370
    :pswitch_25
    new-instance p0, Lwo/e;

    .line 371
    .line 372
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 373
    .line 374
    .line 375
    goto/16 :goto_2

    .line 376
    .line 377
    :pswitch_26
    new-instance p0, Lwo/e;

    .line 378
    .line 379
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 380
    .line 381
    .line 382
    goto/16 :goto_2

    .line 383
    .line 384
    :pswitch_27
    new-instance p0, Lwo/e;

    .line 385
    .line 386
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 387
    .line 388
    .line 389
    goto/16 :goto_2

    .line 390
    .line 391
    :pswitch_28
    new-instance p0, Lwo/d;

    .line 392
    .line 393
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    goto/16 :goto_2

    .line 397
    .line 398
    :pswitch_29
    new-instance p0, Lwo/d;

    .line 399
    .line 400
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    goto/16 :goto_2

    .line 404
    .line 405
    :pswitch_2a
    new-instance p0, Lwo/d;

    .line 406
    .line 407
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 408
    .line 409
    .line 410
    goto/16 :goto_2

    .line 411
    .line 412
    :pswitch_2b
    new-instance p0, Lwo/d;

    .line 413
    .line 414
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    goto/16 :goto_2

    .line 418
    .line 419
    :pswitch_2c
    new-instance p0, Lwo/d;

    .line 420
    .line 421
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 422
    .line 423
    .line 424
    goto/16 :goto_2

    .line 425
    .line 426
    :pswitch_2d
    new-instance p0, Lwo/e;

    .line 427
    .line 428
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 429
    .line 430
    .line 431
    goto/16 :goto_2

    .line 432
    .line 433
    :pswitch_2e
    new-instance p0, Lwo/d;

    .line 434
    .line 435
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 436
    .line 437
    .line 438
    goto/16 :goto_2

    .line 439
    .line 440
    :pswitch_2f
    new-instance p0, Lwo/d;

    .line 441
    .line 442
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 443
    .line 444
    .line 445
    goto :goto_2

    .line 446
    :pswitch_30
    new-instance p0, Lwo/d;

    .line 447
    .line 448
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 449
    .line 450
    .line 451
    goto :goto_2

    .line 452
    :pswitch_31
    new-instance p0, Lwo/d;

    .line 453
    .line 454
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 455
    .line 456
    .line 457
    goto :goto_2

    .line 458
    :pswitch_32
    new-instance p0, Lwo/d;

    .line 459
    .line 460
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 461
    .line 462
    .line 463
    goto :goto_2

    .line 464
    :pswitch_33
    new-instance p0, Lwo/e;

    .line 465
    .line 466
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 467
    .line 468
    .line 469
    goto :goto_2

    .line 470
    :pswitch_34
    new-instance p0, Lwo/d;

    .line 471
    .line 472
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 473
    .line 474
    .line 475
    goto :goto_2

    .line 476
    :pswitch_35
    new-instance p0, Lwo/d;

    .line 477
    .line 478
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 479
    .line 480
    .line 481
    goto :goto_2

    .line 482
    :pswitch_36
    new-instance p0, Lwo/e;

    .line 483
    .line 484
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    goto :goto_2

    .line 488
    :pswitch_37
    new-instance p0, Lwo/d;

    .line 489
    .line 490
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 491
    .line 492
    .line 493
    goto :goto_2

    .line 494
    :pswitch_38
    new-instance p0, Lwo/d;

    .line 495
    .line 496
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 497
    .line 498
    .line 499
    goto :goto_2

    .line 500
    :pswitch_39
    new-instance p0, Lb0/l;

    .line 501
    .line 502
    invoke-direct {p0, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 503
    .line 504
    .line 505
    goto :goto_2

    .line 506
    :pswitch_3a
    new-instance p0, Laq/c;

    .line 507
    .line 508
    const/16 v6, 0x9

    .line 509
    .line 510
    invoke-direct {p0, v5, v6}, Laq/c;-><init>(Ljava/lang/String;I)V

    .line 511
    .line 512
    .line 513
    goto :goto_2

    .line 514
    :pswitch_3b
    new-instance p0, Laq/c;

    .line 515
    .line 516
    const/4 v6, 0x7

    .line 517
    invoke-direct {p0, v5, v6}, Laq/c;-><init>(Ljava/lang/String;I)V

    .line 518
    .line 519
    .line 520
    goto :goto_2

    .line 521
    :pswitch_3c
    new-instance p0, Lwo/c;

    .line 522
    .line 523
    invoke-direct {p0, v5}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;)V

    .line 524
    .line 525
    .line 526
    goto :goto_2

    .line 527
    :pswitch_3d
    new-instance p0, Laq/c;

    .line 528
    .line 529
    const/16 v6, 0x8

    .line 530
    .line 531
    invoke-direct {p0, v5, v6}, Laq/c;-><init>(Ljava/lang/String;I)V

    .line 532
    .line 533
    .line 534
    goto :goto_2

    .line 535
    :pswitch_3e
    new-instance p0, Lgz0/a;

    .line 536
    .line 537
    invoke-direct {p0, v5}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 538
    .line 539
    .line 540
    :goto_2
    instance-of v5, p0, Lko/e;

    .line 541
    .line 542
    if-nez v5, :cond_3

    .line 543
    .line 544
    goto :goto_3

    .line 545
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 546
    .line 547
    goto/16 :goto_1

    .line 548
    .line 549
    :cond_4
    const-string p1, "Error"

    .line 550
    .line 551
    invoke-virtual {p0, p1}, Landroid/os/Bundle;->getSerializable(Ljava/lang/String;)Ljava/io/Serializable;

    .line 552
    .line 553
    .line 554
    move-result-object p0

    .line 555
    check-cast p0, Ljava/lang/Exception;

    .line 556
    .line 557
    :cond_5
    :goto_3
    if-eqz p0, :cond_6

    .line 558
    .line 559
    invoke-virtual {v0, p0}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 560
    .line 561
    .line 562
    return v1

    .line 563
    :cond_6
    new-instance p0, Laq/c;

    .line 564
    .line 565
    const-string p1, "Failed to get error reason."

    .line 566
    .line 567
    const/4 p2, 0x7

    .line 568
    invoke-direct {p0, p1, p2}, Laq/c;-><init>(Ljava/lang/String;I)V

    .line 569
    .line 570
    .line 571
    invoke-virtual {v0, p0}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 572
    .line 573
    .line 574
    return v1

    .line 575
    :cond_7
    sget-object p2, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 576
    .line 577
    invoke-static {p1, p2}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 578
    .line 579
    .line 580
    move-result-object p2

    .line 581
    check-cast p2, Landroid/os/Bundle;

    .line 582
    .line 583
    sget-object v2, Lko/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 584
    .line 585
    invoke-static {p1, v2}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 586
    .line 587
    .line 588
    move-result-object v2

    .line 589
    check-cast v2, Lko/f;

    .line 590
    .line 591
    invoke-static {p1}, Lfp/a;->b(Landroid/os/Parcel;)V

    .line 592
    .line 593
    .line 594
    iget-object p0, p0, Lxo/e;->e:Lxo/a;

    .line 595
    .line 596
    invoke-interface {p0, p2}, Lxo/a;->o(Landroid/os/Bundle;)Ljava/lang/Object;

    .line 597
    .line 598
    .line 599
    move-result-object p0

    .line 600
    invoke-virtual {v0, p0}, Laq/k;->d(Ljava/lang/Object;)V

    .line 601
    .line 602
    .line 603
    return v1

    .line 604
    nop

    .line 605
    :pswitch_data_0
    .packed-switch 0xb79b
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
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

.class public final Lpp/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable$Creator;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lpp/h;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v0, v0, Lpp/h;->a:I

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance v0, Ltt/c;

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ltt/c;-><init>(Landroid/os/Parcel;)V

    .line 13
    .line 14
    .line 15
    return-object v0

    .line 16
    :pswitch_0
    const-string v0, "parcel"

    .line 17
    .line 18
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    new-instance v3, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 32
    .line 33
    .line 34
    const/4 v4, 0x0

    .line 35
    move v5, v4

    .line 36
    :goto_0
    const/4 v6, 0x1

    .line 37
    if-eq v5, v2, :cond_0

    .line 38
    .line 39
    sget-object v7, Ltc/e;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 40
    .line 41
    invoke-static {v7, v1, v3, v5, v6}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_1

    .line 51
    .line 52
    move v4, v6

    .line 53
    :cond_1
    new-instance v1, Ltc/q;

    .line 54
    .line 55
    invoke-direct {v1, v0, v3, v4}, Ltc/q;-><init>(Ljava/lang/String;Ljava/util/ArrayList;Z)V

    .line 56
    .line 57
    .line 58
    return-object v1

    .line 59
    :pswitch_1
    const-string v0, "parcel"

    .line 60
    .line 61
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    new-instance v2, Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-direct {v2, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 71
    .line 72
    .line 73
    const/4 v3, 0x0

    .line 74
    :goto_1
    if-eq v3, v0, :cond_2

    .line 75
    .line 76
    const-class v4, Ltc/k;

    .line 77
    .line 78
    invoke-virtual {v4}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    invoke-virtual {v1, v4}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 83
    .line 84
    .line 85
    move-result-object v4

    .line 86
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    add-int/lit8 v3, v3, 0x1

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_2
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    new-instance v1, Ltc/k;

    .line 97
    .line 98
    invoke-direct {v1, v0, v2}, Ltc/k;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 99
    .line 100
    .line 101
    return-object v1

    .line 102
    :pswitch_2
    const-string v0, "parcel"

    .line 103
    .line 104
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    move-object v0, v1

    .line 108
    new-instance v1, Ltc/e;

    .line 109
    .line 110
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    invoke-static {v4}, Ltc/d;->valueOf(Ljava/lang/String;)Ltc/d;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 131
    .line 132
    .line 133
    move-result v6

    .line 134
    const/4 v7, 0x0

    .line 135
    const/4 v8, 0x1

    .line 136
    const/4 v9, 0x0

    .line 137
    if-nez v6, :cond_3

    .line 138
    .line 139
    move-object v6, v9

    .line 140
    goto :goto_3

    .line 141
    :cond_3
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 142
    .line 143
    .line 144
    move-result v6

    .line 145
    if-eqz v6, :cond_4

    .line 146
    .line 147
    move v6, v8

    .line 148
    goto :goto_2

    .line 149
    :cond_4
    move v6, v7

    .line 150
    :goto_2
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 151
    .line 152
    .line 153
    move-result-object v6

    .line 154
    :goto_3
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 155
    .line 156
    .line 157
    move-result v10

    .line 158
    if-nez v10, :cond_5

    .line 159
    .line 160
    :goto_4
    move-object v7, v9

    .line 161
    goto :goto_5

    .line 162
    :cond_5
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 163
    .line 164
    .line 165
    move-result v9

    .line 166
    if-eqz v9, :cond_6

    .line 167
    .line 168
    move v7, v8

    .line 169
    :cond_6
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 170
    .line 171
    .line 172
    move-result-object v9

    .line 173
    goto :goto_4

    .line 174
    :goto_5
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object v8

    .line 178
    invoke-direct/range {v1 .. v8}, Ltc/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ltc/d;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    return-object v1

    .line 182
    :pswitch_3
    move-object v0, v1

    .line 183
    const-string v1, "parcel"

    .line 184
    .line 185
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    new-instance v1, Ltb/w;

    .line 189
    .line 190
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v2

    .line 194
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    invoke-direct {v1, v2, v3, v0}, Ltb/w;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    return-object v1

    .line 206
    :pswitch_4
    move-object v0, v1

    .line 207
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    const/4 v2, 0x0

    .line 212
    :goto_6
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 213
    .line 214
    .line 215
    move-result v3

    .line 216
    if-ge v3, v1, :cond_8

    .line 217
    .line 218
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 219
    .line 220
    .line 221
    move-result v3

    .line 222
    int-to-char v4, v3

    .line 223
    const/4 v5, 0x2

    .line 224
    if-eq v4, v5, :cond_7

    .line 225
    .line 226
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 227
    .line 228
    .line 229
    goto :goto_6

    .line 230
    :cond_7
    invoke-static {v0, v3}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 231
    .line 232
    .line 233
    move-result-object v2

    .line 234
    goto :goto_6

    .line 235
    :cond_8
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 236
    .line 237
    .line 238
    new-instance v0, Lsp/s;

    .line 239
    .line 240
    invoke-direct {v0, v2}, Lsp/s;-><init>(Landroid/os/IBinder;)V

    .line 241
    .line 242
    .line 243
    return-object v0

    .line 244
    :pswitch_5
    move-object v0, v1

    .line 245
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 246
    .line 247
    .line 248
    move-result v1

    .line 249
    const/4 v2, 0x0

    .line 250
    const/4 v3, 0x0

    .line 251
    const/4 v4, 0x0

    .line 252
    move-object v6, v2

    .line 253
    move-object v13, v6

    .line 254
    move-object v14, v13

    .line 255
    move-object/from16 v16, v14

    .line 256
    .line 257
    move-object/from16 v17, v16

    .line 258
    .line 259
    move v8, v3

    .line 260
    move v10, v8

    .line 261
    move v11, v10

    .line 262
    move v12, v11

    .line 263
    move v15, v12

    .line 264
    move v7, v4

    .line 265
    move v9, v7

    .line 266
    :goto_7
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 267
    .line 268
    .line 269
    move-result v2

    .line 270
    if-ge v2, v1, :cond_9

    .line 271
    .line 272
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 273
    .line 274
    .line 275
    move-result v2

    .line 276
    int-to-char v3, v2

    .line 277
    packed-switch v3, :pswitch_data_1

    .line 278
    .line 279
    .line 280
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 281
    .line 282
    .line 283
    goto :goto_7

    .line 284
    :pswitch_6
    sget-object v3, Lsp/u;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 285
    .line 286
    invoke-static {v0, v2, v3}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 287
    .line 288
    .line 289
    move-result-object v17

    .line 290
    goto :goto_7

    .line 291
    :pswitch_7
    sget-object v3, Lsp/m;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 292
    .line 293
    invoke-static {v0, v2, v3}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 294
    .line 295
    .line 296
    move-result-object v16

    .line 297
    goto :goto_7

    .line 298
    :pswitch_8
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 299
    .line 300
    .line 301
    move-result v15

    .line 302
    goto :goto_7

    .line 303
    :pswitch_9
    sget-object v3, Lsp/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 304
    .line 305
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 306
    .line 307
    .line 308
    move-result-object v2

    .line 309
    move-object v14, v2

    .line 310
    check-cast v14, Lsp/d;

    .line 311
    .line 312
    goto :goto_7

    .line 313
    :pswitch_a
    sget-object v3, Lsp/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 314
    .line 315
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 316
    .line 317
    .line 318
    move-result-object v2

    .line 319
    move-object v13, v2

    .line 320
    check-cast v13, Lsp/d;

    .line 321
    .line 322
    goto :goto_7

    .line 323
    :pswitch_b
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 324
    .line 325
    .line 326
    move-result v12

    .line 327
    goto :goto_7

    .line 328
    :pswitch_c
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 329
    .line 330
    .line 331
    move-result v11

    .line 332
    goto :goto_7

    .line 333
    :pswitch_d
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 334
    .line 335
    .line 336
    move-result v10

    .line 337
    goto :goto_7

    .line 338
    :pswitch_e
    invoke-static {v0, v2}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 339
    .line 340
    .line 341
    move-result v9

    .line 342
    goto :goto_7

    .line 343
    :pswitch_f
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 344
    .line 345
    .line 346
    move-result v8

    .line 347
    goto :goto_7

    .line 348
    :pswitch_10
    invoke-static {v0, v2}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 349
    .line 350
    .line 351
    move-result v7

    .line 352
    goto :goto_7

    .line 353
    :pswitch_11
    sget-object v3, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 354
    .line 355
    invoke-static {v0, v2, v3}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 356
    .line 357
    .line 358
    move-result-object v6

    .line 359
    goto :goto_7

    .line 360
    :cond_9
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 361
    .line 362
    .line 363
    new-instance v5, Lsp/r;

    .line 364
    .line 365
    invoke-direct/range {v5 .. v17}, Lsp/r;-><init>(Ljava/util/ArrayList;FIFZZZLsp/d;Lsp/d;ILjava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 366
    .line 367
    .line 368
    return-object v5

    .line 369
    :pswitch_12
    move-object v0, v1

    .line 370
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 371
    .line 372
    .line 373
    move-result v1

    .line 374
    const/4 v2, 0x0

    .line 375
    move-object v3, v2

    .line 376
    move-object v4, v3

    .line 377
    :goto_8
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 378
    .line 379
    .line 380
    move-result v5

    .line 381
    if-ge v5, v1, :cond_d

    .line 382
    .line 383
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 384
    .line 385
    .line 386
    move-result v5

    .line 387
    int-to-char v6, v5

    .line 388
    const/4 v7, 0x2

    .line 389
    if-eq v6, v7, :cond_c

    .line 390
    .line 391
    const/4 v7, 0x3

    .line 392
    if-eq v6, v7, :cond_b

    .line 393
    .line 394
    const/4 v7, 0x4

    .line 395
    if-eq v6, v7, :cond_a

    .line 396
    .line 397
    invoke-static {v0, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 398
    .line 399
    .line 400
    goto :goto_8

    .line 401
    :cond_a
    invoke-static {v0, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object v4

    .line 405
    goto :goto_8

    .line 406
    :cond_b
    invoke-static {v0, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 407
    .line 408
    .line 409
    move-result-object v3

    .line 410
    goto :goto_8

    .line 411
    :cond_c
    sget-object v2, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 412
    .line 413
    invoke-static {v0, v5, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 414
    .line 415
    .line 416
    move-result-object v2

    .line 417
    check-cast v2, Lcom/google/android/gms/maps/model/LatLng;

    .line 418
    .line 419
    goto :goto_8

    .line 420
    :cond_d
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 421
    .line 422
    .line 423
    new-instance v0, Lsp/n;

    .line 424
    .line 425
    invoke-direct {v0, v2, v3, v4}, Lsp/n;-><init>(Lcom/google/android/gms/maps/model/LatLng;Ljava/lang/String;Ljava/lang/String;)V

    .line 426
    .line 427
    .line 428
    return-object v0

    .line 429
    :pswitch_13
    move-object v0, v1

    .line 430
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 431
    .line 432
    .line 433
    move-result v1

    .line 434
    const/4 v2, 0x0

    .line 435
    const/4 v3, 0x0

    .line 436
    :goto_9
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 437
    .line 438
    .line 439
    move-result v4

    .line 440
    if-ge v4, v1, :cond_10

    .line 441
    .line 442
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 443
    .line 444
    .line 445
    move-result v4

    .line 446
    int-to-char v5, v4

    .line 447
    const/4 v6, 0x2

    .line 448
    if-eq v5, v6, :cond_f

    .line 449
    .line 450
    const/4 v6, 0x3

    .line 451
    if-eq v5, v6, :cond_e

    .line 452
    .line 453
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 454
    .line 455
    .line 456
    goto :goto_9

    .line 457
    :cond_e
    invoke-static {v0, v4}, Ljp/xb;->p(Landroid/os/Parcel;I)Ljava/lang/Float;

    .line 458
    .line 459
    .line 460
    move-result-object v2

    .line 461
    goto :goto_9

    .line 462
    :cond_f
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 463
    .line 464
    .line 465
    move-result v3

    .line 466
    goto :goto_9

    .line 467
    :cond_10
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 468
    .line 469
    .line 470
    new-instance v0, Lsp/m;

    .line 471
    .line 472
    invoke-direct {v0, v3, v2}, Lsp/m;-><init>(ILjava/lang/Float;)V

    .line 473
    .line 474
    .line 475
    return-object v0

    .line 476
    :pswitch_14
    move-object v0, v1

    .line 477
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 478
    .line 479
    .line 480
    move-result v1

    .line 481
    const/4 v4, 0x0

    .line 482
    const/high16 v5, 0x3f800000    # 1.0f

    .line 483
    .line 484
    const/high16 v6, 0x3f000000    # 0.5f

    .line 485
    .line 486
    move v13, v4

    .line 487
    move v14, v13

    .line 488
    move v15, v14

    .line 489
    move/from16 v23, v15

    .line 490
    .line 491
    move/from16 v24, v23

    .line 492
    .line 493
    move/from16 v21, v5

    .line 494
    .line 495
    move/from16 v19, v6

    .line 496
    .line 497
    const/4 v7, 0x0

    .line 498
    const/4 v8, 0x0

    .line 499
    const/4 v9, 0x0

    .line 500
    const/4 v10, 0x0

    .line 501
    const/4 v11, 0x0

    .line 502
    const/4 v12, 0x0

    .line 503
    const/16 v16, 0x0

    .line 504
    .line 505
    const/16 v18, 0x0

    .line 506
    .line 507
    const/16 v20, 0x0

    .line 508
    .line 509
    const/16 v22, 0x0

    .line 510
    .line 511
    const/16 v25, 0x0

    .line 512
    .line 513
    const/16 v26, 0x0

    .line 514
    .line 515
    :goto_a
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 516
    .line 517
    .line 518
    move-result v3

    .line 519
    if-ge v3, v1, :cond_11

    .line 520
    .line 521
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 522
    .line 523
    .line 524
    move-result v3

    .line 525
    int-to-char v2, v3

    .line 526
    packed-switch v2, :pswitch_data_2

    .line 527
    .line 528
    .line 529
    :pswitch_15
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 530
    .line 531
    .line 532
    goto :goto_a

    .line 533
    :pswitch_16
    invoke-static {v0, v3}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 534
    .line 535
    .line 536
    move-result v26

    .line 537
    goto :goto_a

    .line 538
    :pswitch_17
    invoke-static {v0, v3}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 539
    .line 540
    .line 541
    move-result-object v25

    .line 542
    goto :goto_a

    .line 543
    :pswitch_18
    invoke-static {v0, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 544
    .line 545
    .line 546
    move-result v24

    .line 547
    goto :goto_a

    .line 548
    :pswitch_19
    invoke-static {v0, v3}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 549
    .line 550
    .line 551
    move-result-object v16

    .line 552
    goto :goto_a

    .line 553
    :pswitch_1a
    invoke-static {v0, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 554
    .line 555
    .line 556
    move-result v23

    .line 557
    goto :goto_a

    .line 558
    :pswitch_1b
    invoke-static {v0, v3}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 559
    .line 560
    .line 561
    move-result v22

    .line 562
    goto :goto_a

    .line 563
    :pswitch_1c
    invoke-static {v0, v3}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 564
    .line 565
    .line 566
    move-result v21

    .line 567
    goto :goto_a

    .line 568
    :pswitch_1d
    invoke-static {v0, v3}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 569
    .line 570
    .line 571
    move-result v20

    .line 572
    goto :goto_a

    .line 573
    :pswitch_1e
    invoke-static {v0, v3}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 574
    .line 575
    .line 576
    move-result v19

    .line 577
    goto :goto_a

    .line 578
    :pswitch_1f
    invoke-static {v0, v3}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 579
    .line 580
    .line 581
    move-result v18

    .line 582
    goto :goto_a

    .line 583
    :pswitch_20
    invoke-static {v0, v3}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 584
    .line 585
    .line 586
    move-result v15

    .line 587
    goto :goto_a

    .line 588
    :pswitch_21
    invoke-static {v0, v3}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 589
    .line 590
    .line 591
    move-result v14

    .line 592
    goto :goto_a

    .line 593
    :pswitch_22
    invoke-static {v0, v3}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 594
    .line 595
    .line 596
    move-result v13

    .line 597
    goto :goto_a

    .line 598
    :pswitch_23
    invoke-static {v0, v3}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 599
    .line 600
    .line 601
    move-result v12

    .line 602
    goto :goto_a

    .line 603
    :pswitch_24
    invoke-static {v0, v3}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 604
    .line 605
    .line 606
    move-result v11

    .line 607
    goto :goto_a

    .line 608
    :pswitch_25
    invoke-static {v0, v3}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 609
    .line 610
    .line 611
    move-result-object v10

    .line 612
    goto :goto_a

    .line 613
    :pswitch_26
    invoke-static {v0, v3}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 614
    .line 615
    .line 616
    move-result-object v9

    .line 617
    goto :goto_a

    .line 618
    :pswitch_27
    invoke-static {v0, v3}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 619
    .line 620
    .line 621
    move-result-object v8

    .line 622
    goto :goto_a

    .line 623
    :pswitch_28
    sget-object v2, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 624
    .line 625
    invoke-static {v0, v3, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 626
    .line 627
    .line 628
    move-result-object v2

    .line 629
    move-object v7, v2

    .line 630
    check-cast v7, Lcom/google/android/gms/maps/model/LatLng;

    .line 631
    .line 632
    goto :goto_a

    .line 633
    :cond_11
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 634
    .line 635
    .line 636
    new-instance v0, Lsp/l;

    .line 637
    .line 638
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 639
    .line 640
    .line 641
    iput v6, v0, Lsp/l;->h:F

    .line 642
    .line 643
    iput v5, v0, Lsp/l;->i:F

    .line 644
    .line 645
    const/4 v1, 0x1

    .line 646
    iput-boolean v1, v0, Lsp/l;->k:Z

    .line 647
    .line 648
    iput-boolean v4, v0, Lsp/l;->l:Z

    .line 649
    .line 650
    const/4 v1, 0x0

    .line 651
    iput v1, v0, Lsp/l;->m:F

    .line 652
    .line 653
    iput v6, v0, Lsp/l;->n:F

    .line 654
    .line 655
    iput v1, v0, Lsp/l;->o:F

    .line 656
    .line 657
    iput v5, v0, Lsp/l;->p:F

    .line 658
    .line 659
    iput v4, v0, Lsp/l;->r:I

    .line 660
    .line 661
    iput-object v7, v0, Lsp/l;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 662
    .line 663
    iput-object v8, v0, Lsp/l;->e:Ljava/lang/String;

    .line 664
    .line 665
    iput-object v9, v0, Lsp/l;->f:Ljava/lang/String;

    .line 666
    .line 667
    if-nez v10, :cond_12

    .line 668
    .line 669
    const/4 v1, 0x0

    .line 670
    iput-object v1, v0, Lsp/l;->g:Lsp/b;

    .line 671
    .line 672
    goto :goto_b

    .line 673
    :cond_12
    const/4 v1, 0x0

    .line 674
    new-instance v2, Lsp/b;

    .line 675
    .line 676
    invoke-static {v10}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 677
    .line 678
    .line 679
    move-result-object v3

    .line 680
    invoke-direct {v2, v3}, Lsp/b;-><init>(Lyo/a;)V

    .line 681
    .line 682
    .line 683
    iput-object v2, v0, Lsp/l;->g:Lsp/b;

    .line 684
    .line 685
    :goto_b
    iput v11, v0, Lsp/l;->h:F

    .line 686
    .line 687
    iput v12, v0, Lsp/l;->i:F

    .line 688
    .line 689
    iput-boolean v13, v0, Lsp/l;->j:Z

    .line 690
    .line 691
    iput-boolean v14, v0, Lsp/l;->k:Z

    .line 692
    .line 693
    iput-boolean v15, v0, Lsp/l;->l:Z

    .line 694
    .line 695
    move/from16 v2, v18

    .line 696
    .line 697
    iput v2, v0, Lsp/l;->m:F

    .line 698
    .line 699
    move/from16 v6, v19

    .line 700
    .line 701
    iput v6, v0, Lsp/l;->n:F

    .line 702
    .line 703
    move/from16 v2, v20

    .line 704
    .line 705
    iput v2, v0, Lsp/l;->o:F

    .line 706
    .line 707
    move/from16 v5, v21

    .line 708
    .line 709
    iput v5, v0, Lsp/l;->p:F

    .line 710
    .line 711
    move/from16 v2, v22

    .line 712
    .line 713
    iput v2, v0, Lsp/l;->q:F

    .line 714
    .line 715
    move/from16 v4, v24

    .line 716
    .line 717
    iput v4, v0, Lsp/l;->t:I

    .line 718
    .line 719
    move/from16 v4, v23

    .line 720
    .line 721
    iput v4, v0, Lsp/l;->r:I

    .line 722
    .line 723
    invoke-static/range {v16 .. v16}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 724
    .line 725
    .line 726
    move-result-object v2

    .line 727
    if-nez v2, :cond_13

    .line 728
    .line 729
    move-object v3, v1

    .line 730
    goto :goto_c

    .line 731
    :cond_13
    invoke-static {v2}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 732
    .line 733
    .line 734
    move-result-object v1

    .line 735
    move-object v3, v1

    .line 736
    check-cast v3, Landroid/view/View;

    .line 737
    .line 738
    :goto_c
    iput-object v3, v0, Lsp/l;->s:Landroid/view/View;

    .line 739
    .line 740
    move-object/from16 v3, v25

    .line 741
    .line 742
    iput-object v3, v0, Lsp/l;->u:Ljava/lang/String;

    .line 743
    .line 744
    move/from16 v2, v26

    .line 745
    .line 746
    iput v2, v0, Lsp/l;->v:F

    .line 747
    .line 748
    return-object v0

    .line 749
    :pswitch_29
    move-object v0, v1

    .line 750
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 751
    .line 752
    .line 753
    move-result v1

    .line 754
    const/4 v2, 0x0

    .line 755
    :goto_d
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 756
    .line 757
    .line 758
    move-result v3

    .line 759
    if-ge v3, v1, :cond_15

    .line 760
    .line 761
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 762
    .line 763
    .line 764
    move-result v3

    .line 765
    int-to-char v4, v3

    .line 766
    const/4 v5, 0x2

    .line 767
    if-eq v4, v5, :cond_14

    .line 768
    .line 769
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 770
    .line 771
    .line 772
    goto :goto_d

    .line 773
    :cond_14
    invoke-static {v0, v3}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 774
    .line 775
    .line 776
    move-result-object v2

    .line 777
    goto :goto_d

    .line 778
    :cond_15
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 779
    .line 780
    .line 781
    new-instance v0, Lsp/j;

    .line 782
    .line 783
    invoke-direct {v0, v2}, Lsp/j;-><init>(Ljava/lang/String;)V

    .line 784
    .line 785
    .line 786
    return-object v0

    .line 787
    :pswitch_2a
    move-object v0, v1

    .line 788
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 789
    .line 790
    .line 791
    move-result v1

    .line 792
    const-wide/16 v2, 0x0

    .line 793
    .line 794
    move-wide v4, v2

    .line 795
    :goto_e
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 796
    .line 797
    .line 798
    move-result v6

    .line 799
    if-ge v6, v1, :cond_18

    .line 800
    .line 801
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 802
    .line 803
    .line 804
    move-result v6

    .line 805
    int-to-char v7, v6

    .line 806
    const/4 v8, 0x2

    .line 807
    if-eq v7, v8, :cond_17

    .line 808
    .line 809
    const/4 v8, 0x3

    .line 810
    if-eq v7, v8, :cond_16

    .line 811
    .line 812
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 813
    .line 814
    .line 815
    goto :goto_e

    .line 816
    :cond_16
    invoke-static {v0, v6}, Ljp/xb;->n(Landroid/os/Parcel;I)D

    .line 817
    .line 818
    .line 819
    move-result-wide v4

    .line 820
    goto :goto_e

    .line 821
    :cond_17
    invoke-static {v0, v6}, Ljp/xb;->n(Landroid/os/Parcel;I)D

    .line 822
    .line 823
    .line 824
    move-result-wide v2

    .line 825
    goto :goto_e

    .line 826
    :cond_18
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 827
    .line 828
    .line 829
    new-instance v0, Lcom/google/android/gms/maps/model/LatLng;

    .line 830
    .line 831
    invoke-direct {v0, v2, v3, v4, v5}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 832
    .line 833
    .line 834
    return-object v0

    .line 835
    :pswitch_2b
    move-object v0, v1

    .line 836
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 837
    .line 838
    .line 839
    move-result v1

    .line 840
    const/4 v2, 0x0

    .line 841
    move-object v3, v2

    .line 842
    :goto_f
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 843
    .line 844
    .line 845
    move-result v4

    .line 846
    if-ge v4, v1, :cond_1b

    .line 847
    .line 848
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 849
    .line 850
    .line 851
    move-result v4

    .line 852
    int-to-char v5, v4

    .line 853
    const/4 v6, 0x2

    .line 854
    if-eq v5, v6, :cond_1a

    .line 855
    .line 856
    const/4 v6, 0x3

    .line 857
    if-eq v5, v6, :cond_19

    .line 858
    .line 859
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 860
    .line 861
    .line 862
    goto :goto_f

    .line 863
    :cond_19
    sget-object v3, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 864
    .line 865
    invoke-static {v0, v4, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 866
    .line 867
    .line 868
    move-result-object v3

    .line 869
    check-cast v3, Lcom/google/android/gms/maps/model/LatLng;

    .line 870
    .line 871
    goto :goto_f

    .line 872
    :cond_1a
    sget-object v2, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 873
    .line 874
    invoke-static {v0, v4, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 875
    .line 876
    .line 877
    move-result-object v2

    .line 878
    check-cast v2, Lcom/google/android/gms/maps/model/LatLng;

    .line 879
    .line 880
    goto :goto_f

    .line 881
    :cond_1b
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 882
    .line 883
    .line 884
    new-instance v0, Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 885
    .line 886
    invoke-direct {v0, v2, v3}, Lcom/google/android/gms/maps/model/LatLngBounds;-><init>(Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 887
    .line 888
    .line 889
    return-object v0

    .line 890
    :pswitch_2c
    move-object v0, v1

    .line 891
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 892
    .line 893
    .line 894
    move-result v1

    .line 895
    const/4 v2, 0x0

    .line 896
    const/4 v3, 0x0

    .line 897
    const/4 v4, 0x0

    .line 898
    const-wide/16 v5, 0x0

    .line 899
    .line 900
    move v7, v3

    .line 901
    move v8, v4

    .line 902
    move v9, v8

    .line 903
    move-wide v10, v5

    .line 904
    move-object v3, v2

    .line 905
    move v4, v7

    .line 906
    move v5, v4

    .line 907
    move v6, v5

    .line 908
    :goto_10
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 909
    .line 910
    .line 911
    move-result v12

    .line 912
    if-ge v12, v1, :cond_1c

    .line 913
    .line 914
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 915
    .line 916
    .line 917
    move-result v12

    .line 918
    int-to-char v13, v12

    .line 919
    packed-switch v13, :pswitch_data_3

    .line 920
    .line 921
    .line 922
    invoke-static {v0, v12}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 923
    .line 924
    .line 925
    goto :goto_10

    .line 926
    :pswitch_2d
    sget-object v3, Lsp/m;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 927
    .line 928
    invoke-static {v0, v12, v3}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 929
    .line 930
    .line 931
    move-result-object v3

    .line 932
    goto :goto_10

    .line 933
    :pswitch_2e
    invoke-static {v0, v12}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 934
    .line 935
    .line 936
    move-result v7

    .line 937
    goto :goto_10

    .line 938
    :pswitch_2f
    invoke-static {v0, v12}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 939
    .line 940
    .line 941
    move-result v6

    .line 942
    goto :goto_10

    .line 943
    :pswitch_30
    invoke-static {v0, v12}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 944
    .line 945
    .line 946
    move-result v9

    .line 947
    goto :goto_10

    .line 948
    :pswitch_31
    invoke-static {v0, v12}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 949
    .line 950
    .line 951
    move-result v5

    .line 952
    goto :goto_10

    .line 953
    :pswitch_32
    invoke-static {v0, v12}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 954
    .line 955
    .line 956
    move-result v4

    .line 957
    goto :goto_10

    .line 958
    :pswitch_33
    invoke-static {v0, v12}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 959
    .line 960
    .line 961
    move-result v8

    .line 962
    goto :goto_10

    .line 963
    :pswitch_34
    invoke-static {v0, v12}, Ljp/xb;->n(Landroid/os/Parcel;I)D

    .line 964
    .line 965
    .line 966
    move-result-wide v10

    .line 967
    goto :goto_10

    .line 968
    :pswitch_35
    sget-object v2, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 969
    .line 970
    invoke-static {v0, v12, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 971
    .line 972
    .line 973
    move-result-object v2

    .line 974
    check-cast v2, Lcom/google/android/gms/maps/model/LatLng;

    .line 975
    .line 976
    goto :goto_10

    .line 977
    :cond_1c
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 978
    .line 979
    .line 980
    new-instance v0, Lsp/f;

    .line 981
    .line 982
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 983
    .line 984
    .line 985
    iput-object v2, v0, Lsp/f;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 986
    .line 987
    iput-wide v10, v0, Lsp/f;->e:D

    .line 988
    .line 989
    iput v8, v0, Lsp/f;->f:F

    .line 990
    .line 991
    iput v4, v0, Lsp/f;->g:I

    .line 992
    .line 993
    iput v5, v0, Lsp/f;->h:I

    .line 994
    .line 995
    iput v9, v0, Lsp/f;->i:F

    .line 996
    .line 997
    iput-boolean v6, v0, Lsp/f;->j:Z

    .line 998
    .line 999
    iput-boolean v7, v0, Lsp/f;->k:Z

    .line 1000
    .line 1001
    iput-object v3, v0, Lsp/f;->l:Ljava/util/ArrayList;

    .line 1002
    .line 1003
    return-object v0

    .line 1004
    :pswitch_36
    move-object v0, v1

    .line 1005
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1006
    .line 1007
    .line 1008
    move-result v1

    .line 1009
    const/4 v2, 0x0

    .line 1010
    const/4 v3, 0x0

    .line 1011
    move-object v4, v2

    .line 1012
    move-object v5, v4

    .line 1013
    :goto_11
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1014
    .line 1015
    .line 1016
    move-result v6

    .line 1017
    if-ge v6, v1, :cond_20

    .line 1018
    .line 1019
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1020
    .line 1021
    .line 1022
    move-result v6

    .line 1023
    int-to-char v7, v6

    .line 1024
    const/4 v8, 0x2

    .line 1025
    if-eq v7, v8, :cond_1f

    .line 1026
    .line 1027
    const/4 v8, 0x3

    .line 1028
    if-eq v7, v8, :cond_1e

    .line 1029
    .line 1030
    const/4 v8, 0x4

    .line 1031
    if-eq v7, v8, :cond_1d

    .line 1032
    .line 1033
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1034
    .line 1035
    .line 1036
    goto :goto_11

    .line 1037
    :cond_1d
    invoke-static {v0, v6}, Ljp/xb;->p(Landroid/os/Parcel;I)Ljava/lang/Float;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v5

    .line 1041
    goto :goto_11

    .line 1042
    :cond_1e
    invoke-static {v0, v6}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1043
    .line 1044
    .line 1045
    move-result-object v4

    .line 1046
    goto :goto_11

    .line 1047
    :cond_1f
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1048
    .line 1049
    .line 1050
    move-result v3

    .line 1051
    goto :goto_11

    .line 1052
    :cond_20
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1053
    .line 1054
    .line 1055
    new-instance v0, Lsp/d;

    .line 1056
    .line 1057
    if-nez v4, :cond_21

    .line 1058
    .line 1059
    goto :goto_12

    .line 1060
    :cond_21
    invoke-static {v4}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 1061
    .line 1062
    .line 1063
    move-result-object v1

    .line 1064
    new-instance v2, Lsp/b;

    .line 1065
    .line 1066
    invoke-direct {v2, v1}, Lsp/b;-><init>(Lyo/a;)V

    .line 1067
    .line 1068
    .line 1069
    :goto_12
    invoke-direct {v0, v3, v2, v5}, Lsp/d;-><init>(ILsp/b;Ljava/lang/Float;)V

    .line 1070
    .line 1071
    .line 1072
    return-object v0

    .line 1073
    :pswitch_37
    move-object v0, v1

    .line 1074
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1075
    .line 1076
    .line 1077
    move-result v1

    .line 1078
    const/4 v2, 0x0

    .line 1079
    move-object v4, v2

    .line 1080
    move-object v5, v4

    .line 1081
    move-object v6, v5

    .line 1082
    move-object v7, v6

    .line 1083
    move-object v8, v7

    .line 1084
    :goto_13
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1085
    .line 1086
    .line 1087
    move-result v2

    .line 1088
    if-ge v2, v1, :cond_27

    .line 1089
    .line 1090
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1091
    .line 1092
    .line 1093
    move-result v2

    .line 1094
    int-to-char v3, v2

    .line 1095
    const/4 v9, 0x2

    .line 1096
    if-eq v3, v9, :cond_26

    .line 1097
    .line 1098
    const/4 v9, 0x3

    .line 1099
    if-eq v3, v9, :cond_25

    .line 1100
    .line 1101
    const/4 v9, 0x4

    .line 1102
    if-eq v3, v9, :cond_24

    .line 1103
    .line 1104
    const/4 v9, 0x5

    .line 1105
    if-eq v3, v9, :cond_23

    .line 1106
    .line 1107
    const/4 v9, 0x6

    .line 1108
    if-eq v3, v9, :cond_22

    .line 1109
    .line 1110
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1111
    .line 1112
    .line 1113
    goto :goto_13

    .line 1114
    :cond_22
    sget-object v3, Lcom/google/android/gms/maps/model/LatLngBounds;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1115
    .line 1116
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1117
    .line 1118
    .line 1119
    move-result-object v2

    .line 1120
    move-object v8, v2

    .line 1121
    check-cast v8, Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 1122
    .line 1123
    goto :goto_13

    .line 1124
    :cond_23
    sget-object v3, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1125
    .line 1126
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v2

    .line 1130
    move-object v7, v2

    .line 1131
    check-cast v7, Lcom/google/android/gms/maps/model/LatLng;

    .line 1132
    .line 1133
    goto :goto_13

    .line 1134
    :cond_24
    sget-object v3, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1135
    .line 1136
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v2

    .line 1140
    move-object v6, v2

    .line 1141
    check-cast v6, Lcom/google/android/gms/maps/model/LatLng;

    .line 1142
    .line 1143
    goto :goto_13

    .line 1144
    :cond_25
    sget-object v3, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1145
    .line 1146
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v2

    .line 1150
    move-object v5, v2

    .line 1151
    check-cast v5, Lcom/google/android/gms/maps/model/LatLng;

    .line 1152
    .line 1153
    goto :goto_13

    .line 1154
    :cond_26
    sget-object v3, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1155
    .line 1156
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v2

    .line 1160
    move-object v4, v2

    .line 1161
    check-cast v4, Lcom/google/android/gms/maps/model/LatLng;

    .line 1162
    .line 1163
    goto :goto_13

    .line 1164
    :cond_27
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1165
    .line 1166
    .line 1167
    new-instance v3, Lsp/v;

    .line 1168
    .line 1169
    invoke-direct/range {v3 .. v8}, Lsp/v;-><init>(Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLngBounds;)V

    .line 1170
    .line 1171
    .line 1172
    return-object v3

    .line 1173
    :pswitch_38
    move-object v0, v1

    .line 1174
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1175
    .line 1176
    .line 1177
    move-result v1

    .line 1178
    const-wide/16 v2, 0x0

    .line 1179
    .line 1180
    const/4 v4, 0x0

    .line 1181
    :goto_14
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1182
    .line 1183
    .line 1184
    move-result v5

    .line 1185
    if-ge v5, v1, :cond_2a

    .line 1186
    .line 1187
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1188
    .line 1189
    .line 1190
    move-result v5

    .line 1191
    int-to-char v6, v5

    .line 1192
    const/4 v7, 0x2

    .line 1193
    if-eq v6, v7, :cond_29

    .line 1194
    .line 1195
    const/4 v7, 0x3

    .line 1196
    if-eq v6, v7, :cond_28

    .line 1197
    .line 1198
    invoke-static {v0, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1199
    .line 1200
    .line 1201
    goto :goto_14

    .line 1202
    :cond_28
    invoke-static {v0, v5}, Ljp/xb;->n(Landroid/os/Parcel;I)D

    .line 1203
    .line 1204
    .line 1205
    move-result-wide v2

    .line 1206
    goto :goto_14

    .line 1207
    :cond_29
    sget-object v4, Lsp/t;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1208
    .line 1209
    invoke-static {v0, v5, v4}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1210
    .line 1211
    .line 1212
    move-result-object v4

    .line 1213
    check-cast v4, Lsp/t;

    .line 1214
    .line 1215
    goto :goto_14

    .line 1216
    :cond_2a
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1217
    .line 1218
    .line 1219
    new-instance v0, Lsp/u;

    .line 1220
    .line 1221
    invoke-direct {v0, v4, v2, v3}, Lsp/u;-><init>(Lsp/t;D)V

    .line 1222
    .line 1223
    .line 1224
    return-object v0

    .line 1225
    :pswitch_39
    move-object v0, v1

    .line 1226
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1227
    .line 1228
    .line 1229
    move-result v1

    .line 1230
    const/4 v2, 0x0

    .line 1231
    const/4 v3, 0x0

    .line 1232
    const/4 v4, 0x0

    .line 1233
    move-object v10, v2

    .line 1234
    move v7, v3

    .line 1235
    move v8, v7

    .line 1236
    move v9, v8

    .line 1237
    move v6, v4

    .line 1238
    :goto_15
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1239
    .line 1240
    .line 1241
    move-result v2

    .line 1242
    if-ge v2, v1, :cond_30

    .line 1243
    .line 1244
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1245
    .line 1246
    .line 1247
    move-result v2

    .line 1248
    int-to-char v3, v2

    .line 1249
    const/4 v4, 0x2

    .line 1250
    if-eq v3, v4, :cond_2f

    .line 1251
    .line 1252
    const/4 v4, 0x3

    .line 1253
    if-eq v3, v4, :cond_2e

    .line 1254
    .line 1255
    const/4 v4, 0x4

    .line 1256
    if-eq v3, v4, :cond_2d

    .line 1257
    .line 1258
    const/4 v4, 0x5

    .line 1259
    if-eq v3, v4, :cond_2c

    .line 1260
    .line 1261
    const/4 v4, 0x6

    .line 1262
    if-eq v3, v4, :cond_2b

    .line 1263
    .line 1264
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1265
    .line 1266
    .line 1267
    goto :goto_15

    .line 1268
    :cond_2b
    sget-object v3, Lsp/s;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1269
    .line 1270
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1271
    .line 1272
    .line 1273
    move-result-object v2

    .line 1274
    move-object v10, v2

    .line 1275
    check-cast v10, Lsp/s;

    .line 1276
    .line 1277
    goto :goto_15

    .line 1278
    :cond_2c
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1279
    .line 1280
    .line 1281
    move-result v9

    .line 1282
    goto :goto_15

    .line 1283
    :cond_2d
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1284
    .line 1285
    .line 1286
    move-result v8

    .line 1287
    goto :goto_15

    .line 1288
    :cond_2e
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1289
    .line 1290
    .line 1291
    move-result v7

    .line 1292
    goto :goto_15

    .line 1293
    :cond_2f
    invoke-static {v0, v2}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 1294
    .line 1295
    .line 1296
    move-result v6

    .line 1297
    goto :goto_15

    .line 1298
    :cond_30
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1299
    .line 1300
    .line 1301
    new-instance v5, Lsp/t;

    .line 1302
    .line 1303
    invoke-direct/range {v5 .. v10}, Lsp/t;-><init>(FIIZLsp/s;)V

    .line 1304
    .line 1305
    .line 1306
    return-object v5

    .line 1307
    :pswitch_3a
    move-object v0, v1

    .line 1308
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1309
    .line 1310
    .line 1311
    move-result v1

    .line 1312
    const/4 v2, 0x0

    .line 1313
    const/4 v3, 0x0

    .line 1314
    move v4, v2

    .line 1315
    move-object v5, v3

    .line 1316
    move v3, v4

    .line 1317
    :goto_16
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1318
    .line 1319
    .line 1320
    move-result v6

    .line 1321
    if-ge v6, v1, :cond_35

    .line 1322
    .line 1323
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1324
    .line 1325
    .line 1326
    move-result v6

    .line 1327
    int-to-char v7, v6

    .line 1328
    const/4 v8, 0x2

    .line 1329
    if-eq v7, v8, :cond_34

    .line 1330
    .line 1331
    const/4 v8, 0x3

    .line 1332
    if-eq v7, v8, :cond_33

    .line 1333
    .line 1334
    const/4 v8, 0x4

    .line 1335
    if-eq v7, v8, :cond_32

    .line 1336
    .line 1337
    const/4 v8, 0x5

    .line 1338
    if-eq v7, v8, :cond_31

    .line 1339
    .line 1340
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1341
    .line 1342
    .line 1343
    goto :goto_16

    .line 1344
    :cond_31
    invoke-static {v0, v6}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 1345
    .line 1346
    .line 1347
    move-result v4

    .line 1348
    goto :goto_16

    .line 1349
    :cond_32
    invoke-static {v0, v6}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 1350
    .line 1351
    .line 1352
    move-result v3

    .line 1353
    goto :goto_16

    .line 1354
    :cond_33
    invoke-static {v0, v6}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 1355
    .line 1356
    .line 1357
    move-result v2

    .line 1358
    goto :goto_16

    .line 1359
    :cond_34
    sget-object v5, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1360
    .line 1361
    invoke-static {v0, v6, v5}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1362
    .line 1363
    .line 1364
    move-result-object v5

    .line 1365
    check-cast v5, Lcom/google/android/gms/maps/model/LatLng;

    .line 1366
    .line 1367
    goto :goto_16

    .line 1368
    :cond_35
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1369
    .line 1370
    .line 1371
    new-instance v0, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 1372
    .line 1373
    invoke-direct {v0, v5, v2, v3, v4}, Lcom/google/android/gms/maps/model/CameraPosition;-><init>(Lcom/google/android/gms/maps/model/LatLng;FFF)V

    .line 1374
    .line 1375
    .line 1376
    return-object v0

    .line 1377
    :pswitch_3b
    move-object v0, v1

    .line 1378
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1379
    .line 1380
    .line 1381
    move-result-object v1

    .line 1382
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1383
    .line 1384
    .line 1385
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1386
    .line 1387
    .line 1388
    move-result v2

    .line 1389
    new-instance v3, Ljava/util/LinkedHashMap;

    .line 1390
    .line 1391
    invoke-direct {v3, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 1392
    .line 1393
    .line 1394
    const/4 v4, 0x0

    .line 1395
    :goto_17
    if-ge v4, v2, :cond_36

    .line 1396
    .line 1397
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1398
    .line 1399
    .line 1400
    move-result-object v5

    .line 1401
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1402
    .line 1403
    .line 1404
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1405
    .line 1406
    .line 1407
    move-result-object v6

    .line 1408
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1409
    .line 1410
    .line 1411
    invoke-interface {v3, v5, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1412
    .line 1413
    .line 1414
    add-int/lit8 v4, v4, 0x1

    .line 1415
    .line 1416
    goto :goto_17

    .line 1417
    :cond_36
    new-instance v0, Lrl/a;

    .line 1418
    .line 1419
    invoke-direct {v0, v1, v3}, Lrl/a;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 1420
    .line 1421
    .line 1422
    return-object v0

    .line 1423
    :pswitch_3c
    move-object v0, v1

    .line 1424
    const-string v1, "parcel"

    .line 1425
    .line 1426
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1427
    .line 1428
    .line 1429
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1430
    .line 1431
    .line 1432
    move-result-object v0

    .line 1433
    invoke-static {v0}, Lrd/d;->valueOf(Ljava/lang/String;)Lrd/d;

    .line 1434
    .line 1435
    .line 1436
    move-result-object v0

    .line 1437
    return-object v0

    .line 1438
    :pswitch_3d
    move-object v0, v1

    .line 1439
    const-string v1, "parcel"

    .line 1440
    .line 1441
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1442
    .line 1443
    .line 1444
    new-instance v1, Lrd/a;

    .line 1445
    .line 1446
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v2

    .line 1450
    sget-object v3, Lpd/m;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1451
    .line 1452
    invoke-interface {v3, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 1453
    .line 1454
    .line 1455
    move-result-object v3

    .line 1456
    check-cast v3, Lpd/m;

    .line 1457
    .line 1458
    sget-object v4, Lrd/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1459
    .line 1460
    invoke-interface {v4, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 1461
    .line 1462
    .line 1463
    move-result-object v0

    .line 1464
    check-cast v0, Lrd/d;

    .line 1465
    .line 1466
    invoke-direct {v1, v2, v3, v0}, Lrd/a;-><init>(Ljava/lang/String;Lpd/m;Lrd/d;)V

    .line 1467
    .line 1468
    .line 1469
    return-object v1

    .line 1470
    :pswitch_3e
    move-object v0, v1

    .line 1471
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1472
    .line 1473
    .line 1474
    move-result v1

    .line 1475
    const/4 v2, 0x0

    .line 1476
    move v5, v2

    .line 1477
    const/4 v6, -0x1

    .line 1478
    const/4 v7, -0x1

    .line 1479
    const/4 v8, 0x0

    .line 1480
    const/4 v9, -0x1

    .line 1481
    const/4 v10, -0x1

    .line 1482
    const/4 v11, -0x1

    .line 1483
    const/4 v12, -0x1

    .line 1484
    const/4 v13, -0x1

    .line 1485
    const/4 v14, -0x1

    .line 1486
    const/4 v15, -0x1

    .line 1487
    const/16 v16, -0x1

    .line 1488
    .line 1489
    const/16 v17, -0x1

    .line 1490
    .line 1491
    const/16 v18, -0x1

    .line 1492
    .line 1493
    const/16 v27, 0x0

    .line 1494
    .line 1495
    const/16 v28, 0x0

    .line 1496
    .line 1497
    const/16 v29, 0x0

    .line 1498
    .line 1499
    const/16 v30, 0x0

    .line 1500
    .line 1501
    const/16 v31, 0x0

    .line 1502
    .line 1503
    :goto_18
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1504
    .line 1505
    .line 1506
    move-result v3

    .line 1507
    if-ge v3, v1, :cond_38

    .line 1508
    .line 1509
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1510
    .line 1511
    .line 1512
    move-result v3

    .line 1513
    int-to-char v4, v3

    .line 1514
    packed-switch v4, :pswitch_data_4

    .line 1515
    .line 1516
    .line 1517
    :pswitch_3f
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1518
    .line 1519
    .line 1520
    goto :goto_18

    .line 1521
    :pswitch_40
    invoke-static {v0, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1522
    .line 1523
    .line 1524
    move-result v5

    .line 1525
    goto :goto_18

    .line 1526
    :pswitch_41
    invoke-static {v0, v3}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1527
    .line 1528
    .line 1529
    move-result-object v31

    .line 1530
    goto :goto_18

    .line 1531
    :pswitch_42
    invoke-static {v0, v3}, Ljp/xb;->u(Landroid/os/Parcel;I)I

    .line 1532
    .line 1533
    .line 1534
    move-result v3

    .line 1535
    if-nez v3, :cond_37

    .line 1536
    .line 1537
    const/16 v30, 0x0

    .line 1538
    .line 1539
    goto :goto_18

    .line 1540
    :cond_37
    const/4 v4, 0x4

    .line 1541
    invoke-static {v0, v3, v4}, Ljp/xb;->z(Landroid/os/Parcel;II)V

    .line 1542
    .line 1543
    .line 1544
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1545
    .line 1546
    .line 1547
    move-result v3

    .line 1548
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1549
    .line 1550
    .line 1551
    move-result-object v3

    .line 1552
    move-object/from16 v30, v3

    .line 1553
    .line 1554
    goto :goto_18

    .line 1555
    :pswitch_43
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1556
    .line 1557
    .line 1558
    move-result v18

    .line 1559
    goto :goto_18

    .line 1560
    :pswitch_44
    sget-object v4, Lcom/google/android/gms/maps/model/LatLngBounds;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1561
    .line 1562
    invoke-static {v0, v3, v4}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1563
    .line 1564
    .line 1565
    move-result-object v3

    .line 1566
    move-object/from16 v29, v3

    .line 1567
    .line 1568
    check-cast v29, Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 1569
    .line 1570
    goto :goto_18

    .line 1571
    :pswitch_45
    invoke-static {v0, v3}, Ljp/xb;->p(Landroid/os/Parcel;I)Ljava/lang/Float;

    .line 1572
    .line 1573
    .line 1574
    move-result-object v28

    .line 1575
    goto :goto_18

    .line 1576
    :pswitch_46
    invoke-static {v0, v3}, Ljp/xb;->p(Landroid/os/Parcel;I)Ljava/lang/Float;

    .line 1577
    .line 1578
    .line 1579
    move-result-object v27

    .line 1580
    goto :goto_18

    .line 1581
    :pswitch_47
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1582
    .line 1583
    .line 1584
    move-result v17

    .line 1585
    goto :goto_18

    .line 1586
    :pswitch_48
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1587
    .line 1588
    .line 1589
    move-result v16

    .line 1590
    goto :goto_18

    .line 1591
    :pswitch_49
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1592
    .line 1593
    .line 1594
    move-result v15

    .line 1595
    goto :goto_18

    .line 1596
    :pswitch_4a
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1597
    .line 1598
    .line 1599
    move-result v14

    .line 1600
    goto :goto_18

    .line 1601
    :pswitch_4b
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1602
    .line 1603
    .line 1604
    move-result v13

    .line 1605
    goto :goto_18

    .line 1606
    :pswitch_4c
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1607
    .line 1608
    .line 1609
    move-result v12

    .line 1610
    goto :goto_18

    .line 1611
    :pswitch_4d
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1612
    .line 1613
    .line 1614
    move-result v11

    .line 1615
    goto :goto_18

    .line 1616
    :pswitch_4e
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1617
    .line 1618
    .line 1619
    move-result v10

    .line 1620
    goto :goto_18

    .line 1621
    :pswitch_4f
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1622
    .line 1623
    .line 1624
    move-result v9

    .line 1625
    goto :goto_18

    .line 1626
    :pswitch_50
    sget-object v4, Lcom/google/android/gms/maps/model/CameraPosition;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1627
    .line 1628
    invoke-static {v0, v3, v4}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1629
    .line 1630
    .line 1631
    move-result-object v3

    .line 1632
    move-object v8, v3

    .line 1633
    check-cast v8, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 1634
    .line 1635
    goto/16 :goto_18

    .line 1636
    .line 1637
    :pswitch_51
    invoke-static {v0, v3}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1638
    .line 1639
    .line 1640
    move-result v2

    .line 1641
    goto/16 :goto_18

    .line 1642
    .line 1643
    :pswitch_52
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1644
    .line 1645
    .line 1646
    move-result v7

    .line 1647
    goto/16 :goto_18

    .line 1648
    .line 1649
    :pswitch_53
    invoke-static {v0, v3}, Ljp/xb;->m(Landroid/os/Parcel;I)B

    .line 1650
    .line 1651
    .line 1652
    move-result v6

    .line 1653
    goto/16 :goto_18

    .line 1654
    .line 1655
    :cond_38
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1656
    .line 1657
    .line 1658
    new-instance v0, Lcom/google/android/gms/maps/GoogleMapOptions;

    .line 1659
    .line 1660
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1661
    .line 1662
    .line 1663
    const/4 v1, -0x1

    .line 1664
    iput v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->f:I

    .line 1665
    .line 1666
    const/4 v1, 0x0

    .line 1667
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->q:Ljava/lang/Float;

    .line 1668
    .line 1669
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->r:Ljava/lang/Float;

    .line 1670
    .line 1671
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->s:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 1672
    .line 1673
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->u:Ljava/lang/Integer;

    .line 1674
    .line 1675
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->v:Ljava/lang/String;

    .line 1676
    .line 1677
    invoke-static {v6}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1678
    .line 1679
    .line 1680
    move-result-object v1

    .line 1681
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->d:Ljava/lang/Boolean;

    .line 1682
    .line 1683
    invoke-static {v7}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1684
    .line 1685
    .line 1686
    move-result-object v1

    .line 1687
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->e:Ljava/lang/Boolean;

    .line 1688
    .line 1689
    iput v2, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->f:I

    .line 1690
    .line 1691
    iput-object v8, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->g:Lcom/google/android/gms/maps/model/CameraPosition;

    .line 1692
    .line 1693
    invoke-static {v9}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1694
    .line 1695
    .line 1696
    move-result-object v1

    .line 1697
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->h:Ljava/lang/Boolean;

    .line 1698
    .line 1699
    invoke-static {v10}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1700
    .line 1701
    .line 1702
    move-result-object v1

    .line 1703
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->i:Ljava/lang/Boolean;

    .line 1704
    .line 1705
    invoke-static {v11}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1706
    .line 1707
    .line 1708
    move-result-object v1

    .line 1709
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->j:Ljava/lang/Boolean;

    .line 1710
    .line 1711
    invoke-static {v12}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1712
    .line 1713
    .line 1714
    move-result-object v1

    .line 1715
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->k:Ljava/lang/Boolean;

    .line 1716
    .line 1717
    invoke-static {v13}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1718
    .line 1719
    .line 1720
    move-result-object v1

    .line 1721
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->l:Ljava/lang/Boolean;

    .line 1722
    .line 1723
    invoke-static {v14}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1724
    .line 1725
    .line 1726
    move-result-object v1

    .line 1727
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->m:Ljava/lang/Boolean;

    .line 1728
    .line 1729
    invoke-static {v15}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1730
    .line 1731
    .line 1732
    move-result-object v1

    .line 1733
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->n:Ljava/lang/Boolean;

    .line 1734
    .line 1735
    invoke-static/range {v16 .. v16}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1736
    .line 1737
    .line 1738
    move-result-object v1

    .line 1739
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->o:Ljava/lang/Boolean;

    .line 1740
    .line 1741
    invoke-static/range {v17 .. v17}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1742
    .line 1743
    .line 1744
    move-result-object v1

    .line 1745
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->p:Ljava/lang/Boolean;

    .line 1746
    .line 1747
    move-object/from16 v3, v27

    .line 1748
    .line 1749
    iput-object v3, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->q:Ljava/lang/Float;

    .line 1750
    .line 1751
    move-object/from16 v3, v28

    .line 1752
    .line 1753
    iput-object v3, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->r:Ljava/lang/Float;

    .line 1754
    .line 1755
    move-object/from16 v3, v29

    .line 1756
    .line 1757
    iput-object v3, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->s:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 1758
    .line 1759
    invoke-static/range {v18 .. v18}, Lkp/y5;->g(B)Ljava/lang/Boolean;

    .line 1760
    .line 1761
    .line 1762
    move-result-object v1

    .line 1763
    iput-object v1, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->t:Ljava/lang/Boolean;

    .line 1764
    .line 1765
    move-object/from16 v3, v30

    .line 1766
    .line 1767
    iput-object v3, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->u:Ljava/lang/Integer;

    .line 1768
    .line 1769
    move-object/from16 v3, v31

    .line 1770
    .line 1771
    iput-object v3, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->v:Ljava/lang/String;

    .line 1772
    .line 1773
    iput v5, v0, Lcom/google/android/gms/maps/GoogleMapOptions;->w:I

    .line 1774
    .line 1775
    return-object v0

    .line 1776
    :pswitch_54
    move-object v0, v1

    .line 1777
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1778
    .line 1779
    .line 1780
    move-result v1

    .line 1781
    const/4 v2, 0x0

    .line 1782
    move v3, v2

    .line 1783
    :goto_19
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1784
    .line 1785
    .line 1786
    move-result v4

    .line 1787
    if-ge v4, v1, :cond_3b

    .line 1788
    .line 1789
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1790
    .line 1791
    .line 1792
    move-result v4

    .line 1793
    int-to-char v5, v4

    .line 1794
    const/4 v6, 0x1

    .line 1795
    if-eq v5, v6, :cond_3a

    .line 1796
    .line 1797
    const/4 v6, 0x2

    .line 1798
    if-eq v5, v6, :cond_39

    .line 1799
    .line 1800
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1801
    .line 1802
    .line 1803
    goto :goto_19

    .line 1804
    :cond_39
    invoke-static {v0, v4}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1805
    .line 1806
    .line 1807
    move-result v3

    .line 1808
    goto :goto_19

    .line 1809
    :cond_3a
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1810
    .line 1811
    .line 1812
    move-result v2

    .line 1813
    goto :goto_19

    .line 1814
    :cond_3b
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1815
    .line 1816
    .line 1817
    new-instance v0, Lqo/c;

    .line 1818
    .line 1819
    invoke-direct {v0, v2, v3}, Lqo/c;-><init>(IZ)V

    .line 1820
    .line 1821
    .line 1822
    return-object v0

    .line 1823
    :pswitch_55
    move-object v0, v1

    .line 1824
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1825
    .line 1826
    .line 1827
    move-result v1

    .line 1828
    const/4 v2, 0x0

    .line 1829
    :goto_1a
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1830
    .line 1831
    .line 1832
    move-result v3

    .line 1833
    if-ge v3, v1, :cond_3d

    .line 1834
    .line 1835
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1836
    .line 1837
    .line 1838
    move-result v3

    .line 1839
    int-to-char v4, v3

    .line 1840
    const/4 v5, 0x1

    .line 1841
    if-eq v4, v5, :cond_3c

    .line 1842
    .line 1843
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1844
    .line 1845
    .line 1846
    goto :goto_1a

    .line 1847
    :cond_3c
    sget-object v2, Landroid/app/PendingIntent;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1848
    .line 1849
    invoke-static {v0, v3, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1850
    .line 1851
    .line 1852
    move-result-object v2

    .line 1853
    check-cast v2, Landroid/app/PendingIntent;

    .line 1854
    .line 1855
    goto :goto_1a

    .line 1856
    :cond_3d
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1857
    .line 1858
    .line 1859
    new-instance v0, Lqo/b;

    .line 1860
    .line 1861
    invoke-direct {v0, v2}, Lqo/b;-><init>(Landroid/app/PendingIntent;)V

    .line 1862
    .line 1863
    .line 1864
    return-object v0

    .line 1865
    :pswitch_56
    move-object v0, v1

    .line 1866
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1867
    .line 1868
    .line 1869
    move-result v1

    .line 1870
    const/4 v2, 0x0

    .line 1871
    move v3, v2

    .line 1872
    :goto_1b
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1873
    .line 1874
    .line 1875
    move-result v4

    .line 1876
    if-ge v4, v1, :cond_40

    .line 1877
    .line 1878
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1879
    .line 1880
    .line 1881
    move-result v4

    .line 1882
    int-to-char v5, v4

    .line 1883
    const/4 v6, 0x1

    .line 1884
    if-eq v5, v6, :cond_3f

    .line 1885
    .line 1886
    const/4 v6, 0x2

    .line 1887
    if-eq v5, v6, :cond_3e

    .line 1888
    .line 1889
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1890
    .line 1891
    .line 1892
    goto :goto_1b

    .line 1893
    :cond_3e
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1894
    .line 1895
    .line 1896
    move-result v3

    .line 1897
    goto :goto_1b

    .line 1898
    :cond_3f
    invoke-static {v0, v4}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1899
    .line 1900
    .line 1901
    move-result v2

    .line 1902
    goto :goto_1b

    .line 1903
    :cond_40
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1904
    .line 1905
    .line 1906
    new-instance v0, Lqo/a;

    .line 1907
    .line 1908
    invoke-direct {v0, v3, v2}, Lqo/a;-><init>(IZ)V

    .line 1909
    .line 1910
    .line 1911
    return-object v0

    .line 1912
    :pswitch_57
    move-object v0, v1

    .line 1913
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1914
    .line 1915
    .line 1916
    move-result v1

    .line 1917
    const/4 v2, 0x0

    .line 1918
    const/4 v3, 0x0

    .line 1919
    move v4, v3

    .line 1920
    move-object v3, v2

    .line 1921
    :goto_1c
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1922
    .line 1923
    .line 1924
    move-result v5

    .line 1925
    if-ge v5, v1, :cond_44

    .line 1926
    .line 1927
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1928
    .line 1929
    .line 1930
    move-result v5

    .line 1931
    int-to-char v6, v5

    .line 1932
    const/4 v7, 0x1

    .line 1933
    if-eq v6, v7, :cond_43

    .line 1934
    .line 1935
    const/4 v7, 0x2

    .line 1936
    if-eq v6, v7, :cond_42

    .line 1937
    .line 1938
    const/4 v7, 0x4

    .line 1939
    if-eq v6, v7, :cond_41

    .line 1940
    .line 1941
    invoke-static {v0, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1942
    .line 1943
    .line 1944
    goto :goto_1c

    .line 1945
    :cond_41
    invoke-static {v0, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1946
    .line 1947
    .line 1948
    move-result-object v3

    .line 1949
    goto :goto_1c

    .line 1950
    :cond_42
    invoke-static {v0, v5}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1951
    .line 1952
    .line 1953
    move-result v4

    .line 1954
    goto :goto_1c

    .line 1955
    :cond_43
    sget-object v2, Lgp/k;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1956
    .line 1957
    invoke-static {v0, v5, v2}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1958
    .line 1959
    .line 1960
    move-result-object v2

    .line 1961
    goto :goto_1c

    .line 1962
    :cond_44
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1963
    .line 1964
    .line 1965
    new-instance v0, Lpp/c;

    .line 1966
    .line 1967
    invoke-direct {v0, v4, v3, v2}, Lpp/c;-><init>(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 1968
    .line 1969
    .line 1970
    return-object v0

    .line 1971
    :pswitch_58
    move-object v0, v1

    .line 1972
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1973
    .line 1974
    .line 1975
    move-result v1

    .line 1976
    const-wide/16 v2, -0x1

    .line 1977
    .line 1978
    const/4 v4, 0x1

    .line 1979
    move-wide v6, v2

    .line 1980
    move-wide v10, v6

    .line 1981
    move v8, v4

    .line 1982
    move v9, v8

    .line 1983
    :goto_1d
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1984
    .line 1985
    .line 1986
    move-result v2

    .line 1987
    if-ge v2, v1, :cond_49

    .line 1988
    .line 1989
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1990
    .line 1991
    .line 1992
    move-result v2

    .line 1993
    int-to-char v3, v2

    .line 1994
    if-eq v3, v4, :cond_48

    .line 1995
    .line 1996
    const/4 v5, 0x2

    .line 1997
    if-eq v3, v5, :cond_47

    .line 1998
    .line 1999
    const/4 v5, 0x3

    .line 2000
    if-eq v3, v5, :cond_46

    .line 2001
    .line 2002
    const/4 v5, 0x4

    .line 2003
    if-eq v3, v5, :cond_45

    .line 2004
    .line 2005
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 2006
    .line 2007
    .line 2008
    goto :goto_1d

    .line 2009
    :cond_45
    invoke-static {v0, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 2010
    .line 2011
    .line 2012
    move-result-wide v2

    .line 2013
    move-wide v10, v2

    .line 2014
    goto :goto_1d

    .line 2015
    :cond_46
    invoke-static {v0, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 2016
    .line 2017
    .line 2018
    move-result-wide v2

    .line 2019
    move-wide v6, v2

    .line 2020
    goto :goto_1d

    .line 2021
    :cond_47
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 2022
    .line 2023
    .line 2024
    move-result v9

    .line 2025
    goto :goto_1d

    .line 2026
    :cond_48
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 2027
    .line 2028
    .line 2029
    move-result v8

    .line 2030
    goto :goto_1d

    .line 2031
    :cond_49
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 2032
    .line 2033
    .line 2034
    new-instance v5, Lpp/j;

    .line 2035
    .line 2036
    invoke-direct/range {v5 .. v11}, Lpp/j;-><init>(JIIJ)V

    .line 2037
    .line 2038
    .line 2039
    return-object v5

    .line 2040
    :pswitch_59
    move-object v0, v1

    .line 2041
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 2042
    .line 2043
    .line 2044
    move-result v1

    .line 2045
    const/4 v2, 0x0

    .line 2046
    move v4, v2

    .line 2047
    move v5, v4

    .line 2048
    move v6, v5

    .line 2049
    move v7, v6

    .line 2050
    move v8, v7

    .line 2051
    move v9, v8

    .line 2052
    :goto_1e
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 2053
    .line 2054
    .line 2055
    move-result v2

    .line 2056
    if-ge v2, v1, :cond_4a

    .line 2057
    .line 2058
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2059
    .line 2060
    .line 2061
    move-result v2

    .line 2062
    int-to-char v3, v2

    .line 2063
    packed-switch v3, :pswitch_data_5

    .line 2064
    .line 2065
    .line 2066
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 2067
    .line 2068
    .line 2069
    goto :goto_1e

    .line 2070
    :pswitch_5a
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 2071
    .line 2072
    .line 2073
    move-result v9

    .line 2074
    goto :goto_1e

    .line 2075
    :pswitch_5b
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 2076
    .line 2077
    .line 2078
    move-result v8

    .line 2079
    goto :goto_1e

    .line 2080
    :pswitch_5c
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 2081
    .line 2082
    .line 2083
    move-result v7

    .line 2084
    goto :goto_1e

    .line 2085
    :pswitch_5d
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 2086
    .line 2087
    .line 2088
    move-result v6

    .line 2089
    goto :goto_1e

    .line 2090
    :pswitch_5e
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 2091
    .line 2092
    .line 2093
    move-result v5

    .line 2094
    goto :goto_1e

    .line 2095
    :pswitch_5f
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 2096
    .line 2097
    .line 2098
    move-result v4

    .line 2099
    goto :goto_1e

    .line 2100
    :cond_4a
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 2101
    .line 2102
    .line 2103
    new-instance v3, Lpp/g;

    .line 2104
    .line 2105
    invoke-direct/range {v3 .. v9}, Lpp/g;-><init>(ZZZZZZ)V

    .line 2106
    .line 2107
    .line 2108
    return-object v3

    .line 2109
    :pswitch_60
    move-object v0, v1

    .line 2110
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 2111
    .line 2112
    .line 2113
    move-result v1

    .line 2114
    const/4 v2, 0x0

    .line 2115
    move-object v3, v2

    .line 2116
    :goto_1f
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 2117
    .line 2118
    .line 2119
    move-result v4

    .line 2120
    if-ge v4, v1, :cond_4d

    .line 2121
    .line 2122
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2123
    .line 2124
    .line 2125
    move-result v4

    .line 2126
    int-to-char v5, v4

    .line 2127
    const/4 v6, 0x1

    .line 2128
    if-eq v5, v6, :cond_4c

    .line 2129
    .line 2130
    const/4 v6, 0x2

    .line 2131
    if-eq v5, v6, :cond_4b

    .line 2132
    .line 2133
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 2134
    .line 2135
    .line 2136
    goto :goto_1f

    .line 2137
    :cond_4b
    sget-object v3, Lpp/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 2138
    .line 2139
    invoke-static {v0, v4, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 2140
    .line 2141
    .line 2142
    move-result-object v3

    .line 2143
    check-cast v3, Lpp/g;

    .line 2144
    .line 2145
    goto :goto_1f

    .line 2146
    :cond_4c
    sget-object v2, Lcom/google/android/gms/common/api/Status;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 2147
    .line 2148
    invoke-static {v0, v4, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 2149
    .line 2150
    .line 2151
    move-result-object v2

    .line 2152
    check-cast v2, Lcom/google/android/gms/common/api/Status;

    .line 2153
    .line 2154
    goto :goto_1f

    .line 2155
    :cond_4d
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 2156
    .line 2157
    .line 2158
    new-instance v0, Lpp/f;

    .line 2159
    .line 2160
    invoke-direct {v0, v2, v3}, Lpp/f;-><init>(Lcom/google/android/gms/common/api/Status;Lpp/g;)V

    .line 2161
    .line 2162
    .line 2163
    return-object v0

    .line 2164
    nop

    .line 2165
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_60
        :pswitch_59
        :pswitch_58
        :pswitch_57
        :pswitch_56
        :pswitch_55
        :pswitch_54
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 2166
    .line 2167
    .line 2168
    .line 2169
    .line 2170
    .line 2171
    .line 2172
    .line 2173
    .line 2174
    .line 2175
    .line 2176
    .line 2177
    .line 2178
    .line 2179
    .line 2180
    .line 2181
    .line 2182
    .line 2183
    .line 2184
    .line 2185
    .line 2186
    .line 2187
    .line 2188
    .line 2189
    .line 2190
    .line 2191
    .line 2192
    .line 2193
    .line 2194
    .line 2195
    .line 2196
    .line 2197
    .line 2198
    .line 2199
    .line 2200
    .line 2201
    .line 2202
    .line 2203
    .line 2204
    .line 2205
    .line 2206
    .line 2207
    .line 2208
    .line 2209
    .line 2210
    .line 2211
    .line 2212
    .line 2213
    .line 2214
    .line 2215
    .line 2216
    .line 2217
    .line 2218
    .line 2219
    .line 2220
    .line 2221
    .line 2222
    .line 2223
    .line 2224
    .line 2225
    .line 2226
    .line 2227
    :pswitch_data_1
    .packed-switch 0x2
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
    .end packed-switch

    .line 2228
    .line 2229
    .line 2230
    .line 2231
    .line 2232
    .line 2233
    .line 2234
    .line 2235
    .line 2236
    .line 2237
    .line 2238
    .line 2239
    .line 2240
    .line 2241
    .line 2242
    .line 2243
    .line 2244
    .line 2245
    .line 2246
    .line 2247
    .line 2248
    .line 2249
    .line 2250
    .line 2251
    .line 2252
    .line 2253
    .line 2254
    .line 2255
    :pswitch_data_2
    .packed-switch 0x2
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
        :pswitch_15
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
    .end packed-switch

    .line 2256
    .line 2257
    .line 2258
    .line 2259
    .line 2260
    .line 2261
    .line 2262
    .line 2263
    .line 2264
    .line 2265
    .line 2266
    .line 2267
    .line 2268
    .line 2269
    .line 2270
    .line 2271
    .line 2272
    .line 2273
    .line 2274
    .line 2275
    .line 2276
    .line 2277
    .line 2278
    .line 2279
    .line 2280
    .line 2281
    .line 2282
    .line 2283
    .line 2284
    .line 2285
    .line 2286
    .line 2287
    .line 2288
    .line 2289
    .line 2290
    .line 2291
    .line 2292
    .line 2293
    .line 2294
    .line 2295
    .line 2296
    .line 2297
    .line 2298
    .line 2299
    :pswitch_data_3
    .packed-switch 0x2
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
    .end packed-switch

    .line 2300
    .line 2301
    .line 2302
    .line 2303
    .line 2304
    .line 2305
    .line 2306
    .line 2307
    .line 2308
    .line 2309
    .line 2310
    .line 2311
    .line 2312
    .line 2313
    .line 2314
    .line 2315
    .line 2316
    .line 2317
    .line 2318
    .line 2319
    .line 2320
    .line 2321
    :pswitch_data_4
    .packed-switch 0x2
        :pswitch_53
        :pswitch_52
        :pswitch_51
        :pswitch_50
        :pswitch_4f
        :pswitch_4e
        :pswitch_4d
        :pswitch_4c
        :pswitch_4b
        :pswitch_4a
        :pswitch_49
        :pswitch_3f
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_45
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_3f
        :pswitch_40
    .end packed-switch

    .line 2322
    .line 2323
    .line 2324
    .line 2325
    .line 2326
    .line 2327
    .line 2328
    .line 2329
    .line 2330
    .line 2331
    .line 2332
    .line 2333
    .line 2334
    .line 2335
    .line 2336
    .line 2337
    .line 2338
    .line 2339
    .line 2340
    .line 2341
    .line 2342
    .line 2343
    .line 2344
    .line 2345
    .line 2346
    .line 2347
    .line 2348
    .line 2349
    .line 2350
    .line 2351
    .line 2352
    .line 2353
    .line 2354
    .line 2355
    .line 2356
    .line 2357
    .line 2358
    .line 2359
    .line 2360
    .line 2361
    .line 2362
    .line 2363
    .line 2364
    .line 2365
    .line 2366
    .line 2367
    .line 2368
    .line 2369
    :pswitch_data_5
    .packed-switch 0x1
        :pswitch_5f
        :pswitch_5e
        :pswitch_5d
        :pswitch_5c
        :pswitch_5b
        :pswitch_5a
    .end packed-switch
.end method

.method public final newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lpp/h;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Ltt/c;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Ltc/q;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Ltc/k;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Ltc/e;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    new-array p0, p1, [Ltb/w;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    new-array p0, p1, [Lsp/s;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    new-array p0, p1, [Lsp/r;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    new-array p0, p1, [Lsp/n;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    new-array p0, p1, [Lsp/m;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    new-array p0, p1, [Lsp/l;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_9
    new-array p0, p1, [Lsp/j;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_a
    new-array p0, p1, [Lcom/google/android/gms/maps/model/LatLng;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_b
    new-array p0, p1, [Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_c
    new-array p0, p1, [Lsp/f;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_d
    new-array p0, p1, [Lsp/d;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_e
    new-array p0, p1, [Lsp/v;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_f
    new-array p0, p1, [Lsp/u;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_10
    new-array p0, p1, [Lsp/t;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_11
    new-array p0, p1, [Lcom/google/android/gms/maps/model/CameraPosition;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_12
    new-array p0, p1, [Lrl/a;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_13
    new-array p0, p1, [Lrd/d;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_14
    new-array p0, p1, [Lrd/a;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_15
    new-array p0, p1, [Lcom/google/android/gms/maps/GoogleMapOptions;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_16
    new-array p0, p1, [Lqo/c;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_17
    new-array p0, p1, [Lqo/b;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_18
    new-array p0, p1, [Lqo/a;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_19
    new-array p0, p1, [Lpp/c;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_1a
    new-array p0, p1, [Lpp/j;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_1b
    new-array p0, p1, [Lpp/g;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_1c
    new-array p0, p1, [Lpp/f;

    .line 94
    .line 95
    return-object p0

    .line 96
    nop

    .line 97
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

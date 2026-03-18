.class public final Lgl/c;
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
    iput p1, p0, Lgl/c;->a:I

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
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v0, v0, Lgl/c;->a:I

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    const-string v0, "parcel"

    .line 11
    .line 12
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Lkg/d0;

    .line 16
    .line 17
    sget-object v2, Lkg/c;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 18
    .line 19
    invoke-interface {v2, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lkg/c;

    .line 24
    .line 25
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v3, 0x0

    .line 34
    :goto_0
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-nez v4, :cond_1

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    sget-object v4, Lkg/l;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 43
    .line 44
    invoke-interface {v4, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    :goto_1
    check-cast v1, Lkg/l;

    .line 49
    .line 50
    invoke-direct {v0, v2, v3, v1}, Lkg/d0;-><init>(Lkg/c;ZLkg/l;)V

    .line 51
    .line 52
    .line 53
    return-object v0

    .line 54
    :pswitch_0
    const-string v0, "parcel"

    .line 55
    .line 56
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Lkg/x;

    .line 60
    .line 61
    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-direct {v0, v1}, Lkg/x;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    return-object v0

    .line 69
    :pswitch_1
    const-string v0, "parcel"

    .line 70
    .line 71
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    move-object v0, v1

    .line 75
    new-instance v1, Lkg/r;

    .line 76
    .line 77
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    const/4 v5, 0x0

    .line 90
    const/4 v6, 0x1

    .line 91
    if-eqz v4, :cond_2

    .line 92
    .line 93
    move v4, v5

    .line 94
    move v5, v6

    .line 95
    goto :goto_2

    .line 96
    :cond_2
    move v4, v5

    .line 97
    :goto_2
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 98
    .line 99
    .line 100
    move-result v7

    .line 101
    if-eqz v7, :cond_3

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_3
    move v6, v4

    .line 105
    :goto_3
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    invoke-direct/range {v1 .. v6}, Lkg/r;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V

    .line 110
    .line 111
    .line 112
    return-object v1

    .line 113
    :pswitch_2
    move-object v0, v1

    .line 114
    const-string v1, "parcel"

    .line 115
    .line 116
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    new-instance v1, Lkg/o;

    .line 120
    .line 121
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-direct {v1, v2, v0}, Lkg/o;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    return-object v1

    .line 133
    :pswitch_3
    move-object v0, v1

    .line 134
    const-string v1, "parcel"

    .line 135
    .line 136
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    new-instance v1, Lkg/l;

    .line 140
    .line 141
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v2

    .line 145
    sget-object v3, Lkg/p0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 146
    .line 147
    invoke-interface {v3, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    check-cast v3, Lkg/p0;

    .line 152
    .line 153
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    invoke-direct {v1, v2, v3, v4, v0}, Lkg/l;-><init>(Ljava/lang/String;Lkg/p0;Ljava/lang/String;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    return-object v1

    .line 165
    :pswitch_4
    move-object v0, v1

    .line 166
    const-string v1, "parcel"

    .line 167
    .line 168
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    new-instance v2, Ljava/util/ArrayList;

    .line 176
    .line 177
    invoke-direct {v2, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 178
    .line 179
    .line 180
    const/4 v3, 0x0

    .line 181
    move v4, v3

    .line 182
    :goto_4
    const/4 v5, 0x1

    .line 183
    if-eq v4, v1, :cond_4

    .line 184
    .line 185
    sget-object v6, Lkg/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 186
    .line 187
    invoke-static {v6, v0, v2, v4, v5}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 188
    .line 189
    .line 190
    move-result v4

    .line 191
    goto :goto_4

    .line 192
    :cond_4
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    if-eqz v4, :cond_5

    .line 201
    .line 202
    move v3, v5

    .line 203
    :cond_5
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    new-instance v4, Lkg/i;

    .line 208
    .line 209
    invoke-direct {v4, v1, v0, v2, v3}, Lkg/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Z)V

    .line 210
    .line 211
    .line 212
    return-object v4

    .line 213
    :pswitch_5
    move-object v0, v1

    .line 214
    const-string v1, "parcel"

    .line 215
    .line 216
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    new-instance v1, Lkg/f;

    .line 220
    .line 221
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v2

    .line 225
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v3

    .line 229
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v4

    .line 233
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    invoke-direct {v1, v2, v3, v4, v0}, Lkg/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    return-object v1

    .line 241
    :pswitch_6
    move-object v0, v1

    .line 242
    const-string v1, "parcel"

    .line 243
    .line 244
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    new-instance v2, Lkg/c;

    .line 248
    .line 249
    sget-object v1, Lkg/p0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 250
    .line 251
    invoke-interface {v1, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v1

    .line 255
    move-object v3, v1

    .line 256
    check-cast v3, Lkg/p0;

    .line 257
    .line 258
    sget-object v1, Lkg/r;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 259
    .line 260
    invoke-interface {v1, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v1

    .line 264
    move-object v4, v1

    .line 265
    check-cast v4, Lkg/r;

    .line 266
    .line 267
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 268
    .line 269
    .line 270
    move-result v1

    .line 271
    const/4 v5, 0x0

    .line 272
    const/4 v6, 0x1

    .line 273
    if-eqz v1, :cond_6

    .line 274
    .line 275
    move v1, v5

    .line 276
    move v5, v6

    .line 277
    move v7, v5

    .line 278
    goto :goto_5

    .line 279
    :cond_6
    move v1, v5

    .line 280
    move v7, v6

    .line 281
    :goto_5
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v6

    .line 285
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 286
    .line 287
    .line 288
    move-result v8

    .line 289
    if-nez v8, :cond_7

    .line 290
    .line 291
    const/4 v0, 0x0

    .line 292
    :goto_6
    move-object v7, v0

    .line 293
    goto :goto_7

    .line 294
    :cond_7
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 295
    .line 296
    .line 297
    move-result v0

    .line 298
    if-eqz v0, :cond_8

    .line 299
    .line 300
    move v1, v7

    .line 301
    :cond_8
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 302
    .line 303
    .line 304
    move-result-object v0

    .line 305
    goto :goto_6

    .line 306
    :goto_7
    invoke-direct/range {v2 .. v7}, Lkg/c;-><init>(Lkg/p0;Lkg/r;ZLjava/lang/String;Ljava/lang/Boolean;)V

    .line 307
    .line 308
    .line 309
    return-object v2

    .line 310
    :pswitch_7
    move-object v0, v1

    .line 311
    new-instance v1, Lka/c1;

    .line 312
    .line 313
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 314
    .line 315
    .line 316
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 317
    .line 318
    .line 319
    move-result v2

    .line 320
    iput v2, v1, Lka/c1;->d:I

    .line 321
    .line 322
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 323
    .line 324
    .line 325
    move-result v2

    .line 326
    iput v2, v1, Lka/c1;->e:I

    .line 327
    .line 328
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 329
    .line 330
    .line 331
    move-result v2

    .line 332
    iput v2, v1, Lka/c1;->f:I

    .line 333
    .line 334
    if-lez v2, :cond_9

    .line 335
    .line 336
    new-array v2, v2, [I

    .line 337
    .line 338
    iput-object v2, v1, Lka/c1;->g:[I

    .line 339
    .line 340
    invoke-virtual {v0, v2}, Landroid/os/Parcel;->readIntArray([I)V

    .line 341
    .line 342
    .line 343
    :cond_9
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 344
    .line 345
    .line 346
    move-result v2

    .line 347
    iput v2, v1, Lka/c1;->h:I

    .line 348
    .line 349
    if-lez v2, :cond_a

    .line 350
    .line 351
    new-array v2, v2, [I

    .line 352
    .line 353
    iput-object v2, v1, Lka/c1;->i:[I

    .line 354
    .line 355
    invoke-virtual {v0, v2}, Landroid/os/Parcel;->readIntArray([I)V

    .line 356
    .line 357
    .line 358
    :cond_a
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 359
    .line 360
    .line 361
    move-result v2

    .line 362
    const/4 v3, 0x0

    .line 363
    const/4 v4, 0x1

    .line 364
    if-ne v2, v4, :cond_b

    .line 365
    .line 366
    move v2, v4

    .line 367
    goto :goto_8

    .line 368
    :cond_b
    move v2, v3

    .line 369
    :goto_8
    iput-boolean v2, v1, Lka/c1;->k:Z

    .line 370
    .line 371
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 372
    .line 373
    .line 374
    move-result v2

    .line 375
    if-ne v2, v4, :cond_c

    .line 376
    .line 377
    move v2, v4

    .line 378
    goto :goto_9

    .line 379
    :cond_c
    move v2, v3

    .line 380
    :goto_9
    iput-boolean v2, v1, Lka/c1;->l:Z

    .line 381
    .line 382
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 383
    .line 384
    .line 385
    move-result v2

    .line 386
    if-ne v2, v4, :cond_d

    .line 387
    .line 388
    move v3, v4

    .line 389
    :cond_d
    iput-boolean v3, v1, Lka/c1;->m:Z

    .line 390
    .line 391
    const-class v2, Lka/b1;

    .line 392
    .line 393
    invoke-virtual {v2}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 394
    .line 395
    .line 396
    move-result-object v2

    .line 397
    invoke-virtual {v0, v2}, Landroid/os/Parcel;->readArrayList(Ljava/lang/ClassLoader;)Ljava/util/ArrayList;

    .line 398
    .line 399
    .line 400
    move-result-object v0

    .line 401
    iput-object v0, v1, Lka/c1;->j:Ljava/util/ArrayList;

    .line 402
    .line 403
    return-object v1

    .line 404
    :pswitch_8
    move-object v0, v1

    .line 405
    new-instance v1, Lka/b1;

    .line 406
    .line 407
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 408
    .line 409
    .line 410
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 411
    .line 412
    .line 413
    move-result v2

    .line 414
    iput v2, v1, Lka/b1;->d:I

    .line 415
    .line 416
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 417
    .line 418
    .line 419
    move-result v2

    .line 420
    iput v2, v1, Lka/b1;->e:I

    .line 421
    .line 422
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 423
    .line 424
    .line 425
    move-result v2

    .line 426
    const/4 v3, 0x1

    .line 427
    if-ne v2, v3, :cond_e

    .line 428
    .line 429
    goto :goto_a

    .line 430
    :cond_e
    const/4 v3, 0x0

    .line 431
    :goto_a
    iput-boolean v3, v1, Lka/b1;->g:Z

    .line 432
    .line 433
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 434
    .line 435
    .line 436
    move-result v2

    .line 437
    if-lez v2, :cond_f

    .line 438
    .line 439
    new-array v2, v2, [I

    .line 440
    .line 441
    iput-object v2, v1, Lka/b1;->f:[I

    .line 442
    .line 443
    invoke-virtual {v0, v2}, Landroid/os/Parcel;->readIntArray([I)V

    .line 444
    .line 445
    .line 446
    :cond_f
    return-object v1

    .line 447
    :pswitch_9
    move-object v0, v1

    .line 448
    new-instance v1, Lka/r;

    .line 449
    .line 450
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 451
    .line 452
    .line 453
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 454
    .line 455
    .line 456
    move-result v2

    .line 457
    iput v2, v1, Lka/r;->d:I

    .line 458
    .line 459
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 460
    .line 461
    .line 462
    move-result v2

    .line 463
    iput v2, v1, Lka/r;->e:I

    .line 464
    .line 465
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 466
    .line 467
    .line 468
    move-result v0

    .line 469
    const/4 v2, 0x1

    .line 470
    if-ne v0, v2, :cond_10

    .line 471
    .line 472
    goto :goto_b

    .line 473
    :cond_10
    const/4 v2, 0x0

    .line 474
    :goto_b
    iput-boolean v2, v1, Lka/r;->f:Z

    .line 475
    .line 476
    return-object v1

    .line 477
    :pswitch_a
    move-object v0, v1

    .line 478
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 479
    .line 480
    .line 481
    move-result v1

    .line 482
    const/4 v2, 0x0

    .line 483
    const/4 v3, 0x0

    .line 484
    move v4, v2

    .line 485
    move-object v5, v3

    .line 486
    move v3, v4

    .line 487
    :goto_c
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 488
    .line 489
    .line 490
    move-result v6

    .line 491
    if-ge v6, v1, :cond_15

    .line 492
    .line 493
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 494
    .line 495
    .line 496
    move-result v6

    .line 497
    int-to-char v7, v6

    .line 498
    const/4 v8, 0x1

    .line 499
    if-eq v7, v8, :cond_14

    .line 500
    .line 501
    const/4 v8, 0x2

    .line 502
    if-eq v7, v8, :cond_13

    .line 503
    .line 504
    const/4 v8, 0x3

    .line 505
    if-eq v7, v8, :cond_12

    .line 506
    .line 507
    const/4 v8, 0x4

    .line 508
    if-eq v7, v8, :cond_11

    .line 509
    .line 510
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 511
    .line 512
    .line 513
    goto :goto_c

    .line 514
    :cond_11
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 515
    .line 516
    .line 517
    move-result v4

    .line 518
    goto :goto_c

    .line 519
    :cond_12
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 520
    .line 521
    .line 522
    move-result v3

    .line 523
    goto :goto_c

    .line 524
    :cond_13
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 525
    .line 526
    .line 527
    move-result-object v5

    .line 528
    goto :goto_c

    .line 529
    :cond_14
    invoke-static {v0, v6}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 530
    .line 531
    .line 532
    move-result v2

    .line 533
    goto :goto_c

    .line 534
    :cond_15
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 535
    .line 536
    .line 537
    new-instance v0, Ljo/r;

    .line 538
    .line 539
    invoke-direct {v0, v5, v3, v4, v2}, Ljo/r;-><init>(Ljava/lang/String;IIZ)V

    .line 540
    .line 541
    .line 542
    return-object v0

    .line 543
    :pswitch_b
    move-object v0, v1

    .line 544
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 545
    .line 546
    .line 547
    move-result v1

    .line 548
    const-wide/16 v2, -0x1

    .line 549
    .line 550
    const/4 v4, 0x0

    .line 551
    const/4 v5, 0x0

    .line 552
    :goto_d
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 553
    .line 554
    .line 555
    move-result v6

    .line 556
    if-ge v6, v1, :cond_19

    .line 557
    .line 558
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 559
    .line 560
    .line 561
    move-result v6

    .line 562
    int-to-char v7, v6

    .line 563
    const/4 v8, 0x1

    .line 564
    if-eq v7, v8, :cond_18

    .line 565
    .line 566
    const/4 v8, 0x2

    .line 567
    if-eq v7, v8, :cond_17

    .line 568
    .line 569
    const/4 v8, 0x3

    .line 570
    if-eq v7, v8, :cond_16

    .line 571
    .line 572
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 573
    .line 574
    .line 575
    goto :goto_d

    .line 576
    :cond_16
    invoke-static {v0, v6}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 577
    .line 578
    .line 579
    move-result-wide v2

    .line 580
    goto :goto_d

    .line 581
    :cond_17
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 582
    .line 583
    .line 584
    move-result v4

    .line 585
    goto :goto_d

    .line 586
    :cond_18
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 587
    .line 588
    .line 589
    move-result-object v5

    .line 590
    goto :goto_d

    .line 591
    :cond_19
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 592
    .line 593
    .line 594
    new-instance v0, Ljo/d;

    .line 595
    .line 596
    invoke-direct {v0, v2, v3, v5, v4}, Ljo/d;-><init>(JLjava/lang/String;I)V

    .line 597
    .line 598
    .line 599
    return-object v0

    .line 600
    :pswitch_c
    move-object v0, v1

    .line 601
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 602
    .line 603
    .line 604
    move-result v1

    .line 605
    const/4 v2, 0x0

    .line 606
    const/4 v3, 0x0

    .line 607
    move v4, v3

    .line 608
    move v5, v4

    .line 609
    move-object v3, v2

    .line 610
    :goto_e
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 611
    .line 612
    .line 613
    move-result v6

    .line 614
    if-ge v6, v1, :cond_1e

    .line 615
    .line 616
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 617
    .line 618
    .line 619
    move-result v6

    .line 620
    int-to-char v7, v6

    .line 621
    const/4 v8, 0x1

    .line 622
    if-eq v7, v8, :cond_1d

    .line 623
    .line 624
    const/4 v8, 0x2

    .line 625
    if-eq v7, v8, :cond_1c

    .line 626
    .line 627
    const/4 v8, 0x3

    .line 628
    if-eq v7, v8, :cond_1b

    .line 629
    .line 630
    const/4 v8, 0x4

    .line 631
    if-eq v7, v8, :cond_1a

    .line 632
    .line 633
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 634
    .line 635
    .line 636
    goto :goto_e

    .line 637
    :cond_1a
    invoke-static {v0, v6}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 638
    .line 639
    .line 640
    move-result-object v3

    .line 641
    goto :goto_e

    .line 642
    :cond_1b
    sget-object v2, Landroid/app/PendingIntent;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 643
    .line 644
    invoke-static {v0, v6, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 645
    .line 646
    .line 647
    move-result-object v2

    .line 648
    check-cast v2, Landroid/app/PendingIntent;

    .line 649
    .line 650
    goto :goto_e

    .line 651
    :cond_1c
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 652
    .line 653
    .line 654
    move-result v5

    .line 655
    goto :goto_e

    .line 656
    :cond_1d
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 657
    .line 658
    .line 659
    move-result v4

    .line 660
    goto :goto_e

    .line 661
    :cond_1e
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 662
    .line 663
    .line 664
    new-instance v0, Ljo/b;

    .line 665
    .line 666
    invoke-direct {v0, v4, v5, v2, v3}, Ljo/b;-><init>(IILandroid/app/PendingIntent;Ljava/lang/String;)V

    .line 667
    .line 668
    .line 669
    return-object v0

    .line 670
    :pswitch_d
    move-object v0, v1

    .line 671
    const-string v1, "parcel"

    .line 672
    .line 673
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    new-instance v1, Lje/z;

    .line 677
    .line 678
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 679
    .line 680
    .line 681
    move-result-object v0

    .line 682
    invoke-static {v0}, Lje/y;->valueOf(Ljava/lang/String;)Lje/y;

    .line 683
    .line 684
    .line 685
    move-result-object v0

    .line 686
    invoke-direct {v1, v0}, Lje/z;-><init>(Lje/y;)V

    .line 687
    .line 688
    .line 689
    return-object v1

    .line 690
    :pswitch_e
    move-object v0, v1

    .line 691
    const-string v1, "parcel"

    .line 692
    .line 693
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 694
    .line 695
    .line 696
    new-instance v1, Lhc/c;

    .line 697
    .line 698
    const-class v2, Lhc/c;

    .line 699
    .line 700
    invoke-virtual {v2}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 701
    .line 702
    .line 703
    move-result-object v2

    .line 704
    invoke-virtual {v0, v2}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 705
    .line 706
    .line 707
    move-result-object v2

    .line 708
    check-cast v2, Lgl/h;

    .line 709
    .line 710
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 711
    .line 712
    .line 713
    move-result-object v0

    .line 714
    invoke-static {v0}, Lhc/b;->valueOf(Ljava/lang/String;)Lhc/b;

    .line 715
    .line 716
    .line 717
    move-result-object v0

    .line 718
    invoke-direct {v1, v2, v0}, Lhc/c;-><init>(Lgl/h;Lhc/b;)V

    .line 719
    .line 720
    .line 721
    return-object v1

    .line 722
    :pswitch_f
    move-object v0, v1

    .line 723
    const-string v1, "parcel"

    .line 724
    .line 725
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 726
    .line 727
    .line 728
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 729
    .line 730
    .line 731
    move-result v1

    .line 732
    new-instance v2, Ljava/util/ArrayList;

    .line 733
    .line 734
    invoke-direct {v2, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 735
    .line 736
    .line 737
    const/4 v3, 0x0

    .line 738
    :goto_f
    if-eq v3, v1, :cond_1f

    .line 739
    .line 740
    sget-object v4, Lhc/c;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 741
    .line 742
    const/4 v5, 0x1

    .line 743
    invoke-static {v4, v0, v2, v3, v5}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 744
    .line 745
    .line 746
    move-result v3

    .line 747
    goto :goto_f

    .line 748
    :cond_1f
    new-instance v0, Lhc/a;

    .line 749
    .line 750
    invoke-direct {v0, v2}, Lhc/a;-><init>(Ljava/util/ArrayList;)V

    .line 751
    .line 752
    .line 753
    return-object v0

    .line 754
    :pswitch_10
    move-object v0, v1

    .line 755
    new-instance v1, Lh6/g;

    .line 756
    .line 757
    invoke-direct {v1, v0}, Landroid/view/View$BaseSavedState;-><init>(Landroid/os/Parcel;)V

    .line 758
    .line 759
    .line 760
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 761
    .line 762
    .line 763
    move-result v0

    .line 764
    iput v0, v1, Lh6/g;->d:I

    .line 765
    .line 766
    return-object v1

    .line 767
    :pswitch_11
    move-object v0, v1

    .line 768
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 769
    .line 770
    .line 771
    move-result v1

    .line 772
    const/4 v2, 0x0

    .line 773
    :goto_10
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 774
    .line 775
    .line 776
    move-result v3

    .line 777
    if-ge v3, v1, :cond_21

    .line 778
    .line 779
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 780
    .line 781
    .line 782
    move-result v3

    .line 783
    int-to-char v4, v3

    .line 784
    const/4 v5, 0x1

    .line 785
    if-eq v4, v5, :cond_20

    .line 786
    .line 787
    invoke-static {v0, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 788
    .line 789
    .line 790
    goto :goto_10

    .line 791
    :cond_20
    sget-object v2, Lcom/google/android/gms/common/api/Status;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 792
    .line 793
    invoke-static {v0, v3, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 794
    .line 795
    .line 796
    move-result-object v2

    .line 797
    check-cast v2, Lcom/google/android/gms/common/api/Status;

    .line 798
    .line 799
    goto :goto_10

    .line 800
    :cond_21
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 801
    .line 802
    .line 803
    new-instance v0, Lgp/s;

    .line 804
    .line 805
    invoke-direct {v0, v2}, Lgp/s;-><init>(Lcom/google/android/gms/common/api/Status;)V

    .line 806
    .line 807
    .line 808
    return-object v0

    .line 809
    :pswitch_12
    move-object v0, v1

    .line 810
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 811
    .line 812
    .line 813
    move-result v1

    .line 814
    const/4 v2, 0x0

    .line 815
    const/4 v3, 0x0

    .line 816
    move-object v6, v2

    .line 817
    move-object v7, v6

    .line 818
    move-object v8, v7

    .line 819
    move-object v9, v8

    .line 820
    move-object v10, v9

    .line 821
    move v5, v3

    .line 822
    :goto_11
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 823
    .line 824
    .line 825
    move-result v2

    .line 826
    if-ge v2, v1, :cond_28

    .line 827
    .line 828
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 829
    .line 830
    .line 831
    move-result v2

    .line 832
    int-to-char v3, v2

    .line 833
    const/4 v4, 0x1

    .line 834
    if-eq v3, v4, :cond_27

    .line 835
    .line 836
    const/4 v4, 0x3

    .line 837
    if-eq v3, v4, :cond_26

    .line 838
    .line 839
    const/4 v4, 0x4

    .line 840
    if-eq v3, v4, :cond_25

    .line 841
    .line 842
    const/4 v4, 0x6

    .line 843
    if-eq v3, v4, :cond_24

    .line 844
    .line 845
    const/4 v4, 0x7

    .line 846
    if-eq v3, v4, :cond_23

    .line 847
    .line 848
    const/16 v4, 0x8

    .line 849
    .line 850
    if-eq v3, v4, :cond_22

    .line 851
    .line 852
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 853
    .line 854
    .line 855
    goto :goto_11

    .line 856
    :cond_22
    sget-object v3, Ljo/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 857
    .line 858
    invoke-static {v0, v2, v3}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 859
    .line 860
    .line 861
    move-result-object v9

    .line 862
    goto :goto_11

    .line 863
    :cond_23
    sget-object v3, Lgp/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 864
    .line 865
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 866
    .line 867
    .line 868
    move-result-object v2

    .line 869
    move-object v10, v2

    .line 870
    check-cast v10, Lgp/g;

    .line 871
    .line 872
    goto :goto_11

    .line 873
    :cond_24
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 874
    .line 875
    .line 876
    move-result-object v8

    .line 877
    goto :goto_11

    .line 878
    :cond_25
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 879
    .line 880
    .line 881
    move-result-object v7

    .line 882
    goto :goto_11

    .line 883
    :cond_26
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 884
    .line 885
    .line 886
    move-result-object v6

    .line 887
    goto :goto_11

    .line 888
    :cond_27
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 889
    .line 890
    .line 891
    move-result v5

    .line 892
    goto :goto_11

    .line 893
    :cond_28
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 894
    .line 895
    .line 896
    new-instance v4, Lgp/g;

    .line 897
    .line 898
    invoke-direct/range {v4 .. v10}, Lgp/g;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Lgp/g;)V

    .line 899
    .line 900
    .line 901
    return-object v4

    .line 902
    :pswitch_13
    move-object v0, v1

    .line 903
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 904
    .line 905
    .line 906
    move-result v1

    .line 907
    const-string v2, ""

    .line 908
    .line 909
    const/4 v3, 0x0

    .line 910
    move-object v4, v3

    .line 911
    :goto_12
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 912
    .line 913
    .line 914
    move-result v5

    .line 915
    if-ge v5, v1, :cond_2c

    .line 916
    .line 917
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 918
    .line 919
    .line 920
    move-result v5

    .line 921
    int-to-char v6, v5

    .line 922
    const/4 v7, 0x1

    .line 923
    if-eq v6, v7, :cond_2b

    .line 924
    .line 925
    const/4 v7, 0x2

    .line 926
    if-eq v6, v7, :cond_2a

    .line 927
    .line 928
    const/4 v7, 0x3

    .line 929
    if-eq v6, v7, :cond_29

    .line 930
    .line 931
    invoke-static {v0, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 932
    .line 933
    .line 934
    goto :goto_12

    .line 935
    :cond_29
    invoke-static {v0, v5}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 936
    .line 937
    .line 938
    move-result-object v2

    .line 939
    goto :goto_12

    .line 940
    :cond_2a
    sget-object v4, Landroid/app/PendingIntent;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 941
    .line 942
    invoke-static {v0, v5, v4}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 943
    .line 944
    .line 945
    move-result-object v4

    .line 946
    check-cast v4, Landroid/app/PendingIntent;

    .line 947
    .line 948
    goto :goto_12

    .line 949
    :cond_2b
    invoke-static {v0, v5}, Ljp/xb;->h(Landroid/os/Parcel;I)Ljava/util/ArrayList;

    .line 950
    .line 951
    .line 952
    move-result-object v3

    .line 953
    goto :goto_12

    .line 954
    :cond_2c
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 955
    .line 956
    .line 957
    new-instance v0, Lgp/l;

    .line 958
    .line 959
    invoke-direct {v0, v3, v4, v2}, Lgp/l;-><init>(Ljava/util/List;Landroid/app/PendingIntent;Ljava/lang/String;)V

    .line 960
    .line 961
    .line 962
    return-object v0

    .line 963
    :pswitch_14
    move-object v0, v1

    .line 964
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 965
    .line 966
    .line 967
    move-result v1

    .line 968
    const/4 v2, -0x1

    .line 969
    const/4 v3, 0x0

    .line 970
    const-wide/16 v4, 0x0

    .line 971
    .line 972
    const/4 v6, 0x0

    .line 973
    const-wide/16 v7, 0x0

    .line 974
    .line 975
    const/4 v9, 0x0

    .line 976
    move/from16 v22, v2

    .line 977
    .line 978
    move v12, v3

    .line 979
    move v13, v12

    .line 980
    move/from16 v21, v13

    .line 981
    .line 982
    move-wide/from16 v19, v4

    .line 983
    .line 984
    move/from16 v18, v6

    .line 985
    .line 986
    move-wide v14, v7

    .line 987
    move-wide/from16 v16, v14

    .line 988
    .line 989
    move-object v11, v9

    .line 990
    :goto_13
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 991
    .line 992
    .line 993
    move-result v2

    .line 994
    if-ge v2, v1, :cond_2d

    .line 995
    .line 996
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 997
    .line 998
    .line 999
    move-result v2

    .line 1000
    int-to-char v3, v2

    .line 1001
    packed-switch v3, :pswitch_data_1

    .line 1002
    .line 1003
    .line 1004
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1005
    .line 1006
    .line 1007
    goto :goto_13

    .line 1008
    :pswitch_15
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1009
    .line 1010
    .line 1011
    move-result v2

    .line 1012
    move/from16 v22, v2

    .line 1013
    .line 1014
    goto :goto_13

    .line 1015
    :pswitch_16
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1016
    .line 1017
    .line 1018
    move-result v2

    .line 1019
    move/from16 v21, v2

    .line 1020
    .line 1021
    goto :goto_13

    .line 1022
    :pswitch_17
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1023
    .line 1024
    .line 1025
    move-result v2

    .line 1026
    move v12, v2

    .line 1027
    goto :goto_13

    .line 1028
    :pswitch_18
    invoke-static {v0, v2}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 1029
    .line 1030
    .line 1031
    move-result v2

    .line 1032
    move/from16 v18, v2

    .line 1033
    .line 1034
    goto :goto_13

    .line 1035
    :pswitch_19
    invoke-static {v0, v2}, Ljp/xb;->n(Landroid/os/Parcel;I)D

    .line 1036
    .line 1037
    .line 1038
    move-result-wide v2

    .line 1039
    move-wide/from16 v16, v2

    .line 1040
    .line 1041
    goto :goto_13

    .line 1042
    :pswitch_1a
    invoke-static {v0, v2}, Ljp/xb;->n(Landroid/os/Parcel;I)D

    .line 1043
    .line 1044
    .line 1045
    move-result-wide v2

    .line 1046
    move-wide v14, v2

    .line 1047
    goto :goto_13

    .line 1048
    :pswitch_1b
    const/4 v3, 0x4

    .line 1049
    invoke-static {v0, v2, v3}, Ljp/xb;->A(Landroid/os/Parcel;II)V

    .line 1050
    .line 1051
    .line 1052
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1053
    .line 1054
    .line 1055
    move-result v2

    .line 1056
    int-to-short v2, v2

    .line 1057
    move v13, v2

    .line 1058
    goto :goto_13

    .line 1059
    :pswitch_1c
    invoke-static {v0, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 1060
    .line 1061
    .line 1062
    move-result-wide v2

    .line 1063
    move-wide/from16 v19, v2

    .line 1064
    .line 1065
    goto :goto_13

    .line 1066
    :pswitch_1d
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v2

    .line 1070
    move-object v11, v2

    .line 1071
    goto :goto_13

    .line 1072
    :cond_2d
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1073
    .line 1074
    .line 1075
    new-instance v10, Lgp/k;

    .line 1076
    .line 1077
    invoke-direct/range {v10 .. v22}, Lgp/k;-><init>(Ljava/lang/String;ISDDFJII)V

    .line 1078
    .line 1079
    .line 1080
    return-object v10

    .line 1081
    :pswitch_1e
    move-object v0, v1

    .line 1082
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1083
    .line 1084
    .line 1085
    move-result v1

    .line 1086
    const/4 v2, 0x0

    .line 1087
    const/4 v3, 0x1

    .line 1088
    move-object v6, v2

    .line 1089
    move-object v7, v6

    .line 1090
    move-object v8, v7

    .line 1091
    move-object v9, v8

    .line 1092
    move-object v10, v9

    .line 1093
    move-object v11, v10

    .line 1094
    move v5, v3

    .line 1095
    :goto_14
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1096
    .line 1097
    .line 1098
    move-result v2

    .line 1099
    if-ge v2, v1, :cond_2e

    .line 1100
    .line 1101
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1102
    .line 1103
    .line 1104
    move-result v2

    .line 1105
    int-to-char v3, v2

    .line 1106
    packed-switch v3, :pswitch_data_2

    .line 1107
    .line 1108
    .line 1109
    :pswitch_1f
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1110
    .line 1111
    .line 1112
    goto :goto_14

    .line 1113
    :pswitch_20
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v11

    .line 1117
    goto :goto_14

    .line 1118
    :pswitch_21
    invoke-static {v0, v2}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1119
    .line 1120
    .line 1121
    move-result-object v10

    .line 1122
    goto :goto_14

    .line 1123
    :pswitch_22
    invoke-static {v0, v2}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1124
    .line 1125
    .line 1126
    move-result-object v8

    .line 1127
    goto :goto_14

    .line 1128
    :pswitch_23
    sget-object v3, Landroid/app/PendingIntent;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1129
    .line 1130
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1131
    .line 1132
    .line 1133
    move-result-object v2

    .line 1134
    move-object v9, v2

    .line 1135
    check-cast v9, Landroid/app/PendingIntent;

    .line 1136
    .line 1137
    goto :goto_14

    .line 1138
    :pswitch_24
    invoke-static {v0, v2}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1139
    .line 1140
    .line 1141
    move-result-object v7

    .line 1142
    goto :goto_14

    .line 1143
    :pswitch_25
    sget-object v3, Lgp/i;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1144
    .line 1145
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1146
    .line 1147
    .line 1148
    move-result-object v2

    .line 1149
    move-object v6, v2

    .line 1150
    check-cast v6, Lgp/i;

    .line 1151
    .line 1152
    goto :goto_14

    .line 1153
    :pswitch_26
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1154
    .line 1155
    .line 1156
    move-result v5

    .line 1157
    goto :goto_14

    .line 1158
    :cond_2e
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1159
    .line 1160
    .line 1161
    new-instance v4, Lgp/j;

    .line 1162
    .line 1163
    invoke-direct/range {v4 .. v11}, Lgp/j;-><init>(ILgp/i;Landroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Landroid/os/IBinder;Ljava/lang/String;)V

    .line 1164
    .line 1165
    .line 1166
    return-object v4

    .line 1167
    :pswitch_27
    move-object v0, v1

    .line 1168
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1169
    .line 1170
    .line 1171
    move-result v1

    .line 1172
    const-wide v2, 0x7fffffffffffffffL

    .line 1173
    .line 1174
    .line 1175
    .line 1176
    .line 1177
    const/4 v4, 0x0

    .line 1178
    const/4 v5, 0x0

    .line 1179
    move-wide v13, v2

    .line 1180
    move-object v7, v4

    .line 1181
    move-object v8, v7

    .line 1182
    move v9, v5

    .line 1183
    move v10, v9

    .line 1184
    move v11, v10

    .line 1185
    move v12, v11

    .line 1186
    :goto_15
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1187
    .line 1188
    .line 1189
    move-result v2

    .line 1190
    if-ge v2, v1, :cond_33

    .line 1191
    .line 1192
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1193
    .line 1194
    .line 1195
    move-result v2

    .line 1196
    int-to-char v3, v2

    .line 1197
    const/4 v4, 0x1

    .line 1198
    if-eq v3, v4, :cond_32

    .line 1199
    .line 1200
    const/4 v4, 0x5

    .line 1201
    if-eq v3, v4, :cond_31

    .line 1202
    .line 1203
    const/16 v4, 0x8

    .line 1204
    .line 1205
    if-eq v3, v4, :cond_30

    .line 1206
    .line 1207
    const/16 v4, 0x9

    .line 1208
    .line 1209
    if-eq v3, v4, :cond_2f

    .line 1210
    .line 1211
    packed-switch v3, :pswitch_data_3

    .line 1212
    .line 1213
    .line 1214
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1215
    .line 1216
    .line 1217
    goto :goto_15

    .line 1218
    :pswitch_28
    invoke-static {v0, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 1219
    .line 1220
    .line 1221
    move-result-wide v2

    .line 1222
    move-wide v13, v2

    .line 1223
    goto :goto_15

    .line 1224
    :pswitch_29
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1225
    .line 1226
    .line 1227
    goto :goto_15

    .line 1228
    :pswitch_2a
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1229
    .line 1230
    .line 1231
    move-result v2

    .line 1232
    move v12, v2

    .line 1233
    goto :goto_15

    .line 1234
    :pswitch_2b
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1235
    .line 1236
    .line 1237
    move-result v2

    .line 1238
    move v11, v2

    .line 1239
    goto :goto_15

    .line 1240
    :cond_2f
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1241
    .line 1242
    .line 1243
    move-result v2

    .line 1244
    move v10, v2

    .line 1245
    goto :goto_15

    .line 1246
    :cond_30
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1247
    .line 1248
    .line 1249
    move-result v2

    .line 1250
    move v9, v2

    .line 1251
    goto :goto_15

    .line 1252
    :cond_31
    sget-object v3, Lno/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1253
    .line 1254
    invoke-static {v0, v2, v3}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1255
    .line 1256
    .line 1257
    move-result-object v2

    .line 1258
    move-object v8, v2

    .line 1259
    goto :goto_15

    .line 1260
    :cond_32
    sget-object v3, Lcom/google/android/gms/location/LocationRequest;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1261
    .line 1262
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1263
    .line 1264
    .line 1265
    move-result-object v2

    .line 1266
    check-cast v2, Lcom/google/android/gms/location/LocationRequest;

    .line 1267
    .line 1268
    move-object v7, v2

    .line 1269
    goto :goto_15

    .line 1270
    :cond_33
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1271
    .line 1272
    .line 1273
    new-instance v6, Lgp/i;

    .line 1274
    .line 1275
    invoke-direct/range {v6 .. v14}, Lgp/i;-><init>(Lcom/google/android/gms/location/LocationRequest;Ljava/util/ArrayList;ZZZZJ)V

    .line 1276
    .line 1277
    .line 1278
    return-object v6

    .line 1279
    :pswitch_2c
    move-object v0, v1

    .line 1280
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1281
    .line 1282
    .line 1283
    move-result v1

    .line 1284
    const/4 v2, 0x0

    .line 1285
    const/4 v3, 0x0

    .line 1286
    move-object v6, v2

    .line 1287
    move-object v7, v6

    .line 1288
    move-object v8, v7

    .line 1289
    move-object v9, v8

    .line 1290
    move v5, v3

    .line 1291
    :goto_16
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1292
    .line 1293
    .line 1294
    move-result v2

    .line 1295
    if-ge v2, v1, :cond_39

    .line 1296
    .line 1297
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1298
    .line 1299
    .line 1300
    move-result v2

    .line 1301
    int-to-char v3, v2

    .line 1302
    const/4 v4, 0x1

    .line 1303
    if-eq v3, v4, :cond_38

    .line 1304
    .line 1305
    const/4 v4, 0x2

    .line 1306
    if-eq v3, v4, :cond_37

    .line 1307
    .line 1308
    const/4 v4, 0x3

    .line 1309
    if-eq v3, v4, :cond_36

    .line 1310
    .line 1311
    const/4 v4, 0x4

    .line 1312
    if-eq v3, v4, :cond_35

    .line 1313
    .line 1314
    const/4 v4, 0x6

    .line 1315
    if-eq v3, v4, :cond_34

    .line 1316
    .line 1317
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1318
    .line 1319
    .line 1320
    goto :goto_16

    .line 1321
    :cond_34
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1322
    .line 1323
    .line 1324
    move-result-object v9

    .line 1325
    goto :goto_16

    .line 1326
    :cond_35
    sget-object v3, Landroid/app/PendingIntent;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1327
    .line 1328
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1329
    .line 1330
    .line 1331
    move-result-object v2

    .line 1332
    move-object v8, v2

    .line 1333
    check-cast v8, Landroid/app/PendingIntent;

    .line 1334
    .line 1335
    goto :goto_16

    .line 1336
    :cond_36
    invoke-static {v0, v2}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1337
    .line 1338
    .line 1339
    move-result-object v7

    .line 1340
    goto :goto_16

    .line 1341
    :cond_37
    invoke-static {v0, v2}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1342
    .line 1343
    .line 1344
    move-result-object v6

    .line 1345
    goto :goto_16

    .line 1346
    :cond_38
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1347
    .line 1348
    .line 1349
    move-result v5

    .line 1350
    goto :goto_16

    .line 1351
    :cond_39
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1352
    .line 1353
    .line 1354
    new-instance v4, Lgp/h;

    .line 1355
    .line 1356
    invoke-direct/range {v4 .. v9}, Lgp/h;-><init>(ILandroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Ljava/lang/String;)V

    .line 1357
    .line 1358
    .line 1359
    return-object v4

    .line 1360
    :pswitch_2d
    move-object v0, v1

    .line 1361
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1362
    .line 1363
    .line 1364
    move-result v1

    .line 1365
    const/4 v2, 0x0

    .line 1366
    const-wide/16 v3, 0x0

    .line 1367
    .line 1368
    const/4 v5, 0x0

    .line 1369
    move-object v8, v2

    .line 1370
    move-object v9, v8

    .line 1371
    move-object v10, v9

    .line 1372
    move-object v11, v10

    .line 1373
    move-object v12, v11

    .line 1374
    move-object v13, v12

    .line 1375
    move-object/from16 v16, v13

    .line 1376
    .line 1377
    move-object/from16 v17, v16

    .line 1378
    .line 1379
    move-object/from16 v18, v17

    .line 1380
    .line 1381
    move-object/from16 v19, v18

    .line 1382
    .line 1383
    move-wide v14, v3

    .line 1384
    move v7, v5

    .line 1385
    :goto_17
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1386
    .line 1387
    .line 1388
    move-result v2

    .line 1389
    if-ge v2, v1, :cond_3a

    .line 1390
    .line 1391
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1392
    .line 1393
    .line 1394
    move-result v2

    .line 1395
    int-to-char v3, v2

    .line 1396
    packed-switch v3, :pswitch_data_4

    .line 1397
    .line 1398
    .line 1399
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1400
    .line 1401
    .line 1402
    goto :goto_17

    .line 1403
    :pswitch_2e
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1404
    .line 1405
    .line 1406
    move-result-object v2

    .line 1407
    move-object/from16 v19, v2

    .line 1408
    .line 1409
    goto :goto_17

    .line 1410
    :pswitch_2f
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1411
    .line 1412
    .line 1413
    move-result-object v2

    .line 1414
    move-object/from16 v18, v2

    .line 1415
    .line 1416
    goto :goto_17

    .line 1417
    :pswitch_30
    sget-object v3, Lcom/google/android/gms/common/api/Scope;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1418
    .line 1419
    invoke-static {v0, v2, v3}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1420
    .line 1421
    .line 1422
    move-result-object v2

    .line 1423
    move-object/from16 v17, v2

    .line 1424
    .line 1425
    goto :goto_17

    .line 1426
    :pswitch_31
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1427
    .line 1428
    .line 1429
    move-result-object v2

    .line 1430
    move-object/from16 v16, v2

    .line 1431
    .line 1432
    goto :goto_17

    .line 1433
    :pswitch_32
    invoke-static {v0, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 1434
    .line 1435
    .line 1436
    move-result-wide v2

    .line 1437
    move-wide v14, v2

    .line 1438
    goto :goto_17

    .line 1439
    :pswitch_33
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1440
    .line 1441
    .line 1442
    move-result-object v2

    .line 1443
    move-object v13, v2

    .line 1444
    goto :goto_17

    .line 1445
    :pswitch_34
    sget-object v3, Landroid/net/Uri;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1446
    .line 1447
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1448
    .line 1449
    .line 1450
    move-result-object v2

    .line 1451
    check-cast v2, Landroid/net/Uri;

    .line 1452
    .line 1453
    move-object v12, v2

    .line 1454
    goto :goto_17

    .line 1455
    :pswitch_35
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1456
    .line 1457
    .line 1458
    move-result-object v2

    .line 1459
    move-object v11, v2

    .line 1460
    goto :goto_17

    .line 1461
    :pswitch_36
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1462
    .line 1463
    .line 1464
    move-result-object v2

    .line 1465
    move-object v10, v2

    .line 1466
    goto :goto_17

    .line 1467
    :pswitch_37
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1468
    .line 1469
    .line 1470
    move-result-object v2

    .line 1471
    move-object v9, v2

    .line 1472
    goto :goto_17

    .line 1473
    :pswitch_38
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1474
    .line 1475
    .line 1476
    move-result-object v2

    .line 1477
    move-object v8, v2

    .line 1478
    goto :goto_17

    .line 1479
    :pswitch_39
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1480
    .line 1481
    .line 1482
    move-result v2

    .line 1483
    move v7, v2

    .line 1484
    goto :goto_17

    .line 1485
    :cond_3a
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1486
    .line 1487
    .line 1488
    new-instance v6, Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;

    .line 1489
    .line 1490
    invoke-direct/range {v6 .. v19}, Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;Ljava/lang/String;JLjava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;)V

    .line 1491
    .line 1492
    .line 1493
    return-object v6

    .line 1494
    :pswitch_3a
    move-object v0, v1

    .line 1495
    const-string v1, "parcel"

    .line 1496
    .line 1497
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1498
    .line 1499
    .line 1500
    new-instance v1, Lgl/g;

    .line 1501
    .line 1502
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1503
    .line 1504
    .line 1505
    move-result v2

    .line 1506
    invoke-virtual {v0}, Landroid/os/Parcel;->createStringArrayList()Ljava/util/ArrayList;

    .line 1507
    .line 1508
    .line 1509
    move-result-object v3

    .line 1510
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1511
    .line 1512
    .line 1513
    move-result v0

    .line 1514
    if-eqz v0, :cond_3b

    .line 1515
    .line 1516
    const/4 v0, 0x1

    .line 1517
    goto :goto_18

    .line 1518
    :cond_3b
    const/4 v0, 0x0

    .line 1519
    :goto_18
    invoke-direct {v1, v2, v3, v0}, Lgl/g;-><init>(ILjava/util/ArrayList;Z)V

    .line 1520
    .line 1521
    .line 1522
    return-object v1

    .line 1523
    :pswitch_3b
    move-object v0, v1

    .line 1524
    const-string v1, "parcel"

    .line 1525
    .line 1526
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1527
    .line 1528
    .line 1529
    new-instance v1, Lgl/f;

    .line 1530
    .line 1531
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1532
    .line 1533
    .line 1534
    move-result-object v2

    .line 1535
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1536
    .line 1537
    .line 1538
    move-result v0

    .line 1539
    if-eqz v0, :cond_3c

    .line 1540
    .line 1541
    const/4 v0, 0x1

    .line 1542
    goto :goto_19

    .line 1543
    :cond_3c
    const/4 v0, 0x0

    .line 1544
    :goto_19
    invoke-direct {v1, v2, v0}, Lgl/f;-><init>(Ljava/lang/String;Z)V

    .line 1545
    .line 1546
    .line 1547
    return-object v1

    .line 1548
    :pswitch_3c
    move-object v0, v1

    .line 1549
    const-string v1, "parcel"

    .line 1550
    .line 1551
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1552
    .line 1553
    .line 1554
    new-instance v1, Lgl/e;

    .line 1555
    .line 1556
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1557
    .line 1558
    .line 1559
    move-result v2

    .line 1560
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1561
    .line 1562
    .line 1563
    move-result v3

    .line 1564
    invoke-virtual {v0}, Landroid/os/Parcel;->createStringArrayList()Ljava/util/ArrayList;

    .line 1565
    .line 1566
    .line 1567
    move-result-object v4

    .line 1568
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1569
    .line 1570
    .line 1571
    move-result v0

    .line 1572
    if-eqz v0, :cond_3d

    .line 1573
    .line 1574
    const/4 v0, 0x1

    .line 1575
    goto :goto_1a

    .line 1576
    :cond_3d
    const/4 v0, 0x0

    .line 1577
    :goto_1a
    invoke-direct {v1, v2, v3, v4, v0}, Lgl/e;-><init>(IILjava/util/ArrayList;Z)V

    .line 1578
    .line 1579
    .line 1580
    return-object v1

    .line 1581
    :pswitch_3d
    move-object v0, v1

    .line 1582
    const-string v1, "parcel"

    .line 1583
    .line 1584
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1585
    .line 1586
    .line 1587
    new-instance v1, Lgl/d;

    .line 1588
    .line 1589
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1590
    .line 1591
    .line 1592
    move-result v2

    .line 1593
    invoke-virtual {v0}, Landroid/os/Parcel;->createStringArrayList()Ljava/util/ArrayList;

    .line 1594
    .line 1595
    .line 1596
    move-result-object v3

    .line 1597
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1598
    .line 1599
    .line 1600
    move-result v0

    .line 1601
    if-eqz v0, :cond_3e

    .line 1602
    .line 1603
    const/4 v0, 0x1

    .line 1604
    goto :goto_1b

    .line 1605
    :cond_3e
    const/4 v0, 0x0

    .line 1606
    :goto_1b
    invoke-direct {v1, v2, v3, v0}, Lgl/d;-><init>(ILjava/util/ArrayList;Z)V

    .line 1607
    .line 1608
    .line 1609
    return-object v1

    .line 1610
    nop

    .line 1611
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_2d
        :pswitch_2c
        :pswitch_27
        :pswitch_1e
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

    .line 1612
    .line 1613
    .line 1614
    .line 1615
    .line 1616
    .line 1617
    .line 1618
    .line 1619
    .line 1620
    .line 1621
    .line 1622
    .line 1623
    .line 1624
    .line 1625
    .line 1626
    .line 1627
    .line 1628
    .line 1629
    .line 1630
    .line 1631
    .line 1632
    .line 1633
    .line 1634
    .line 1635
    .line 1636
    .line 1637
    .line 1638
    .line 1639
    .line 1640
    .line 1641
    .line 1642
    .line 1643
    .line 1644
    .line 1645
    .line 1646
    .line 1647
    .line 1648
    .line 1649
    .line 1650
    .line 1651
    .line 1652
    .line 1653
    .line 1654
    .line 1655
    .line 1656
    .line 1657
    .line 1658
    .line 1659
    .line 1660
    .line 1661
    .line 1662
    .line 1663
    .line 1664
    .line 1665
    .line 1666
    .line 1667
    .line 1668
    .line 1669
    .line 1670
    .line 1671
    .line 1672
    .line 1673
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
    .end packed-switch

    .line 1674
    .line 1675
    .line 1676
    .line 1677
    .line 1678
    .line 1679
    .line 1680
    .line 1681
    .line 1682
    .line 1683
    .line 1684
    .line 1685
    .line 1686
    .line 1687
    .line 1688
    .line 1689
    .line 1690
    .line 1691
    .line 1692
    .line 1693
    .line 1694
    .line 1695
    :pswitch_data_2
    .packed-switch 0x1
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_1f
        :pswitch_20
    .end packed-switch

    .line 1696
    .line 1697
    .line 1698
    .line 1699
    .line 1700
    .line 1701
    .line 1702
    .line 1703
    .line 1704
    .line 1705
    .line 1706
    .line 1707
    .line 1708
    .line 1709
    .line 1710
    .line 1711
    .line 1712
    .line 1713
    .line 1714
    .line 1715
    :pswitch_data_3
    .packed-switch 0xb
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
    .end packed-switch

    .line 1716
    .line 1717
    .line 1718
    .line 1719
    .line 1720
    .line 1721
    .line 1722
    .line 1723
    .line 1724
    .line 1725
    .line 1726
    .line 1727
    :pswitch_data_4
    .packed-switch 0x1
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
    .end packed-switch
.end method

.method public final newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lgl/c;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lkg/d0;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lkg/x;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Lkg/r;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Lkg/o;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    new-array p0, p1, [Lkg/l;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    new-array p0, p1, [Lkg/i;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    new-array p0, p1, [Lkg/f;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    new-array p0, p1, [Lkg/c;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    new-array p0, p1, [Lka/c1;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    new-array p0, p1, [Lka/b1;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_9
    new-array p0, p1, [Lka/r;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_a
    new-array p0, p1, [Ljo/r;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_b
    new-array p0, p1, [Ljo/d;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_c
    new-array p0, p1, [Ljo/b;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_d
    new-array p0, p1, [Lje/z;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_e
    new-array p0, p1, [Lhc/c;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_f
    new-array p0, p1, [Lhc/a;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_10
    new-array p0, p1, [Lh6/g;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_11
    new-array p0, p1, [Lgp/s;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_12
    new-array p0, p1, [Lgp/g;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_13
    new-array p0, p1, [Lgp/l;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_14
    new-array p0, p1, [Lgp/k;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_15
    new-array p0, p1, [Lgp/j;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_16
    new-array p0, p1, [Lgp/i;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_17
    new-array p0, p1, [Lgp/h;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_18
    new-array p0, p1, [Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_19
    new-array p0, p1, [Lgl/g;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_1a
    new-array p0, p1, [Lgl/f;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_1b
    new-array p0, p1, [Lgl/e;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_1c
    new-array p0, p1, [Lgl/d;

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

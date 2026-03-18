.class public final Lcom/google/android/gms/internal/measurement/b6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lcom/google/android/gms/internal/measurement/u;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/z6;Lcom/google/android/gms/internal/measurement/z6;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/google/android/gms/internal/measurement/u;

    .line 5
    .line 6
    invoke-direct {v0, p1, p2}, Lcom/google/android/gms/internal/measurement/u;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/b6;->a:Lcom/google/android/gms/internal/measurement/u;

    .line 10
    .line 11
    return-void
.end method

.method public static a(Lcom/google/android/gms/internal/measurement/b5;Lcom/google/android/gms/internal/measurement/u;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/u;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/android/gms/internal/measurement/z6;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-static {p0, v0, v1, p2}, Lcom/google/android/gms/internal/measurement/f5;->b(Lcom/google/android/gms/internal/measurement/b5;Lcom/google/android/gms/internal/measurement/z6;ILjava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/u;->b:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p1, Lcom/google/android/gms/internal/measurement/z6;

    .line 12
    .line 13
    const/4 p2, 0x2

    .line 14
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/gms/internal/measurement/f5;->b(Lcom/google/android/gms/internal/measurement/b5;Lcom/google/android/gms/internal/measurement/z6;ILjava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public static b(Lcom/google/android/gms/internal/measurement/u;Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 12

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/u;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/android/gms/internal/measurement/z6;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/u;->b:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcom/google/android/gms/internal/measurement/z6;

    .line 8
    .line 9
    sget v1, Lcom/google/android/gms/internal/measurement/f5;->c:I

    .line 10
    .line 11
    const/16 v1, 0x8

    .line 12
    .line 13
    invoke-static {v1}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    sget-object v3, Lcom/google/android/gms/internal/measurement/z6;->g:Lcom/google/android/gms/internal/measurement/z6;

    .line 18
    .line 19
    if-ne v0, v3, :cond_0

    .line 20
    .line 21
    move-object v4, p1

    .line 22
    check-cast v4, Lcom/google/android/gms/internal/measurement/t4;

    .line 23
    .line 24
    sget-object v4, Lcom/google/android/gms/internal/measurement/s5;->a:Ljava/nio/charset/Charset;

    .line 25
    .line 26
    add-int/2addr v2, v2

    .line 27
    :cond_0
    sget-object v4, Lcom/google/android/gms/internal/measurement/a7;->d:Lcom/google/android/gms/internal/measurement/a7;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    const/4 v4, 0x1

    .line 34
    const/16 v5, 0x3f

    .line 35
    .line 36
    const-string v6, "There is no way to get here, but the compiler thinks otherwise."

    .line 37
    .line 38
    const/4 v7, 0x4

    .line 39
    packed-switch v0, :pswitch_data_0

    .line 40
    .line 41
    .line 42
    new-instance p0, Ljava/lang/RuntimeException;

    .line 43
    .line 44
    invoke-direct {p0, v6}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :pswitch_0
    check-cast p1, Ljava/lang/Long;

    .line 49
    .line 50
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 51
    .line 52
    .line 53
    move-result-wide v8

    .line 54
    add-long v10, v8, v8

    .line 55
    .line 56
    shr-long/2addr v8, v5

    .line 57
    xor-long/2addr v8, v10

    .line 58
    invoke-static {v8, v9}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    goto/16 :goto_3

    .line 63
    .line 64
    :pswitch_1
    check-cast p1, Ljava/lang/Integer;

    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    add-int v0, p1, p1

    .line 71
    .line 72
    shr-int/lit8 p1, p1, 0x1f

    .line 73
    .line 74
    xor-int/2addr p1, v0

    .line 75
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    goto/16 :goto_3

    .line 80
    .line 81
    :pswitch_2
    check-cast p1, Ljava/lang/Long;

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    :goto_0
    move p1, v1

    .line 87
    goto/16 :goto_3

    .line 88
    .line 89
    :pswitch_3
    check-cast p1, Ljava/lang/Integer;

    .line 90
    .line 91
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    :goto_1
    move p1, v7

    .line 95
    goto/16 :goto_3

    .line 96
    .line 97
    :pswitch_4
    instance-of v0, p1, Lcom/google/android/gms/internal/measurement/n5;

    .line 98
    .line 99
    if-eqz v0, :cond_1

    .line 100
    .line 101
    check-cast p1, Lcom/google/android/gms/internal/measurement/n5;

    .line 102
    .line 103
    invoke-interface {p1}, Lcom/google/android/gms/internal/measurement/n5;->h()I

    .line 104
    .line 105
    .line 106
    move-result p1

    .line 107
    int-to-long v8, p1

    .line 108
    invoke-static {v8, v9}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    goto/16 :goto_3

    .line 113
    .line 114
    :cond_1
    check-cast p1, Ljava/lang/Integer;

    .line 115
    .line 116
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    int-to-long v8, p1

    .line 121
    invoke-static {v8, v9}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    goto/16 :goto_3

    .line 126
    .line 127
    :pswitch_5
    check-cast p1, Ljava/lang/Integer;

    .line 128
    .line 129
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    goto/16 :goto_3

    .line 138
    .line 139
    :pswitch_6
    instance-of v0, p1, Lcom/google/android/gms/internal/measurement/a5;

    .line 140
    .line 141
    if-eqz v0, :cond_2

    .line 142
    .line 143
    check-cast p1, Lcom/google/android/gms/internal/measurement/a5;

    .line 144
    .line 145
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/a5;->g()I

    .line 146
    .line 147
    .line 148
    move-result p1

    .line 149
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 150
    .line 151
    .line 152
    move-result v0

    .line 153
    :goto_2
    add-int/2addr p1, v0

    .line 154
    goto/16 :goto_3

    .line 155
    .line 156
    :cond_2
    check-cast p1, [B

    .line 157
    .line 158
    array-length p1, p1

    .line 159
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    goto :goto_2

    .line 164
    :pswitch_7
    check-cast p1, Lcom/google/android/gms/internal/measurement/t4;

    .line 165
    .line 166
    check-cast p1, Lcom/google/android/gms/internal/measurement/l5;

    .line 167
    .line 168
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/l5;->k()I

    .line 169
    .line 170
    .line 171
    move-result p1

    .line 172
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 173
    .line 174
    .line 175
    move-result v0

    .line 176
    goto :goto_2

    .line 177
    :pswitch_8
    check-cast p1, Lcom/google/android/gms/internal/measurement/t4;

    .line 178
    .line 179
    check-cast p1, Lcom/google/android/gms/internal/measurement/l5;

    .line 180
    .line 181
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/l5;->k()I

    .line 182
    .line 183
    .line 184
    move-result p1

    .line 185
    goto :goto_3

    .line 186
    :pswitch_9
    instance-of v0, p1, Lcom/google/android/gms/internal/measurement/a5;

    .line 187
    .line 188
    if-eqz v0, :cond_3

    .line 189
    .line 190
    check-cast p1, Lcom/google/android/gms/internal/measurement/a5;

    .line 191
    .line 192
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/a5;->g()I

    .line 193
    .line 194
    .line 195
    move-result p1

    .line 196
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    goto :goto_2

    .line 201
    :cond_3
    check-cast p1, Ljava/lang/String;

    .line 202
    .line 203
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/b5;->d(Ljava/lang/String;)I

    .line 204
    .line 205
    .line 206
    move-result p1

    .line 207
    goto :goto_3

    .line 208
    :pswitch_a
    check-cast p1, Ljava/lang/Boolean;

    .line 209
    .line 210
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 211
    .line 212
    .line 213
    move p1, v4

    .line 214
    goto :goto_3

    .line 215
    :pswitch_b
    check-cast p1, Ljava/lang/Integer;

    .line 216
    .line 217
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 218
    .line 219
    .line 220
    goto :goto_1

    .line 221
    :pswitch_c
    check-cast p1, Ljava/lang/Long;

    .line 222
    .line 223
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 224
    .line 225
    .line 226
    goto/16 :goto_0

    .line 227
    .line 228
    :pswitch_d
    check-cast p1, Ljava/lang/Integer;

    .line 229
    .line 230
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 231
    .line 232
    .line 233
    move-result p1

    .line 234
    int-to-long v8, p1

    .line 235
    invoke-static {v8, v9}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 236
    .line 237
    .line 238
    move-result p1

    .line 239
    goto :goto_3

    .line 240
    :pswitch_e
    check-cast p1, Ljava/lang/Long;

    .line 241
    .line 242
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 243
    .line 244
    .line 245
    move-result-wide v8

    .line 246
    invoke-static {v8, v9}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 247
    .line 248
    .line 249
    move-result p1

    .line 250
    goto :goto_3

    .line 251
    :pswitch_f
    check-cast p1, Ljava/lang/Long;

    .line 252
    .line 253
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 254
    .line 255
    .line 256
    move-result-wide v8

    .line 257
    invoke-static {v8, v9}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 258
    .line 259
    .line 260
    move-result p1

    .line 261
    goto :goto_3

    .line 262
    :pswitch_10
    check-cast p1, Ljava/lang/Float;

    .line 263
    .line 264
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 265
    .line 266
    .line 267
    goto/16 :goto_1

    .line 268
    .line 269
    :pswitch_11
    check-cast p1, Ljava/lang/Double;

    .line 270
    .line 271
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 272
    .line 273
    .line 274
    goto/16 :goto_0

    .line 275
    .line 276
    :goto_3
    add-int/2addr p1, v2

    .line 277
    const/16 v0, 0x10

    .line 278
    .line 279
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 280
    .line 281
    .line 282
    move-result v0

    .line 283
    if-ne p0, v3, :cond_4

    .line 284
    .line 285
    move-object v2, p2

    .line 286
    check-cast v2, Lcom/google/android/gms/internal/measurement/t4;

    .line 287
    .line 288
    sget-object v2, Lcom/google/android/gms/internal/measurement/s5;->a:Ljava/nio/charset/Charset;

    .line 289
    .line 290
    add-int/2addr v0, v0

    .line 291
    :cond_4
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 292
    .line 293
    .line 294
    move-result p0

    .line 295
    packed-switch p0, :pswitch_data_1

    .line 296
    .line 297
    .line 298
    new-instance p0, Ljava/lang/RuntimeException;

    .line 299
    .line 300
    invoke-direct {p0, v6}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    throw p0

    .line 304
    :pswitch_12
    check-cast p2, Ljava/lang/Long;

    .line 305
    .line 306
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 307
    .line 308
    .line 309
    move-result-wide v1

    .line 310
    add-long v3, v1, v1

    .line 311
    .line 312
    shr-long/2addr v1, v5

    .line 313
    xor-long/2addr v1, v3

    .line 314
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 315
    .line 316
    .line 317
    move-result v1

    .line 318
    goto/16 :goto_6

    .line 319
    .line 320
    :pswitch_13
    check-cast p2, Ljava/lang/Integer;

    .line 321
    .line 322
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 323
    .line 324
    .line 325
    move-result p0

    .line 326
    add-int p2, p0, p0

    .line 327
    .line 328
    shr-int/lit8 p0, p0, 0x1f

    .line 329
    .line 330
    xor-int/2addr p0, p2

    .line 331
    invoke-static {p0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 332
    .line 333
    .line 334
    move-result v1

    .line 335
    goto/16 :goto_6

    .line 336
    .line 337
    :pswitch_14
    check-cast p2, Ljava/lang/Long;

    .line 338
    .line 339
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 340
    .line 341
    .line 342
    goto/16 :goto_6

    .line 343
    .line 344
    :pswitch_15
    check-cast p2, Ljava/lang/Integer;

    .line 345
    .line 346
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 347
    .line 348
    .line 349
    :goto_4
    move v1, v7

    .line 350
    goto/16 :goto_6

    .line 351
    .line 352
    :pswitch_16
    instance-of p0, p2, Lcom/google/android/gms/internal/measurement/n5;

    .line 353
    .line 354
    if-eqz p0, :cond_5

    .line 355
    .line 356
    check-cast p2, Lcom/google/android/gms/internal/measurement/n5;

    .line 357
    .line 358
    invoke-interface {p2}, Lcom/google/android/gms/internal/measurement/n5;->h()I

    .line 359
    .line 360
    .line 361
    move-result p0

    .line 362
    int-to-long v1, p0

    .line 363
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 364
    .line 365
    .line 366
    move-result v1

    .line 367
    goto/16 :goto_6

    .line 368
    .line 369
    :cond_5
    check-cast p2, Ljava/lang/Integer;

    .line 370
    .line 371
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 372
    .line 373
    .line 374
    move-result p0

    .line 375
    int-to-long v1, p0

    .line 376
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 377
    .line 378
    .line 379
    move-result v1

    .line 380
    goto/16 :goto_6

    .line 381
    .line 382
    :pswitch_17
    check-cast p2, Ljava/lang/Integer;

    .line 383
    .line 384
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 385
    .line 386
    .line 387
    move-result p0

    .line 388
    invoke-static {p0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 389
    .line 390
    .line 391
    move-result v1

    .line 392
    goto/16 :goto_6

    .line 393
    .line 394
    :pswitch_18
    instance-of p0, p2, Lcom/google/android/gms/internal/measurement/a5;

    .line 395
    .line 396
    if-eqz p0, :cond_6

    .line 397
    .line 398
    check-cast p2, Lcom/google/android/gms/internal/measurement/a5;

    .line 399
    .line 400
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/a5;->g()I

    .line 401
    .line 402
    .line 403
    move-result p0

    .line 404
    invoke-static {p0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 405
    .line 406
    .line 407
    move-result p2

    .line 408
    :goto_5
    add-int v1, p2, p0

    .line 409
    .line 410
    goto/16 :goto_6

    .line 411
    .line 412
    :cond_6
    check-cast p2, [B

    .line 413
    .line 414
    array-length p0, p2

    .line 415
    invoke-static {p0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 416
    .line 417
    .line 418
    move-result p2

    .line 419
    goto :goto_5

    .line 420
    :pswitch_19
    check-cast p2, Lcom/google/android/gms/internal/measurement/t4;

    .line 421
    .line 422
    check-cast p2, Lcom/google/android/gms/internal/measurement/l5;

    .line 423
    .line 424
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/l5;->k()I

    .line 425
    .line 426
    .line 427
    move-result p0

    .line 428
    invoke-static {p0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 429
    .line 430
    .line 431
    move-result p2

    .line 432
    goto :goto_5

    .line 433
    :pswitch_1a
    check-cast p2, Lcom/google/android/gms/internal/measurement/t4;

    .line 434
    .line 435
    check-cast p2, Lcom/google/android/gms/internal/measurement/l5;

    .line 436
    .line 437
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/l5;->k()I

    .line 438
    .line 439
    .line 440
    move-result v1

    .line 441
    goto :goto_6

    .line 442
    :pswitch_1b
    instance-of p0, p2, Lcom/google/android/gms/internal/measurement/a5;

    .line 443
    .line 444
    if-eqz p0, :cond_7

    .line 445
    .line 446
    check-cast p2, Lcom/google/android/gms/internal/measurement/a5;

    .line 447
    .line 448
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/a5;->g()I

    .line 449
    .line 450
    .line 451
    move-result p0

    .line 452
    invoke-static {p0}, Lcom/google/android/gms/internal/measurement/b5;->u(I)I

    .line 453
    .line 454
    .line 455
    move-result p2

    .line 456
    goto :goto_5

    .line 457
    :cond_7
    check-cast p2, Ljava/lang/String;

    .line 458
    .line 459
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/b5;->d(Ljava/lang/String;)I

    .line 460
    .line 461
    .line 462
    move-result v1

    .line 463
    goto :goto_6

    .line 464
    :pswitch_1c
    check-cast p2, Ljava/lang/Boolean;

    .line 465
    .line 466
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 467
    .line 468
    .line 469
    move v1, v4

    .line 470
    goto :goto_6

    .line 471
    :pswitch_1d
    check-cast p2, Ljava/lang/Integer;

    .line 472
    .line 473
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 474
    .line 475
    .line 476
    goto :goto_4

    .line 477
    :pswitch_1e
    check-cast p2, Ljava/lang/Long;

    .line 478
    .line 479
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 480
    .line 481
    .line 482
    goto :goto_6

    .line 483
    :pswitch_1f
    check-cast p2, Ljava/lang/Integer;

    .line 484
    .line 485
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 486
    .line 487
    .line 488
    move-result p0

    .line 489
    int-to-long v1, p0

    .line 490
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 491
    .line 492
    .line 493
    move-result v1

    .line 494
    goto :goto_6

    .line 495
    :pswitch_20
    check-cast p2, Ljava/lang/Long;

    .line 496
    .line 497
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 498
    .line 499
    .line 500
    move-result-wide v1

    .line 501
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 502
    .line 503
    .line 504
    move-result v1

    .line 505
    goto :goto_6

    .line 506
    :pswitch_21
    check-cast p2, Ljava/lang/Long;

    .line 507
    .line 508
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 509
    .line 510
    .line 511
    move-result-wide v1

    .line 512
    invoke-static {v1, v2}, Lcom/google/android/gms/internal/measurement/b5;->c(J)I

    .line 513
    .line 514
    .line 515
    move-result v1

    .line 516
    goto :goto_6

    .line 517
    :pswitch_22
    check-cast p2, Ljava/lang/Float;

    .line 518
    .line 519
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 520
    .line 521
    .line 522
    goto/16 :goto_4

    .line 523
    .line 524
    :pswitch_23
    check-cast p2, Ljava/lang/Double;

    .line 525
    .line 526
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 527
    .line 528
    .line 529
    :goto_6
    add-int/2addr v1, v0

    .line 530
    add-int/2addr v1, p1

    .line 531
    return v1

    .line 532
    nop

    .line 533
    :pswitch_data_0
    .packed-switch 0x0
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

    .line 534
    .line 535
    .line 536
    .line 537
    .line 538
    .line 539
    .line 540
    .line 541
    .line 542
    .line 543
    .line 544
    .line 545
    .line 546
    .line 547
    .line 548
    .line 549
    .line 550
    .line 551
    .line 552
    .line 553
    .line 554
    .line 555
    .line 556
    .line 557
    .line 558
    .line 559
    .line 560
    .line 561
    .line 562
    .line 563
    .line 564
    .line 565
    .line 566
    .line 567
    .line 568
    .line 569
    .line 570
    .line 571
    .line 572
    .line 573
    :pswitch_data_1
    .packed-switch 0x0
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
    .end packed-switch
.end method

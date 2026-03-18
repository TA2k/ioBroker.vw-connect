.class public final Le2/r0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Le2/w0;


# direct methods
.method public synthetic constructor <init>(Le2/w0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Le2/r0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le2/r0;->f:Le2/w0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Le2/r0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Le2/r0;

    .line 7
    .line 8
    iget-object p0, p0, Le2/r0;->f:Le2/w0;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Le2/r0;-><init>(Le2/w0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Le2/r0;

    .line 16
    .line 17
    iget-object p0, p0, Le2/r0;->f:Le2/w0;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Le2/r0;-><init>(Le2/w0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Le2/r0;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Le2/r0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Le2/r0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Le2/r0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Le2/r0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Le2/r0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Le2/r0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 45

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le2/r0;->d:I

    .line 4
    .line 5
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 6
    .line 7
    iget-object v3, v0, Le2/r0;->f:Le2/w0;

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    packed-switch v1, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    iget v6, v0, Le2/r0;->e:I

    .line 18
    .line 19
    const/4 v8, 0x2

    .line 20
    if-eqz v6, :cond_2

    .line 21
    .line 22
    if-eq v6, v4, :cond_1

    .line 23
    .line 24
    if-ne v6, v8, :cond_0

    .line 25
    .line 26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    move-object/from16 v0, p1

    .line 30
    .line 31
    goto/16 :goto_14

    .line 32
    .line 33
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v0

    .line 39
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    move-object/from16 v6, p1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    iget-object v2, v3, Le2/w0;->g:Lw3/c1;

    .line 49
    .line 50
    if-eqz v2, :cond_27

    .line 51
    .line 52
    iput v4, v0, Le2/r0;->e:I

    .line 53
    .line 54
    check-cast v2, Lw3/h;

    .line 55
    .line 56
    iget-object v2, v2, Lw3/h;->a:Lw3/i;

    .line 57
    .line 58
    iget-object v2, v2, Lw3/i;->a:Landroid/content/ClipboardManager;

    .line 59
    .line 60
    invoke-virtual {v2}, Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    if-eqz v2, :cond_3

    .line 65
    .line 66
    new-instance v6, Lw3/b1;

    .line 67
    .line 68
    invoke-direct {v6, v2}, Lw3/b1;-><init>(Landroid/content/ClipData;)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_3
    const/4 v6, 0x0

    .line 73
    :goto_0
    if-ne v6, v1, :cond_4

    .line 74
    .line 75
    goto/16 :goto_13

    .line 76
    .line 77
    :cond_4
    :goto_1
    check-cast v6, Lw3/b1;

    .line 78
    .line 79
    if-eqz v6, :cond_27

    .line 80
    .line 81
    iput v8, v0, Le2/r0;->e:I

    .line 82
    .line 83
    iget-object v0, v6, Lw3/b1;->a:Landroid/content/ClipData;

    .line 84
    .line 85
    const/4 v2, 0x0

    .line 86
    invoke-virtual {v0, v2}, Landroid/content/ClipData;->getItemAt(I)Landroid/content/ClipData$Item;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    if-eqz v0, :cond_24

    .line 91
    .line 92
    invoke-virtual {v0}, Landroid/content/ClipData$Item;->getText()Ljava/lang/CharSequence;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    if-eqz v0, :cond_24

    .line 97
    .line 98
    instance-of v6, v0, Landroid/text/Spanned;

    .line 99
    .line 100
    if-nez v6, :cond_5

    .line 101
    .line 102
    new-instance v2, Lg4/g;

    .line 103
    .line 104
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    invoke-direct {v2, v0}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    move-object v0, v2

    .line 112
    goto/16 :goto_12

    .line 113
    .line 114
    :cond_5
    move-object v6, v0

    .line 115
    check-cast v6, Landroid/text/Spanned;

    .line 116
    .line 117
    invoke-interface {v6}, Ljava/lang/CharSequence;->length()I

    .line 118
    .line 119
    .line 120
    move-result v9

    .line 121
    const-class v10, Landroid/text/Annotation;

    .line 122
    .line 123
    invoke-interface {v6, v2, v9, v10}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v9

    .line 127
    check-cast v9, [Landroid/text/Annotation;

    .line 128
    .line 129
    new-instance v10, Ljava/util/ArrayList;

    .line 130
    .line 131
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 132
    .line 133
    .line 134
    const-string v11, "<this>"

    .line 135
    .line 136
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    array-length v11, v9

    .line 140
    sub-int/2addr v11, v4

    .line 141
    if-ltz v11, :cond_21

    .line 142
    .line 143
    move v12, v2

    .line 144
    :goto_2
    aget-object v13, v9, v12

    .line 145
    .line 146
    invoke-virtual {v13}, Landroid/text/Annotation;->getKey()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v14

    .line 150
    const-string v15, "androidx.compose.text.SpanStyle"

    .line 151
    .line 152
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v14

    .line 156
    if-nez v14, :cond_6

    .line 157
    .line 158
    move-object/from16 p1, v0

    .line 159
    .line 160
    move/from16 p0, v2

    .line 161
    .line 162
    move-object v4, v6

    .line 163
    goto/16 :goto_10

    .line 164
    .line 165
    :cond_6
    invoke-interface {v6, v13}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 166
    .line 167
    .line 168
    move-result v14

    .line 169
    invoke-interface {v6, v13}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 170
    .line 171
    .line 172
    move-result v15

    .line 173
    move/from16 p0, v2

    .line 174
    .line 175
    new-instance v2, Lhu/q;

    .line 176
    .line 177
    invoke-virtual {v13}, Landroid/text/Annotation;->getValue()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v13

    .line 181
    invoke-direct {v2, v13}, Lhu/q;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    iget-object v13, v2, Lhu/q;->e:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast v13, Landroid/os/Parcel;

    .line 187
    .line 188
    sget-wide v16, Le3/s;->i:J

    .line 189
    .line 190
    sget-wide v18, Lt4/o;->c:J

    .line 191
    .line 192
    move-wide/from16 v21, v16

    .line 193
    .line 194
    move-wide/from16 v35, v21

    .line 195
    .line 196
    move-wide/from16 v23, v18

    .line 197
    .line 198
    move-wide/from16 v30, v23

    .line 199
    .line 200
    const/16 v25, 0x0

    .line 201
    .line 202
    const/16 v26, 0x0

    .line 203
    .line 204
    const/16 v27, 0x0

    .line 205
    .line 206
    const/16 v29, 0x0

    .line 207
    .line 208
    const/16 v32, 0x0

    .line 209
    .line 210
    const/16 v33, 0x0

    .line 211
    .line 212
    const/16 v37, 0x0

    .line 213
    .line 214
    const/16 v38, 0x0

    .line 215
    .line 216
    :goto_3
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 217
    .line 218
    .line 219
    move-result v7

    .line 220
    if-le v7, v4, :cond_7

    .line 221
    .line 222
    invoke-virtual {v13}, Landroid/os/Parcel;->readByte()B

    .line 223
    .line 224
    .line 225
    move-result v7

    .line 226
    const/16 v8, 0x8

    .line 227
    .line 228
    if-ne v7, v4, :cond_9

    .line 229
    .line 230
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 231
    .line 232
    .line 233
    move-result v7

    .line 234
    if-lt v7, v8, :cond_7

    .line 235
    .line 236
    invoke-virtual {v2}, Lhu/q;->u()J

    .line 237
    .line 238
    .line 239
    move-result-wide v21

    .line 240
    :goto_4
    const/4 v8, 0x2

    .line 241
    goto :goto_3

    .line 242
    :cond_7
    move-object/from16 p1, v0

    .line 243
    .line 244
    :cond_8
    move-object v4, v6

    .line 245
    goto/16 :goto_f

    .line 246
    .line 247
    :cond_9
    const/4 v8, 0x5

    .line 248
    const/4 v4, 0x2

    .line 249
    if-ne v7, v4, :cond_a

    .line 250
    .line 251
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 252
    .line 253
    .line 254
    move-result v4

    .line 255
    if-lt v4, v8, :cond_7

    .line 256
    .line 257
    invoke-virtual {v2}, Lhu/q;->v()J

    .line 258
    .line 259
    .line 260
    move-result-wide v23

    .line 261
    :goto_5
    const/4 v4, 0x1

    .line 262
    goto :goto_4

    .line 263
    :cond_a
    const/4 v4, 0x3

    .line 264
    const/4 v8, 0x4

    .line 265
    if-ne v7, v4, :cond_b

    .line 266
    .line 267
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 268
    .line 269
    .line 270
    move-result v4

    .line 271
    if-lt v4, v8, :cond_7

    .line 272
    .line 273
    new-instance v4, Lk4/x;

    .line 274
    .line 275
    invoke-virtual {v13}, Landroid/os/Parcel;->readInt()I

    .line 276
    .line 277
    .line 278
    move-result v7

    .line 279
    invoke-direct {v4, v7}, Lk4/x;-><init>(I)V

    .line 280
    .line 281
    .line 282
    move-object/from16 v25, v4

    .line 283
    .line 284
    goto :goto_5

    .line 285
    :cond_b
    if-ne v7, v8, :cond_e

    .line 286
    .line 287
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 288
    .line 289
    .line 290
    move-result v4

    .line 291
    const/4 v7, 0x1

    .line 292
    if-lt v4, v7, :cond_7

    .line 293
    .line 294
    invoke-virtual {v13}, Landroid/os/Parcel;->readByte()B

    .line 295
    .line 296
    .line 297
    move-result v4

    .line 298
    if-nez v4, :cond_d

    .line 299
    .line 300
    :cond_c
    move/from16 v4, p0

    .line 301
    .line 302
    goto :goto_6

    .line 303
    :cond_d
    if-ne v4, v7, :cond_c

    .line 304
    .line 305
    move v4, v7

    .line 306
    :goto_6
    new-instance v8, Lk4/t;

    .line 307
    .line 308
    invoke-direct {v8, v4}, Lk4/t;-><init>(I)V

    .line 309
    .line 310
    .line 311
    move v4, v7

    .line 312
    move-object/from16 v26, v8

    .line 313
    .line 314
    goto :goto_4

    .line 315
    :cond_e
    const/4 v4, 0x5

    .line 316
    const/4 v8, 0x1

    .line 317
    if-ne v7, v4, :cond_13

    .line 318
    .line 319
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 320
    .line 321
    .line 322
    move-result v4

    .line 323
    if-lt v4, v8, :cond_7

    .line 324
    .line 325
    invoke-virtual {v13}, Landroid/os/Parcel;->readByte()B

    .line 326
    .line 327
    .line 328
    move-result v4

    .line 329
    if-nez v4, :cond_f

    .line 330
    .line 331
    move/from16 v4, p0

    .line 332
    .line 333
    :goto_7
    const/4 v8, 0x2

    .line 334
    goto :goto_8

    .line 335
    :cond_f
    if-ne v4, v8, :cond_10

    .line 336
    .line 337
    const v4, 0xffff

    .line 338
    .line 339
    .line 340
    goto :goto_7

    .line 341
    :cond_10
    const/4 v7, 0x3

    .line 342
    if-ne v4, v7, :cond_11

    .line 343
    .line 344
    const/4 v4, 0x2

    .line 345
    goto :goto_7

    .line 346
    :cond_11
    const/4 v8, 0x2

    .line 347
    if-ne v4, v8, :cond_12

    .line 348
    .line 349
    const/4 v4, 0x1

    .line 350
    goto :goto_8

    .line 351
    :cond_12
    move/from16 v4, p0

    .line 352
    .line 353
    :goto_8
    new-instance v7, Lk4/u;

    .line 354
    .line 355
    invoke-direct {v7, v4}, Lk4/u;-><init>(I)V

    .line 356
    .line 357
    .line 358
    move-object/from16 v27, v7

    .line 359
    .line 360
    :goto_9
    const/4 v4, 0x1

    .line 361
    goto/16 :goto_3

    .line 362
    .line 363
    :cond_13
    const/4 v8, 0x2

    .line 364
    const/4 v4, 0x6

    .line 365
    if-ne v7, v4, :cond_14

    .line 366
    .line 367
    invoke-virtual {v13}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 368
    .line 369
    .line 370
    move-result-object v29

    .line 371
    goto :goto_9

    .line 372
    :cond_14
    const/4 v4, 0x7

    .line 373
    if-ne v7, v4, :cond_15

    .line 374
    .line 375
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 376
    .line 377
    .line 378
    move-result v4

    .line 379
    const/4 v7, 0x5

    .line 380
    if-lt v4, v7, :cond_7

    .line 381
    .line 382
    invoke-virtual {v2}, Lhu/q;->v()J

    .line 383
    .line 384
    .line 385
    move-result-wide v30

    .line 386
    goto :goto_9

    .line 387
    :cond_15
    const/16 v4, 0x8

    .line 388
    .line 389
    if-ne v7, v4, :cond_16

    .line 390
    .line 391
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 392
    .line 393
    .line 394
    move-result v4

    .line 395
    const/4 v7, 0x4

    .line 396
    if-lt v4, v7, :cond_7

    .line 397
    .line 398
    invoke-virtual {v13}, Landroid/os/Parcel;->readFloat()F

    .line 399
    .line 400
    .line 401
    move-result v4

    .line 402
    new-instance v7, Lr4/a;

    .line 403
    .line 404
    invoke-direct {v7, v4}, Lr4/a;-><init>(F)V

    .line 405
    .line 406
    .line 407
    move-object/from16 v32, v7

    .line 408
    .line 409
    goto :goto_9

    .line 410
    :cond_16
    const/16 v8, 0x9

    .line 411
    .line 412
    if-ne v7, v8, :cond_17

    .line 413
    .line 414
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 415
    .line 416
    .line 417
    move-result v7

    .line 418
    if-lt v7, v4, :cond_7

    .line 419
    .line 420
    new-instance v4, Lr4/p;

    .line 421
    .line 422
    invoke-virtual {v13}, Landroid/os/Parcel;->readFloat()F

    .line 423
    .line 424
    .line 425
    move-result v7

    .line 426
    invoke-virtual {v13}, Landroid/os/Parcel;->readFloat()F

    .line 427
    .line 428
    .line 429
    move-result v8

    .line 430
    invoke-direct {v4, v7, v8}, Lr4/p;-><init>(FF)V

    .line 431
    .line 432
    .line 433
    move-object/from16 v33, v4

    .line 434
    .line 435
    goto/16 :goto_5

    .line 436
    .line 437
    :cond_17
    const/16 v8, 0xa

    .line 438
    .line 439
    if-ne v7, v8, :cond_18

    .line 440
    .line 441
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 442
    .line 443
    .line 444
    move-result v7

    .line 445
    if-lt v7, v4, :cond_7

    .line 446
    .line 447
    invoke-virtual {v2}, Lhu/q;->u()J

    .line 448
    .line 449
    .line 450
    move-result-wide v35

    .line 451
    goto/16 :goto_5

    .line 452
    .line 453
    :cond_18
    const/16 v4, 0xb

    .line 454
    .line 455
    if-ne v7, v4, :cond_20

    .line 456
    .line 457
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 458
    .line 459
    .line 460
    move-result v4

    .line 461
    const/4 v7, 0x4

    .line 462
    if-lt v4, v7, :cond_7

    .line 463
    .line 464
    invoke-virtual {v13}, Landroid/os/Parcel;->readInt()I

    .line 465
    .line 466
    .line 467
    move-result v4

    .line 468
    and-int/lit8 v7, v4, 0x2

    .line 469
    .line 470
    if-eqz v7, :cond_19

    .line 471
    .line 472
    const/4 v7, 0x1

    .line 473
    goto :goto_a

    .line 474
    :cond_19
    move/from16 v7, p0

    .line 475
    .line 476
    :goto_a
    and-int/lit8 v4, v4, 0x1

    .line 477
    .line 478
    if-eqz v4, :cond_1a

    .line 479
    .line 480
    const/4 v4, 0x1

    .line 481
    goto :goto_b

    .line 482
    :cond_1a
    move/from16 v4, p0

    .line 483
    .line 484
    :goto_b
    sget-object v8, Lr4/l;->d:Lr4/l;

    .line 485
    .line 486
    move-object/from16 p1, v0

    .line 487
    .line 488
    sget-object v0, Lr4/l;->c:Lr4/l;

    .line 489
    .line 490
    if-eqz v7, :cond_1c

    .line 491
    .line 492
    if-eqz v4, :cond_1c

    .line 493
    .line 494
    filled-new-array {v8, v0}, [Lr4/l;

    .line 495
    .line 496
    .line 497
    move-result-object v0

    .line 498
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 499
    .line 500
    .line 501
    move-result-object v0

    .line 502
    invoke-static/range {p0 .. p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 503
    .line 504
    .line 505
    move-result-object v4

    .line 506
    move-object v7, v0

    .line 507
    check-cast v7, Ljava/util/Collection;

    .line 508
    .line 509
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 510
    .line 511
    .line 512
    move-result v7

    .line 513
    move/from16 v8, p0

    .line 514
    .line 515
    :goto_c
    if-ge v8, v7, :cond_1b

    .line 516
    .line 517
    invoke-interface {v0, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    move-result-object v19

    .line 521
    move-object/from16 v20, v0

    .line 522
    .line 523
    move-object/from16 v0, v19

    .line 524
    .line 525
    check-cast v0, Lr4/l;

    .line 526
    .line 527
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 528
    .line 529
    .line 530
    move-result v4

    .line 531
    iget v0, v0, Lr4/l;->a:I

    .line 532
    .line 533
    or-int/2addr v0, v4

    .line 534
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 535
    .line 536
    .line 537
    move-result-object v4

    .line 538
    add-int/lit8 v8, v8, 0x1

    .line 539
    .line 540
    move-object/from16 v0, v20

    .line 541
    .line 542
    goto :goto_c

    .line 543
    :cond_1b
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 544
    .line 545
    .line 546
    move-result v0

    .line 547
    new-instance v4, Lr4/l;

    .line 548
    .line 549
    invoke-direct {v4, v0}, Lr4/l;-><init>(I)V

    .line 550
    .line 551
    .line 552
    move-object/from16 v37, v4

    .line 553
    .line 554
    goto :goto_e

    .line 555
    :cond_1c
    if-eqz v7, :cond_1d

    .line 556
    .line 557
    move-object/from16 v37, v8

    .line 558
    .line 559
    goto :goto_e

    .line 560
    :cond_1d
    if-eqz v4, :cond_1e

    .line 561
    .line 562
    :goto_d
    move-object/from16 v37, v0

    .line 563
    .line 564
    goto :goto_e

    .line 565
    :cond_1e
    sget-object v0, Lr4/l;->b:Lr4/l;

    .line 566
    .line 567
    goto :goto_d

    .line 568
    :cond_1f
    :goto_e
    move-object/from16 v0, p1

    .line 569
    .line 570
    goto/16 :goto_5

    .line 571
    .line 572
    :cond_20
    move-object/from16 p1, v0

    .line 573
    .line 574
    const/16 v0, 0xc

    .line 575
    .line 576
    if-ne v7, v0, :cond_1f

    .line 577
    .line 578
    invoke-virtual {v13}, Landroid/os/Parcel;->dataAvail()I

    .line 579
    .line 580
    .line 581
    move-result v0

    .line 582
    const/16 v4, 0x14

    .line 583
    .line 584
    if-lt v0, v4, :cond_8

    .line 585
    .line 586
    new-instance v39, Le3/m0;

    .line 587
    .line 588
    invoke-virtual {v2}, Lhu/q;->u()J

    .line 589
    .line 590
    .line 591
    move-result-wide v40

    .line 592
    invoke-virtual {v13}, Landroid/os/Parcel;->readFloat()F

    .line 593
    .line 594
    .line 595
    move-result v0

    .line 596
    invoke-virtual {v13}, Landroid/os/Parcel;->readFloat()F

    .line 597
    .line 598
    .line 599
    move-result v4

    .line 600
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 601
    .line 602
    .line 603
    move-result v0

    .line 604
    int-to-long v7, v0

    .line 605
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 606
    .line 607
    .line 608
    move-result v0

    .line 609
    move-object v4, v6

    .line 610
    move-wide/from16 v19, v7

    .line 611
    .line 612
    int-to-long v6, v0

    .line 613
    const/16 v0, 0x20

    .line 614
    .line 615
    shl-long v19, v19, v0

    .line 616
    .line 617
    const-wide v42, 0xffffffffL

    .line 618
    .line 619
    .line 620
    .line 621
    .line 622
    and-long v6, v6, v42

    .line 623
    .line 624
    or-long v42, v19, v6

    .line 625
    .line 626
    invoke-virtual {v13}, Landroid/os/Parcel;->readFloat()F

    .line 627
    .line 628
    .line 629
    move-result v44

    .line 630
    invoke-direct/range {v39 .. v44}, Le3/m0;-><init>(JJF)V

    .line 631
    .line 632
    .line 633
    move-object/from16 v0, p1

    .line 634
    .line 635
    move-object v6, v4

    .line 636
    move-object/from16 v38, v39

    .line 637
    .line 638
    goto/16 :goto_5

    .line 639
    .line 640
    :goto_f
    new-instance v20, Lg4/g0;

    .line 641
    .line 642
    const v39, 0xc000

    .line 643
    .line 644
    .line 645
    const/16 v28, 0x0

    .line 646
    .line 647
    const/16 v34, 0x0

    .line 648
    .line 649
    invoke-direct/range {v20 .. v39}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 650
    .line 651
    .line 652
    move-object/from16 v0, v20

    .line 653
    .line 654
    new-instance v2, Lg4/e;

    .line 655
    .line 656
    invoke-direct {v2, v0, v14, v15}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    .line 657
    .line 658
    .line 659
    invoke-virtual {v10, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 660
    .line 661
    .line 662
    :goto_10
    if-eq v12, v11, :cond_22

    .line 663
    .line 664
    add-int/lit8 v12, v12, 0x1

    .line 665
    .line 666
    move/from16 v2, p0

    .line 667
    .line 668
    move-object/from16 v0, p1

    .line 669
    .line 670
    move-object v6, v4

    .line 671
    const/4 v4, 0x1

    .line 672
    const/4 v8, 0x2

    .line 673
    goto/16 :goto_2

    .line 674
    .line 675
    :cond_21
    move-object/from16 p1, v0

    .line 676
    .line 677
    :cond_22
    new-instance v0, Lg4/g;

    .line 678
    .line 679
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 680
    .line 681
    .line 682
    move-result-object v2

    .line 683
    sget-object v4, Lg4/h;->a:Lg4/g;

    .line 684
    .line 685
    invoke-virtual {v10}, Ljava/util/ArrayList;->isEmpty()Z

    .line 686
    .line 687
    .line 688
    move-result v4

    .line 689
    if-eqz v4, :cond_23

    .line 690
    .line 691
    const/4 v7, 0x0

    .line 692
    goto :goto_11

    .line 693
    :cond_23
    move-object v7, v10

    .line 694
    :goto_11
    invoke-direct {v0, v7, v2}, Lg4/g;-><init>(Ljava/util/List;Ljava/lang/String;)V

    .line 695
    .line 696
    .line 697
    goto :goto_12

    .line 698
    :cond_24
    const/4 v0, 0x0

    .line 699
    :goto_12
    if-ne v0, v1, :cond_25

    .line 700
    .line 701
    :goto_13
    move-object v5, v1

    .line 702
    goto :goto_15

    .line 703
    :cond_25
    :goto_14
    check-cast v0, Lg4/g;

    .line 704
    .line 705
    if-nez v0, :cond_26

    .line 706
    .line 707
    goto :goto_15

    .line 708
    :cond_26
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 709
    .line 710
    .line 711
    move-result-object v1

    .line 712
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 713
    .line 714
    .line 715
    move-result-object v2

    .line 716
    iget-object v2, v2, Ll4/v;->a:Lg4/g;

    .line 717
    .line 718
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 719
    .line 720
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 721
    .line 722
    .line 723
    move-result v2

    .line 724
    invoke-static {v1, v2}, Llp/re;->d(Ll4/v;I)Lg4/g;

    .line 725
    .line 726
    .line 727
    move-result-object v1

    .line 728
    new-instance v2, Lg4/d;

    .line 729
    .line 730
    invoke-direct {v2, v1}, Lg4/d;-><init>(Lg4/g;)V

    .line 731
    .line 732
    .line 733
    invoke-virtual {v2, v0}, Lg4/d;->c(Lg4/g;)V

    .line 734
    .line 735
    .line 736
    invoke-virtual {v2}, Lg4/d;->j()Lg4/g;

    .line 737
    .line 738
    .line 739
    move-result-object v1

    .line 740
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 741
    .line 742
    .line 743
    move-result-object v2

    .line 744
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 745
    .line 746
    .line 747
    move-result-object v4

    .line 748
    iget-object v4, v4, Ll4/v;->a:Lg4/g;

    .line 749
    .line 750
    iget-object v4, v4, Lg4/g;->e:Ljava/lang/String;

    .line 751
    .line 752
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 753
    .line 754
    .line 755
    move-result v4

    .line 756
    invoke-static {v2, v4}, Llp/re;->c(Ll4/v;I)Lg4/g;

    .line 757
    .line 758
    .line 759
    move-result-object v2

    .line 760
    new-instance v4, Lg4/d;

    .line 761
    .line 762
    invoke-direct {v4, v1}, Lg4/d;-><init>(Lg4/g;)V

    .line 763
    .line 764
    .line 765
    invoke-virtual {v4, v2}, Lg4/d;->c(Lg4/g;)V

    .line 766
    .line 767
    .line 768
    invoke-virtual {v4}, Lg4/d;->j()Lg4/g;

    .line 769
    .line 770
    .line 771
    move-result-object v1

    .line 772
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 773
    .line 774
    .line 775
    move-result-object v2

    .line 776
    iget-wide v6, v2, Ll4/v;->b:J

    .line 777
    .line 778
    invoke-static {v6, v7}, Lg4/o0;->f(J)I

    .line 779
    .line 780
    .line 781
    move-result v2

    .line 782
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 783
    .line 784
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 785
    .line 786
    .line 787
    move-result v0

    .line 788
    add-int/2addr v0, v2

    .line 789
    invoke-static {v0, v0}, Lg4/f0;->b(II)J

    .line 790
    .line 791
    .line 792
    move-result-wide v6

    .line 793
    invoke-static {v1, v6, v7}, Le2/w0;->e(Lg4/g;J)Ll4/v;

    .line 794
    .line 795
    .line 796
    move-result-object v0

    .line 797
    iget-object v1, v3, Le2/w0;->c:Lay0/k;

    .line 798
    .line 799
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 800
    .line 801
    .line 802
    iget-wide v0, v0, Ll4/v;->b:J

    .line 803
    .line 804
    new-instance v2, Lg4/o0;

    .line 805
    .line 806
    invoke-direct {v2, v0, v1}, Lg4/o0;-><init>(J)V

    .line 807
    .line 808
    .line 809
    iput-object v2, v3, Le2/w0;->v:Lg4/o0;

    .line 810
    .line 811
    sget-object v0, Lt1/c0;->d:Lt1/c0;

    .line 812
    .line 813
    invoke-virtual {v3, v0}, Le2/w0;->p(Lt1/c0;)V

    .line 814
    .line 815
    .line 816
    iget-object v0, v3, Le2/w0;->a:Lt1/n1;

    .line 817
    .line 818
    const/4 v7, 0x1

    .line 819
    iput-boolean v7, v0, Lt1/n1;->e:Z

    .line 820
    .line 821
    :cond_27
    :goto_15
    return-object v5

    .line 822
    :pswitch_0
    move v7, v4

    .line 823
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 824
    .line 825
    iget v4, v0, Le2/r0;->e:I

    .line 826
    .line 827
    if-eqz v4, :cond_29

    .line 828
    .line 829
    if-ne v4, v7, :cond_28

    .line 830
    .line 831
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 832
    .line 833
    .line 834
    goto :goto_16

    .line 835
    :cond_28
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 836
    .line 837
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 838
    .line 839
    .line 840
    throw v0

    .line 841
    :cond_29
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 842
    .line 843
    .line 844
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 845
    .line 846
    .line 847
    move-result-object v2

    .line 848
    iget-wide v6, v2, Ll4/v;->b:J

    .line 849
    .line 850
    invoke-static {v6, v7}, Lg4/o0;->c(J)Z

    .line 851
    .line 852
    .line 853
    move-result v2

    .line 854
    if-eqz v2, :cond_2a

    .line 855
    .line 856
    goto/16 :goto_17

    .line 857
    .line 858
    :cond_2a
    iget-object v2, v3, Le2/w0;->g:Lw3/c1;

    .line 859
    .line 860
    if-eqz v2, :cond_2b

    .line 861
    .line 862
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 863
    .line 864
    .line 865
    move-result-object v4

    .line 866
    invoke-static {v4}, Llp/re;->b(Ll4/v;)Lg4/g;

    .line 867
    .line 868
    .line 869
    move-result-object v4

    .line 870
    invoke-static {v4}, Lj1/d;->a(Lg4/g;)Lw3/b1;

    .line 871
    .line 872
    .line 873
    move-result-object v4

    .line 874
    const/4 v7, 0x1

    .line 875
    iput v7, v0, Le2/r0;->e:I

    .line 876
    .line 877
    check-cast v2, Lw3/h;

    .line 878
    .line 879
    iget-object v0, v2, Lw3/h;->a:Lw3/i;

    .line 880
    .line 881
    iget-object v0, v0, Lw3/i;->a:Landroid/content/ClipboardManager;

    .line 882
    .line 883
    iget-object v2, v4, Lw3/b1;->a:Landroid/content/ClipData;

    .line 884
    .line 885
    invoke-virtual {v0, v2}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V

    .line 886
    .line 887
    .line 888
    if-ne v5, v1, :cond_2b

    .line 889
    .line 890
    move-object v5, v1

    .line 891
    goto :goto_17

    .line 892
    :cond_2b
    :goto_16
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 893
    .line 894
    .line 895
    move-result-object v0

    .line 896
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 897
    .line 898
    .line 899
    move-result-object v1

    .line 900
    iget-object v1, v1, Ll4/v;->a:Lg4/g;

    .line 901
    .line 902
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 903
    .line 904
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 905
    .line 906
    .line 907
    move-result v1

    .line 908
    invoke-static {v0, v1}, Llp/re;->d(Ll4/v;I)Lg4/g;

    .line 909
    .line 910
    .line 911
    move-result-object v0

    .line 912
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 913
    .line 914
    .line 915
    move-result-object v1

    .line 916
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 917
    .line 918
    .line 919
    move-result-object v2

    .line 920
    iget-object v2, v2, Ll4/v;->a:Lg4/g;

    .line 921
    .line 922
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 923
    .line 924
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 925
    .line 926
    .line 927
    move-result v2

    .line 928
    invoke-static {v1, v2}, Llp/re;->c(Ll4/v;I)Lg4/g;

    .line 929
    .line 930
    .line 931
    move-result-object v1

    .line 932
    new-instance v2, Lg4/d;

    .line 933
    .line 934
    invoke-direct {v2, v0}, Lg4/d;-><init>(Lg4/g;)V

    .line 935
    .line 936
    .line 937
    invoke-virtual {v2, v1}, Lg4/d;->c(Lg4/g;)V

    .line 938
    .line 939
    .line 940
    invoke-virtual {v2}, Lg4/d;->j()Lg4/g;

    .line 941
    .line 942
    .line 943
    move-result-object v0

    .line 944
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 945
    .line 946
    .line 947
    move-result-object v1

    .line 948
    iget-wide v1, v1, Ll4/v;->b:J

    .line 949
    .line 950
    invoke-static {v1, v2}, Lg4/o0;->f(J)I

    .line 951
    .line 952
    .line 953
    move-result v1

    .line 954
    invoke-static {v1, v1}, Lg4/f0;->b(II)J

    .line 955
    .line 956
    .line 957
    move-result-wide v1

    .line 958
    invoke-static {v0, v1, v2}, Le2/w0;->e(Lg4/g;J)Ll4/v;

    .line 959
    .line 960
    .line 961
    move-result-object v0

    .line 962
    iget-object v1, v3, Le2/w0;->c:Lay0/k;

    .line 963
    .line 964
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 965
    .line 966
    .line 967
    iget-wide v0, v0, Ll4/v;->b:J

    .line 968
    .line 969
    new-instance v2, Lg4/o0;

    .line 970
    .line 971
    invoke-direct {v2, v0, v1}, Lg4/o0;-><init>(J)V

    .line 972
    .line 973
    .line 974
    iput-object v2, v3, Le2/w0;->v:Lg4/o0;

    .line 975
    .line 976
    sget-object v0, Lt1/c0;->d:Lt1/c0;

    .line 977
    .line 978
    invoke-virtual {v3, v0}, Le2/w0;->p(Lt1/c0;)V

    .line 979
    .line 980
    .line 981
    iget-object v0, v3, Le2/w0;->a:Lt1/n1;

    .line 982
    .line 983
    const/4 v7, 0x1

    .line 984
    iput-boolean v7, v0, Lt1/n1;->e:Z

    .line 985
    .line 986
    :goto_17
    return-object v5

    .line 987
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

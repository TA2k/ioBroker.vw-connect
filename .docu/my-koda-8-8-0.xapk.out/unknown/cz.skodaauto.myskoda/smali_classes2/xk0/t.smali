.class public final synthetic Lxk0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lxk0/t;->d:I

    iput-object p1, p0, Lxk0/t;->e:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;II)V
    .locals 0

    .line 2
    iput p3, p0, Lxk0/t;->d:I

    iput-object p1, p0, Lxk0/t;->e:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lxk0/t;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Lz70/l;->n(Lay0/a;Ll2/o;I)V

    .line 21
    .line 22
    .line 23
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    and-int/lit8 v0, p2, 0x3

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    const/4 v2, 0x0

    .line 34
    const/4 v3, 0x1

    .line 35
    if-eq v0, v1, :cond_0

    .line 36
    .line 37
    move v0, v3

    .line 38
    goto :goto_1

    .line 39
    :cond_0
    move v0, v2

    .line 40
    :goto_1
    and-int/2addr p2, v3

    .line 41
    check-cast p1, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    if-eqz p2, :cond_1

    .line 48
    .line 49
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 50
    .line 51
    invoke-static {p0, p1, v2}, Lz70/l;->n(Lay0/a;Ll2/o;I)V

    .line 52
    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 56
    .line 57
    .line 58
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    return-object p0

    .line 61
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    and-int/lit8 v0, p2, 0x3

    .line 66
    .line 67
    const/4 v1, 0x2

    .line 68
    const/4 v2, 0x1

    .line 69
    if-eq v0, v1, :cond_2

    .line 70
    .line 71
    move v0, v2

    .line 72
    goto :goto_3

    .line 73
    :cond_2
    const/4 v0, 0x0

    .line 74
    :goto_3
    and-int/2addr p2, v2

    .line 75
    move-object v8, p1

    .line 76
    check-cast v8, Ll2/t;

    .line 77
    .line 78
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    if-eqz p1, :cond_3

    .line 83
    .line 84
    new-instance v4, Li91/x2;

    .line 85
    .line 86
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 87
    .line 88
    const/4 p1, 0x3

    .line 89
    invoke-direct {v4, p0, p1}, Li91/x2;-><init>(Lay0/a;I)V

    .line 90
    .line 91
    .line 92
    const/4 v9, 0x0

    .line 93
    const/16 v10, 0x3bf

    .line 94
    .line 95
    const/4 v1, 0x0

    .line 96
    const/4 v2, 0x0

    .line 97
    const/4 v3, 0x0

    .line 98
    const/4 v5, 0x0

    .line 99
    const/4 v6, 0x0

    .line 100
    const/4 v7, 0x0

    .line 101
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 102
    .line 103
    .line 104
    goto :goto_4

    .line 105
    :cond_3
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 106
    .line 107
    .line 108
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object p0

    .line 111
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 112
    .line 113
    .line 114
    move-result p2

    .line 115
    and-int/lit8 v0, p2, 0x3

    .line 116
    .line 117
    const/4 v1, 0x2

    .line 118
    const/4 v2, 0x1

    .line 119
    if-eq v0, v1, :cond_4

    .line 120
    .line 121
    move v0, v2

    .line 122
    goto :goto_5

    .line 123
    :cond_4
    const/4 v0, 0x0

    .line 124
    :goto_5
    and-int/2addr p2, v2

    .line 125
    move-object v8, p1

    .line 126
    check-cast v8, Ll2/t;

    .line 127
    .line 128
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    if-eqz p1, :cond_5

    .line 133
    .line 134
    const p1, 0x7f1211a7

    .line 135
    .line 136
    .line 137
    invoke-static {v8, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    new-instance v4, Li91/w2;

    .line 142
    .line 143
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 144
    .line 145
    const/4 p1, 0x3

    .line 146
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 147
    .line 148
    .line 149
    const/4 v9, 0x0

    .line 150
    const/16 v10, 0x3bd

    .line 151
    .line 152
    const/4 v1, 0x0

    .line 153
    const/4 v3, 0x0

    .line 154
    const/4 v5, 0x0

    .line 155
    const/4 v6, 0x0

    .line 156
    const/4 v7, 0x0

    .line 157
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 158
    .line 159
    .line 160
    goto :goto_6

    .line 161
    :cond_5
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 162
    .line 163
    .line 164
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 168
    .line 169
    .line 170
    move-result p2

    .line 171
    and-int/lit8 v0, p2, 0x3

    .line 172
    .line 173
    const/4 v1, 0x2

    .line 174
    const/4 v2, 0x1

    .line 175
    if-eq v0, v1, :cond_6

    .line 176
    .line 177
    move v0, v2

    .line 178
    goto :goto_7

    .line 179
    :cond_6
    const/4 v0, 0x0

    .line 180
    :goto_7
    and-int/2addr p2, v2

    .line 181
    move-object v8, p1

    .line 182
    check-cast v8, Ll2/t;

    .line 183
    .line 184
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 185
    .line 186
    .line 187
    move-result p1

    .line 188
    if-eqz p1, :cond_7

    .line 189
    .line 190
    const p1, 0x7f12116b

    .line 191
    .line 192
    .line 193
    invoke-static {v8, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    new-instance v4, Li91/w2;

    .line 198
    .line 199
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 200
    .line 201
    const/4 p1, 0x3

    .line 202
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 203
    .line 204
    .line 205
    const/4 v9, 0x0

    .line 206
    const/16 v10, 0x3bd

    .line 207
    .line 208
    const/4 v1, 0x0

    .line 209
    const/4 v3, 0x0

    .line 210
    const/4 v5, 0x0

    .line 211
    const/4 v6, 0x0

    .line 212
    const/4 v7, 0x0

    .line 213
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 214
    .line 215
    .line 216
    goto :goto_8

    .line 217
    :cond_7
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 218
    .line 219
    .line 220
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 221
    .line 222
    return-object p0

    .line 223
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 224
    .line 225
    .line 226
    move-result p2

    .line 227
    and-int/lit8 v0, p2, 0x3

    .line 228
    .line 229
    const/4 v1, 0x2

    .line 230
    const/4 v2, 0x1

    .line 231
    if-eq v0, v1, :cond_8

    .line 232
    .line 233
    move v0, v2

    .line 234
    goto :goto_9

    .line 235
    :cond_8
    const/4 v0, 0x0

    .line 236
    :goto_9
    and-int/2addr p2, v2

    .line 237
    move-object v8, p1

    .line 238
    check-cast v8, Ll2/t;

    .line 239
    .line 240
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 241
    .line 242
    .line 243
    move-result p1

    .line 244
    if-eqz p1, :cond_9

    .line 245
    .line 246
    const p1, 0x7f121169

    .line 247
    .line 248
    .line 249
    invoke-static {v8, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 250
    .line 251
    .line 252
    move-result-object v2

    .line 253
    new-instance v4, Li91/w2;

    .line 254
    .line 255
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 256
    .line 257
    const/4 p1, 0x3

    .line 258
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 259
    .line 260
    .line 261
    const/4 v9, 0x0

    .line 262
    const/16 v10, 0x3bd

    .line 263
    .line 264
    const/4 v1, 0x0

    .line 265
    const/4 v3, 0x0

    .line 266
    const/4 v5, 0x0

    .line 267
    const/4 v6, 0x0

    .line 268
    const/4 v7, 0x0

    .line 269
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 270
    .line 271
    .line 272
    goto :goto_a

    .line 273
    :cond_9
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 274
    .line 275
    .line 276
    :goto_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 277
    .line 278
    return-object p0

    .line 279
    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 280
    .line 281
    .line 282
    move-result p2

    .line 283
    and-int/lit8 v0, p2, 0x3

    .line 284
    .line 285
    const/4 v1, 0x2

    .line 286
    const/4 v2, 0x1

    .line 287
    if-eq v0, v1, :cond_a

    .line 288
    .line 289
    move v0, v2

    .line 290
    goto :goto_b

    .line 291
    :cond_a
    const/4 v0, 0x0

    .line 292
    :goto_b
    and-int/2addr p2, v2

    .line 293
    move-object v8, p1

    .line 294
    check-cast v8, Ll2/t;

    .line 295
    .line 296
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 297
    .line 298
    .line 299
    move-result p1

    .line 300
    if-eqz p1, :cond_b

    .line 301
    .line 302
    new-instance v4, Li91/x2;

    .line 303
    .line 304
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 305
    .line 306
    const/4 p1, 0x3

    .line 307
    invoke-direct {v4, p0, p1}, Li91/x2;-><init>(Lay0/a;I)V

    .line 308
    .line 309
    .line 310
    const/4 v9, 0x0

    .line 311
    const/16 v10, 0x3bf

    .line 312
    .line 313
    const/4 v1, 0x0

    .line 314
    const/4 v2, 0x0

    .line 315
    const/4 v3, 0x0

    .line 316
    const/4 v5, 0x0

    .line 317
    const/4 v6, 0x0

    .line 318
    const/4 v7, 0x0

    .line 319
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 320
    .line 321
    .line 322
    goto :goto_c

    .line 323
    :cond_b
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 324
    .line 325
    .line 326
    :goto_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 327
    .line 328
    return-object p0

    .line 329
    :pswitch_6
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 330
    .line 331
    .line 332
    move-result p2

    .line 333
    and-int/lit8 v0, p2, 0x3

    .line 334
    .line 335
    const/4 v1, 0x2

    .line 336
    const/4 v2, 0x1

    .line 337
    if-eq v0, v1, :cond_c

    .line 338
    .line 339
    move v0, v2

    .line 340
    goto :goto_d

    .line 341
    :cond_c
    const/4 v0, 0x0

    .line 342
    :goto_d
    and-int/2addr p2, v2

    .line 343
    move-object v8, p1

    .line 344
    check-cast v8, Ll2/t;

    .line 345
    .line 346
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 347
    .line 348
    .line 349
    move-result p1

    .line 350
    if-eqz p1, :cond_d

    .line 351
    .line 352
    const p1, 0x7f12116a

    .line 353
    .line 354
    .line 355
    invoke-static {v8, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    new-instance v4, Li91/x2;

    .line 360
    .line 361
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 362
    .line 363
    const/4 p1, 0x3

    .line 364
    invoke-direct {v4, p0, p1}, Li91/x2;-><init>(Lay0/a;I)V

    .line 365
    .line 366
    .line 367
    const/4 v9, 0x0

    .line 368
    const/16 v10, 0x3bd

    .line 369
    .line 370
    const/4 v1, 0x0

    .line 371
    const/4 v3, 0x0

    .line 372
    const/4 v5, 0x0

    .line 373
    const/4 v6, 0x0

    .line 374
    const/4 v7, 0x0

    .line 375
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 376
    .line 377
    .line 378
    goto :goto_e

    .line 379
    :cond_d
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 380
    .line 381
    .line 382
    :goto_e
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 383
    .line 384
    return-object p0

    .line 385
    :pswitch_7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 386
    .line 387
    .line 388
    move-result p2

    .line 389
    and-int/lit8 v0, p2, 0x3

    .line 390
    .line 391
    const/4 v1, 0x2

    .line 392
    const/4 v2, 0x1

    .line 393
    if-eq v0, v1, :cond_e

    .line 394
    .line 395
    move v0, v2

    .line 396
    goto :goto_f

    .line 397
    :cond_e
    const/4 v0, 0x0

    .line 398
    :goto_f
    and-int/2addr p2, v2

    .line 399
    move-object v8, p1

    .line 400
    check-cast v8, Ll2/t;

    .line 401
    .line 402
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 403
    .line 404
    .line 405
    move-result p1

    .line 406
    if-eqz p1, :cond_f

    .line 407
    .line 408
    const p1, 0x7f12035a

    .line 409
    .line 410
    .line 411
    invoke-static {v8, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 412
    .line 413
    .line 414
    move-result-object v2

    .line 415
    new-instance v4, Li91/w2;

    .line 416
    .line 417
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 418
    .line 419
    const/4 p1, 0x3

    .line 420
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 421
    .line 422
    .line 423
    const/4 v9, 0x0

    .line 424
    const/16 v10, 0x3bd

    .line 425
    .line 426
    const/4 v1, 0x0

    .line 427
    const/4 v3, 0x0

    .line 428
    const/4 v5, 0x0

    .line 429
    const/4 v6, 0x0

    .line 430
    const/4 v7, 0x0

    .line 431
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 432
    .line 433
    .line 434
    goto :goto_10

    .line 435
    :cond_f
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 436
    .line 437
    .line 438
    :goto_10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 439
    .line 440
    return-object p0

    .line 441
    :pswitch_8
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 442
    .line 443
    .line 444
    const/4 p2, 0x1

    .line 445
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 446
    .line 447
    .line 448
    move-result p2

    .line 449
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 450
    .line 451
    invoke-static {p0, p1, p2}, Lz10/a;->k(Lay0/a;Ll2/o;I)V

    .line 452
    .line 453
    .line 454
    goto/16 :goto_0

    .line 455
    .line 456
    :pswitch_9
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 457
    .line 458
    .line 459
    move-result p2

    .line 460
    and-int/lit8 v0, p2, 0x3

    .line 461
    .line 462
    const/4 v1, 0x2

    .line 463
    const/4 v2, 0x1

    .line 464
    if-eq v0, v1, :cond_10

    .line 465
    .line 466
    move v0, v2

    .line 467
    goto :goto_11

    .line 468
    :cond_10
    const/4 v0, 0x0

    .line 469
    :goto_11
    and-int/2addr p2, v2

    .line 470
    move-object v8, p1

    .line 471
    check-cast v8, Ll2/t;

    .line 472
    .line 473
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 474
    .line 475
    .line 476
    move-result p1

    .line 477
    if-eqz p1, :cond_11

    .line 478
    .line 479
    const p1, 0x7f120f21

    .line 480
    .line 481
    .line 482
    invoke-static {v8, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 483
    .line 484
    .line 485
    move-result-object v2

    .line 486
    new-instance v4, Li91/w2;

    .line 487
    .line 488
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 489
    .line 490
    const/4 p1, 0x3

    .line 491
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 492
    .line 493
    .line 494
    const/4 v9, 0x0

    .line 495
    const/16 v10, 0x3bd

    .line 496
    .line 497
    const/4 v1, 0x0

    .line 498
    const/4 v3, 0x0

    .line 499
    const/4 v5, 0x0

    .line 500
    const/4 v6, 0x0

    .line 501
    const/4 v7, 0x0

    .line 502
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 503
    .line 504
    .line 505
    goto :goto_12

    .line 506
    :cond_11
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 507
    .line 508
    .line 509
    :goto_12
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 510
    .line 511
    return-object p0

    .line 512
    :pswitch_a
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 513
    .line 514
    .line 515
    move-result p2

    .line 516
    and-int/lit8 v0, p2, 0x3

    .line 517
    .line 518
    const/4 v1, 0x2

    .line 519
    const/4 v2, 0x1

    .line 520
    if-eq v0, v1, :cond_12

    .line 521
    .line 522
    move v0, v2

    .line 523
    goto :goto_13

    .line 524
    :cond_12
    const/4 v0, 0x0

    .line 525
    :goto_13
    and-int/2addr p2, v2

    .line 526
    move-object v8, p1

    .line 527
    check-cast v8, Ll2/t;

    .line 528
    .line 529
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 530
    .line 531
    .line 532
    move-result p1

    .line 533
    if-eqz p1, :cond_13

    .line 534
    .line 535
    const p1, 0x7f120ec4

    .line 536
    .line 537
    .line 538
    invoke-static {v8, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 539
    .line 540
    .line 541
    move-result-object v2

    .line 542
    new-instance v4, Li91/w2;

    .line 543
    .line 544
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 545
    .line 546
    const/4 p1, 0x3

    .line 547
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 548
    .line 549
    .line 550
    const/4 v9, 0x0

    .line 551
    const/16 v10, 0x3bd

    .line 552
    .line 553
    const/4 v1, 0x0

    .line 554
    const/4 v3, 0x0

    .line 555
    const/4 v5, 0x0

    .line 556
    const/4 v6, 0x0

    .line 557
    const/4 v7, 0x0

    .line 558
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 559
    .line 560
    .line 561
    goto :goto_14

    .line 562
    :cond_13
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 563
    .line 564
    .line 565
    :goto_14
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 566
    .line 567
    return-object p0

    .line 568
    :pswitch_b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 569
    .line 570
    .line 571
    const/4 p2, 0x1

    .line 572
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 573
    .line 574
    .line 575
    move-result p2

    .line 576
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 577
    .line 578
    invoke-static {p0, p1, p2}, Lxk0/h;->c(Lay0/a;Ll2/o;I)V

    .line 579
    .line 580
    .line 581
    goto/16 :goto_0

    .line 582
    .line 583
    :pswitch_c
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 584
    .line 585
    .line 586
    move-result p2

    .line 587
    and-int/lit8 v0, p2, 0x3

    .line 588
    .line 589
    const/4 v1, 0x2

    .line 590
    const/4 v2, 0x1

    .line 591
    if-eq v0, v1, :cond_14

    .line 592
    .line 593
    move v0, v2

    .line 594
    goto :goto_15

    .line 595
    :cond_14
    const/4 v0, 0x0

    .line 596
    :goto_15
    and-int/2addr p2, v2

    .line 597
    move-object v8, p1

    .line 598
    check-cast v8, Ll2/t;

    .line 599
    .line 600
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 601
    .line 602
    .line 603
    move-result p1

    .line 604
    if-eqz p1, :cond_15

    .line 605
    .line 606
    new-instance v4, Li91/x2;

    .line 607
    .line 608
    iget-object p0, p0, Lxk0/t;->e:Lay0/a;

    .line 609
    .line 610
    const/4 p1, 0x3

    .line 611
    invoke-direct {v4, p0, p1}, Li91/x2;-><init>(Lay0/a;I)V

    .line 612
    .line 613
    .line 614
    const/4 v9, 0x0

    .line 615
    const/16 v10, 0x3bf

    .line 616
    .line 617
    const/4 v1, 0x0

    .line 618
    const/4 v2, 0x0

    .line 619
    const/4 v3, 0x0

    .line 620
    const/4 v5, 0x0

    .line 621
    const/4 v6, 0x0

    .line 622
    const/4 v7, 0x0

    .line 623
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 624
    .line 625
    .line 626
    goto :goto_16

    .line 627
    :cond_15
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 628
    .line 629
    .line 630
    :goto_16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 631
    .line 632
    return-object p0

    .line 633
    :pswitch_data_0
    .packed-switch 0x0
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

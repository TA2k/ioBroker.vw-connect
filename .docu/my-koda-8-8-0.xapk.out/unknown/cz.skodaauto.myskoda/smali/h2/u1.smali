.class public final Lh2/u1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/u1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/u1;->e:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/u1;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x1

    .line 24
    if-eq v3, v4, :cond_0

    .line 25
    .line 26
    move v3, v5

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x0

    .line 29
    :goto_0
    and-int/2addr v2, v5

    .line 30
    check-cast v1, Ll2/t;

    .line 31
    .line 32
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    const/16 v25, 0x0

    .line 39
    .line 40
    const v26, 0x3fffe

    .line 41
    .line 42
    .line 43
    iget-object v4, v0, Lh2/u1;->e:Ljava/lang/String;

    .line 44
    .line 45
    const/4 v5, 0x0

    .line 46
    const-wide/16 v6, 0x0

    .line 47
    .line 48
    const-wide/16 v8, 0x0

    .line 49
    .line 50
    const/4 v10, 0x0

    .line 51
    const-wide/16 v11, 0x0

    .line 52
    .line 53
    const/4 v13, 0x0

    .line 54
    const/4 v14, 0x0

    .line 55
    const-wide/16 v15, 0x0

    .line 56
    .line 57
    const/16 v17, 0x0

    .line 58
    .line 59
    const/16 v18, 0x0

    .line 60
    .line 61
    const/16 v19, 0x0

    .line 62
    .line 63
    const/16 v20, 0x0

    .line 64
    .line 65
    const/16 v21, 0x0

    .line 66
    .line 67
    const/16 v22, 0x0

    .line 68
    .line 69
    const/16 v24, 0x0

    .line 70
    .line 71
    move-object/from16 v23, v1

    .line 72
    .line 73
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_1
    move-object/from16 v23, v1

    .line 78
    .line 79
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 80
    .line 81
    .line 82
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object v0

    .line 85
    :pswitch_0
    move-object/from16 v1, p1

    .line 86
    .line 87
    check-cast v1, Ll2/o;

    .line 88
    .line 89
    move-object/from16 v2, p2

    .line 90
    .line 91
    check-cast v2, Ljava/lang/Number;

    .line 92
    .line 93
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    and-int/lit8 v3, v2, 0x3

    .line 98
    .line 99
    const/4 v4, 0x2

    .line 100
    const/4 v5, 0x1

    .line 101
    if-eq v3, v4, :cond_2

    .line 102
    .line 103
    move v3, v5

    .line 104
    goto :goto_2

    .line 105
    :cond_2
    const/4 v3, 0x0

    .line 106
    :goto_2
    and-int/2addr v2, v5

    .line 107
    check-cast v1, Ll2/t;

    .line 108
    .line 109
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    if-eqz v2, :cond_4

    .line 114
    .line 115
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 120
    .line 121
    if-ne v2, v3, :cond_3

    .line 122
    .line 123
    new-instance v2, Lh10/d;

    .line 124
    .line 125
    const/4 v3, 0x5

    .line 126
    invoke-direct {v2, v3}, Lh10/d;-><init>(I)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    :cond_3
    check-cast v2, Lay0/k;

    .line 133
    .line 134
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 135
    .line 136
    invoke-static {v3, v2}, Ld4/n;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 137
    .line 138
    .line 139
    move-result-object v5

    .line 140
    const/16 v25, 0x0

    .line 141
    .line 142
    const v26, 0x3fffc

    .line 143
    .line 144
    .line 145
    iget-object v4, v0, Lh2/u1;->e:Ljava/lang/String;

    .line 146
    .line 147
    const-wide/16 v6, 0x0

    .line 148
    .line 149
    const-wide/16 v8, 0x0

    .line 150
    .line 151
    const/4 v10, 0x0

    .line 152
    const-wide/16 v11, 0x0

    .line 153
    .line 154
    const/4 v13, 0x0

    .line 155
    const/4 v14, 0x0

    .line 156
    const-wide/16 v15, 0x0

    .line 157
    .line 158
    const/16 v17, 0x0

    .line 159
    .line 160
    const/16 v18, 0x0

    .line 161
    .line 162
    const/16 v19, 0x0

    .line 163
    .line 164
    const/16 v20, 0x0

    .line 165
    .line 166
    const/16 v21, 0x0

    .line 167
    .line 168
    const/16 v22, 0x0

    .line 169
    .line 170
    const/16 v24, 0x0

    .line 171
    .line 172
    move-object/from16 v23, v1

    .line 173
    .line 174
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 175
    .line 176
    .line 177
    goto :goto_3

    .line 178
    :cond_4
    move-object/from16 v23, v1

    .line 179
    .line 180
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 181
    .line 182
    .line 183
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 184
    .line 185
    return-object v0

    .line 186
    :pswitch_1
    move-object/from16 v1, p1

    .line 187
    .line 188
    check-cast v1, Ll2/o;

    .line 189
    .line 190
    move-object/from16 v2, p2

    .line 191
    .line 192
    check-cast v2, Ljava/lang/Number;

    .line 193
    .line 194
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 195
    .line 196
    .line 197
    move-result v2

    .line 198
    and-int/lit8 v3, v2, 0x3

    .line 199
    .line 200
    const/4 v4, 0x2

    .line 201
    const/4 v5, 0x1

    .line 202
    if-eq v3, v4, :cond_5

    .line 203
    .line 204
    move v3, v5

    .line 205
    goto :goto_4

    .line 206
    :cond_5
    const/4 v3, 0x0

    .line 207
    :goto_4
    and-int/2addr v2, v5

    .line 208
    check-cast v1, Ll2/t;

    .line 209
    .line 210
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 211
    .line 212
    .line 213
    move-result v2

    .line 214
    if-eqz v2, :cond_7

    .line 215
    .line 216
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v2

    .line 220
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 221
    .line 222
    if-ne v2, v3, :cond_6

    .line 223
    .line 224
    new-instance v2, Lh10/d;

    .line 225
    .line 226
    const/4 v3, 0x5

    .line 227
    invoke-direct {v2, v3}, Lh10/d;-><init>(I)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    :cond_6
    check-cast v2, Lay0/k;

    .line 234
    .line 235
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 236
    .line 237
    invoke-static {v3, v2}, Ld4/n;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 238
    .line 239
    .line 240
    move-result-object v5

    .line 241
    const/16 v25, 0x0

    .line 242
    .line 243
    const v26, 0x3fffc

    .line 244
    .line 245
    .line 246
    iget-object v4, v0, Lh2/u1;->e:Ljava/lang/String;

    .line 247
    .line 248
    const-wide/16 v6, 0x0

    .line 249
    .line 250
    const-wide/16 v8, 0x0

    .line 251
    .line 252
    const/4 v10, 0x0

    .line 253
    const-wide/16 v11, 0x0

    .line 254
    .line 255
    const/4 v13, 0x0

    .line 256
    const/4 v14, 0x0

    .line 257
    const-wide/16 v15, 0x0

    .line 258
    .line 259
    const/16 v17, 0x0

    .line 260
    .line 261
    const/16 v18, 0x0

    .line 262
    .line 263
    const/16 v19, 0x0

    .line 264
    .line 265
    const/16 v20, 0x0

    .line 266
    .line 267
    const/16 v21, 0x0

    .line 268
    .line 269
    const/16 v22, 0x0

    .line 270
    .line 271
    const/16 v24, 0x0

    .line 272
    .line 273
    move-object/from16 v23, v1

    .line 274
    .line 275
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 276
    .line 277
    .line 278
    goto :goto_5

    .line 279
    :cond_7
    move-object/from16 v23, v1

    .line 280
    .line 281
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 282
    .line 283
    .line 284
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 285
    .line 286
    return-object v0

    .line 287
    :pswitch_2
    move-object/from16 v1, p1

    .line 288
    .line 289
    check-cast v1, Ll2/o;

    .line 290
    .line 291
    move-object/from16 v2, p2

    .line 292
    .line 293
    check-cast v2, Ljava/lang/Number;

    .line 294
    .line 295
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 296
    .line 297
    .line 298
    move-result v2

    .line 299
    and-int/lit8 v3, v2, 0x3

    .line 300
    .line 301
    const/4 v4, 0x2

    .line 302
    const/4 v5, 0x1

    .line 303
    if-eq v3, v4, :cond_8

    .line 304
    .line 305
    move v3, v5

    .line 306
    goto :goto_6

    .line 307
    :cond_8
    const/4 v3, 0x0

    .line 308
    :goto_6
    and-int/2addr v2, v5

    .line 309
    check-cast v1, Ll2/t;

    .line 310
    .line 311
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 312
    .line 313
    .line 314
    move-result v2

    .line 315
    if-eqz v2, :cond_9

    .line 316
    .line 317
    const/16 v25, 0x0

    .line 318
    .line 319
    const v26, 0x3fffe

    .line 320
    .line 321
    .line 322
    iget-object v4, v0, Lh2/u1;->e:Ljava/lang/String;

    .line 323
    .line 324
    const/4 v5, 0x0

    .line 325
    const-wide/16 v6, 0x0

    .line 326
    .line 327
    const-wide/16 v8, 0x0

    .line 328
    .line 329
    const/4 v10, 0x0

    .line 330
    const-wide/16 v11, 0x0

    .line 331
    .line 332
    const/4 v13, 0x0

    .line 333
    const/4 v14, 0x0

    .line 334
    const-wide/16 v15, 0x0

    .line 335
    .line 336
    const/16 v17, 0x0

    .line 337
    .line 338
    const/16 v18, 0x0

    .line 339
    .line 340
    const/16 v19, 0x0

    .line 341
    .line 342
    const/16 v20, 0x0

    .line 343
    .line 344
    const/16 v21, 0x0

    .line 345
    .line 346
    const/16 v22, 0x0

    .line 347
    .line 348
    const/16 v24, 0x0

    .line 349
    .line 350
    move-object/from16 v23, v1

    .line 351
    .line 352
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 353
    .line 354
    .line 355
    goto :goto_7

    .line 356
    :cond_9
    move-object/from16 v23, v1

    .line 357
    .line 358
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 359
    .line 360
    .line 361
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 362
    .line 363
    return-object v0

    .line 364
    :pswitch_3
    move-object/from16 v1, p1

    .line 365
    .line 366
    check-cast v1, Ll2/o;

    .line 367
    .line 368
    move-object/from16 v2, p2

    .line 369
    .line 370
    check-cast v2, Ljava/lang/Number;

    .line 371
    .line 372
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 373
    .line 374
    .line 375
    move-result v2

    .line 376
    and-int/lit8 v3, v2, 0x3

    .line 377
    .line 378
    const/4 v4, 0x2

    .line 379
    const/4 v5, 0x1

    .line 380
    if-eq v3, v4, :cond_a

    .line 381
    .line 382
    move v3, v5

    .line 383
    goto :goto_8

    .line 384
    :cond_a
    const/4 v3, 0x0

    .line 385
    :goto_8
    and-int/2addr v2, v5

    .line 386
    check-cast v1, Ll2/t;

    .line 387
    .line 388
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 389
    .line 390
    .line 391
    move-result v2

    .line 392
    if-eqz v2, :cond_c

    .line 393
    .line 394
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v2

    .line 398
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 399
    .line 400
    if-ne v2, v3, :cond_b

    .line 401
    .line 402
    new-instance v2, Lh10/d;

    .line 403
    .line 404
    const/4 v3, 0x5

    .line 405
    invoke-direct {v2, v3}, Lh10/d;-><init>(I)V

    .line 406
    .line 407
    .line 408
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 409
    .line 410
    .line 411
    :cond_b
    check-cast v2, Lay0/k;

    .line 412
    .line 413
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 414
    .line 415
    invoke-static {v3, v2}, Ld4/n;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 416
    .line 417
    .line 418
    move-result-object v5

    .line 419
    const/16 v25, 0x0

    .line 420
    .line 421
    const v26, 0x3fffc

    .line 422
    .line 423
    .line 424
    iget-object v4, v0, Lh2/u1;->e:Ljava/lang/String;

    .line 425
    .line 426
    const-wide/16 v6, 0x0

    .line 427
    .line 428
    const-wide/16 v8, 0x0

    .line 429
    .line 430
    const/4 v10, 0x0

    .line 431
    const-wide/16 v11, 0x0

    .line 432
    .line 433
    const/4 v13, 0x0

    .line 434
    const/4 v14, 0x0

    .line 435
    const-wide/16 v15, 0x0

    .line 436
    .line 437
    const/16 v17, 0x0

    .line 438
    .line 439
    const/16 v18, 0x0

    .line 440
    .line 441
    const/16 v19, 0x0

    .line 442
    .line 443
    const/16 v20, 0x0

    .line 444
    .line 445
    const/16 v21, 0x0

    .line 446
    .line 447
    const/16 v22, 0x0

    .line 448
    .line 449
    const/16 v24, 0x0

    .line 450
    .line 451
    move-object/from16 v23, v1

    .line 452
    .line 453
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 454
    .line 455
    .line 456
    goto :goto_9

    .line 457
    :cond_c
    move-object/from16 v23, v1

    .line 458
    .line 459
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 460
    .line 461
    .line 462
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 463
    .line 464
    return-object v0

    .line 465
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

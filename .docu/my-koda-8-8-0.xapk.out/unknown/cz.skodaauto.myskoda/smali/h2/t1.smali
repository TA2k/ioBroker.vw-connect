.class public final Lh2/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/t1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/t1;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/t1;->f:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/t1;->d:I

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
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x1

    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v6

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v5

    .line 30
    :goto_0
    and-int/2addr v2, v6

    .line 31
    check-cast v1, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_1

    .line 38
    .line 39
    iget-object v2, v0, Lh2/t1;->f:Ljava/lang/String;

    .line 40
    .line 41
    new-array v3, v5, [Ljava/lang/Object;

    .line 42
    .line 43
    iget-object v0, v0, Lh2/t1;->e:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v0, v2, v1, v3}, Lkp/a7;->c(Ljava/lang/String;Ljava/lang/String;Ll2/t;[Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 50
    .line 51
    .line 52
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object v0

    .line 55
    :pswitch_0
    move-object/from16 v1, p1

    .line 56
    .line 57
    check-cast v1, Ll2/o;

    .line 58
    .line 59
    move-object/from16 v2, p2

    .line 60
    .line 61
    check-cast v2, Ljava/lang/Number;

    .line 62
    .line 63
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    and-int/lit8 v3, v2, 0x3

    .line 68
    .line 69
    const/4 v4, 0x2

    .line 70
    const/4 v5, 0x0

    .line 71
    const/4 v6, 0x1

    .line 72
    if-eq v3, v4, :cond_2

    .line 73
    .line 74
    move v3, v6

    .line 75
    goto :goto_2

    .line 76
    :cond_2
    move v3, v5

    .line 77
    :goto_2
    and-int/2addr v2, v6

    .line 78
    check-cast v1, Ll2/t;

    .line 79
    .line 80
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-eqz v2, :cond_5

    .line 85
    .line 86
    iget-object v6, v0, Lh2/t1;->e:Ljava/lang/String;

    .line 87
    .line 88
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    iget-object v3, v0, Lh2/t1;->f:Ljava/lang/String;

    .line 93
    .line 94
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    or-int/2addr v2, v4

    .line 99
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    if-nez v2, :cond_3

    .line 104
    .line 105
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 106
    .line 107
    if-ne v4, v2, :cond_4

    .line 108
    .line 109
    :cond_3
    new-instance v4, Lcp0/s;

    .line 110
    .line 111
    const/4 v2, 0x3

    .line 112
    iget-object v0, v0, Lh2/t1;->e:Ljava/lang/String;

    .line 113
    .line 114
    invoke-direct {v4, v0, v3, v2}, Lcp0/s;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_4
    check-cast v4, Lay0/k;

    .line 121
    .line 122
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 123
    .line 124
    invoke-static {v0, v5, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 125
    .line 126
    .line 127
    move-result-object v7

    .line 128
    const/16 v27, 0x0

    .line 129
    .line 130
    const v28, 0x3fffc

    .line 131
    .line 132
    .line 133
    const-wide/16 v8, 0x0

    .line 134
    .line 135
    const-wide/16 v10, 0x0

    .line 136
    .line 137
    const/4 v12, 0x0

    .line 138
    const-wide/16 v13, 0x0

    .line 139
    .line 140
    const/4 v15, 0x0

    .line 141
    const/16 v16, 0x0

    .line 142
    .line 143
    const-wide/16 v17, 0x0

    .line 144
    .line 145
    const/16 v19, 0x0

    .line 146
    .line 147
    const/16 v20, 0x0

    .line 148
    .line 149
    const/16 v21, 0x0

    .line 150
    .line 151
    const/16 v22, 0x0

    .line 152
    .line 153
    const/16 v23, 0x0

    .line 154
    .line 155
    const/16 v24, 0x0

    .line 156
    .line 157
    const/16 v26, 0x0

    .line 158
    .line 159
    move-object/from16 v25, v1

    .line 160
    .line 161
    invoke-static/range {v6 .. v28}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 162
    .line 163
    .line 164
    goto :goto_3

    .line 165
    :cond_5
    move-object/from16 v25, v1

    .line 166
    .line 167
    invoke-virtual/range {v25 .. v25}, Ll2/t;->R()V

    .line 168
    .line 169
    .line 170
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    return-object v0

    .line 173
    :pswitch_1
    move-object/from16 v1, p1

    .line 174
    .line 175
    check-cast v1, Ll2/o;

    .line 176
    .line 177
    move-object/from16 v2, p2

    .line 178
    .line 179
    check-cast v2, Ljava/lang/Number;

    .line 180
    .line 181
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 182
    .line 183
    .line 184
    move-result v2

    .line 185
    and-int/lit8 v3, v2, 0x3

    .line 186
    .line 187
    const/4 v4, 0x2

    .line 188
    const/4 v5, 0x0

    .line 189
    const/4 v6, 0x1

    .line 190
    if-eq v3, v4, :cond_6

    .line 191
    .line 192
    move v3, v6

    .line 193
    goto :goto_4

    .line 194
    :cond_6
    move v3, v5

    .line 195
    :goto_4
    and-int/2addr v2, v6

    .line 196
    check-cast v1, Ll2/t;

    .line 197
    .line 198
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 199
    .line 200
    .line 201
    move-result v2

    .line 202
    if-eqz v2, :cond_9

    .line 203
    .line 204
    iget-object v6, v0, Lh2/t1;->e:Ljava/lang/String;

    .line 205
    .line 206
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result v2

    .line 210
    iget-object v3, v0, Lh2/t1;->f:Ljava/lang/String;

    .line 211
    .line 212
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result v4

    .line 216
    or-int/2addr v2, v4

    .line 217
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v4

    .line 221
    if-nez v2, :cond_7

    .line 222
    .line 223
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 224
    .line 225
    if-ne v4, v2, :cond_8

    .line 226
    .line 227
    :cond_7
    new-instance v4, Lcp0/s;

    .line 228
    .line 229
    const/4 v2, 0x2

    .line 230
    iget-object v0, v0, Lh2/t1;->e:Ljava/lang/String;

    .line 231
    .line 232
    invoke-direct {v4, v0, v3, v2}, Lcp0/s;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    :cond_8
    check-cast v4, Lay0/k;

    .line 239
    .line 240
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 241
    .line 242
    invoke-static {v0, v5, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 243
    .line 244
    .line 245
    move-result-object v7

    .line 246
    const/16 v27, 0x0

    .line 247
    .line 248
    const v28, 0x3fffc

    .line 249
    .line 250
    .line 251
    const-wide/16 v8, 0x0

    .line 252
    .line 253
    const-wide/16 v10, 0x0

    .line 254
    .line 255
    const/4 v12, 0x0

    .line 256
    const-wide/16 v13, 0x0

    .line 257
    .line 258
    const/4 v15, 0x0

    .line 259
    const/16 v16, 0x0

    .line 260
    .line 261
    const-wide/16 v17, 0x0

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
    const/16 v23, 0x0

    .line 272
    .line 273
    const/16 v24, 0x0

    .line 274
    .line 275
    const/16 v26, 0x0

    .line 276
    .line 277
    move-object/from16 v25, v1

    .line 278
    .line 279
    invoke-static/range {v6 .. v28}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 280
    .line 281
    .line 282
    goto :goto_5

    .line 283
    :cond_9
    move-object/from16 v25, v1

    .line 284
    .line 285
    invoke-virtual/range {v25 .. v25}, Ll2/t;->R()V

    .line 286
    .line 287
    .line 288
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 289
    .line 290
    return-object v0

    .line 291
    :pswitch_2
    move-object/from16 v1, p1

    .line 292
    .line 293
    check-cast v1, Ll2/o;

    .line 294
    .line 295
    move-object/from16 v2, p2

    .line 296
    .line 297
    check-cast v2, Ljava/lang/Number;

    .line 298
    .line 299
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 300
    .line 301
    .line 302
    move-result v2

    .line 303
    and-int/lit8 v3, v2, 0x3

    .line 304
    .line 305
    const/4 v4, 0x2

    .line 306
    const/4 v5, 0x0

    .line 307
    const/4 v6, 0x1

    .line 308
    if-eq v3, v4, :cond_a

    .line 309
    .line 310
    move v3, v6

    .line 311
    goto :goto_6

    .line 312
    :cond_a
    move v3, v5

    .line 313
    :goto_6
    and-int/2addr v2, v6

    .line 314
    check-cast v1, Ll2/t;

    .line 315
    .line 316
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 317
    .line 318
    .line 319
    move-result v2

    .line 320
    if-eqz v2, :cond_d

    .line 321
    .line 322
    iget-object v6, v0, Lh2/t1;->e:Ljava/lang/String;

    .line 323
    .line 324
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 325
    .line 326
    .line 327
    move-result v2

    .line 328
    iget-object v3, v0, Lh2/t1;->f:Ljava/lang/String;

    .line 329
    .line 330
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 331
    .line 332
    .line 333
    move-result v4

    .line 334
    or-int/2addr v2, v4

    .line 335
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v4

    .line 339
    if-nez v2, :cond_b

    .line 340
    .line 341
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 342
    .line 343
    if-ne v4, v2, :cond_c

    .line 344
    .line 345
    :cond_b
    new-instance v4, Lcp0/s;

    .line 346
    .line 347
    const/4 v2, 0x1

    .line 348
    iget-object v0, v0, Lh2/t1;->e:Ljava/lang/String;

    .line 349
    .line 350
    invoke-direct {v4, v0, v3, v2}, Lcp0/s;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 351
    .line 352
    .line 353
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    :cond_c
    check-cast v4, Lay0/k;

    .line 357
    .line 358
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 359
    .line 360
    invoke-static {v0, v5, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 361
    .line 362
    .line 363
    move-result-object v7

    .line 364
    const/16 v27, 0x0

    .line 365
    .line 366
    const v28, 0x3fffc

    .line 367
    .line 368
    .line 369
    const-wide/16 v8, 0x0

    .line 370
    .line 371
    const-wide/16 v10, 0x0

    .line 372
    .line 373
    const/4 v12, 0x0

    .line 374
    const-wide/16 v13, 0x0

    .line 375
    .line 376
    const/4 v15, 0x0

    .line 377
    const/16 v16, 0x0

    .line 378
    .line 379
    const-wide/16 v17, 0x0

    .line 380
    .line 381
    const/16 v19, 0x0

    .line 382
    .line 383
    const/16 v20, 0x0

    .line 384
    .line 385
    const/16 v21, 0x0

    .line 386
    .line 387
    const/16 v22, 0x0

    .line 388
    .line 389
    const/16 v23, 0x0

    .line 390
    .line 391
    const/16 v24, 0x0

    .line 392
    .line 393
    const/16 v26, 0x0

    .line 394
    .line 395
    move-object/from16 v25, v1

    .line 396
    .line 397
    invoke-static/range {v6 .. v28}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 398
    .line 399
    .line 400
    goto :goto_7

    .line 401
    :cond_d
    move-object/from16 v25, v1

    .line 402
    .line 403
    invoke-virtual/range {v25 .. v25}, Ll2/t;->R()V

    .line 404
    .line 405
    .line 406
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 407
    .line 408
    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

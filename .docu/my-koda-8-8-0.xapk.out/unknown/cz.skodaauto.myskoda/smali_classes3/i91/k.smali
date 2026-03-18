.class public final synthetic Li91/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Integer;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Li91/h1;

.field public final synthetic i:Z


# direct methods
.method public synthetic constructor <init>(ZLjava/lang/Integer;Ljava/lang/String;Li91/h1;Z)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li91/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Li91/k;->e:Z

    iput-object p2, p0, Li91/k;->f:Ljava/lang/Integer;

    iput-object p3, p0, Li91/k;->g:Ljava/lang/String;

    iput-object p4, p0, Li91/k;->h:Li91/h1;

    iput-boolean p5, p0, Li91/k;->i:Z

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/String;Ljava/lang/Integer;ZLi91/h1;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Li91/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Li91/k;->e:Z

    iput-object p2, p0, Li91/k;->g:Ljava/lang/String;

    iput-object p3, p0, Li91/k;->f:Ljava/lang/Integer;

    iput-boolean p4, p0, Li91/k;->i:Z

    iput-object p5, p0, Li91/k;->h:Li91/h1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/k;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk1/h1;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const-string v4, "$this$Button"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v1, v3, 0x11

    .line 30
    .line 31
    const/16 v4, 0x10

    .line 32
    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x0

    .line 35
    if-eq v1, v4, :cond_0

    .line 36
    .line 37
    move v1, v5

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v1, v6

    .line 40
    :goto_0
    and-int/2addr v3, v5

    .line 41
    move-object v12, v2

    .line 42
    check-cast v12, Ll2/t;

    .line 43
    .line 44
    invoke-virtual {v12, v3, v1}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_8

    .line 49
    .line 50
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 51
    .line 52
    const/4 v2, 0x4

    .line 53
    int-to-float v2, v2

    .line 54
    invoke-static {v2}, Lk1/j;->g(F)Lk1/h;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    const/16 v3, 0x36

    .line 59
    .line 60
    invoke-static {v2, v1, v12, v3}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    iget-wide v2, v12, Ll2/t;->T:J

    .line 65
    .line 66
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 75
    .line 76
    invoke-static {v12, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 81
    .line 82
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 86
    .line 87
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 88
    .line 89
    .line 90
    iget-boolean v9, v12, Ll2/t;->S:Z

    .line 91
    .line 92
    if-eqz v9, :cond_1

    .line 93
    .line 94
    invoke-virtual {v12, v8}, Ll2/t;->l(Lay0/a;)V

    .line 95
    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_1
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 99
    .line 100
    .line 101
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 102
    .line 103
    invoke-static {v8, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 104
    .line 105
    .line 106
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 107
    .line 108
    invoke-static {v1, v3, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 109
    .line 110
    .line 111
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 112
    .line 113
    iget-boolean v3, v12, Ll2/t;->S:Z

    .line 114
    .line 115
    if-nez v3, :cond_2

    .line 116
    .line 117
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 122
    .line 123
    .line 124
    move-result-object v8

    .line 125
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    if-nez v3, :cond_3

    .line 130
    .line 131
    :cond_2
    invoke-static {v2, v12, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 132
    .line 133
    .line 134
    :cond_3
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 135
    .line 136
    invoke-static {v1, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 137
    .line 138
    .line 139
    iget-boolean v1, v0, Li91/k;->e:Z

    .line 140
    .line 141
    if-eqz v1, :cond_4

    .line 142
    .line 143
    const v0, 0x5c1c6aa4

    .line 144
    .line 145
    .line 146
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    const/4 v0, 0x0

    .line 150
    invoke-static {v6, v5, v12, v0}, Li91/j0;->N(IILl2/o;Lx2/s;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 154
    .line 155
    .line 156
    goto/16 :goto_8

    .line 157
    .line 158
    :cond_4
    const v1, 0x27723892

    .line 159
    .line 160
    .line 161
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    iget-object v1, v0, Li91/k;->f:Ljava/lang/Integer;

    .line 165
    .line 166
    if-nez v1, :cond_5

    .line 167
    .line 168
    const v1, 0x27728c3e

    .line 169
    .line 170
    .line 171
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 172
    .line 173
    .line 174
    :goto_2
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 175
    .line 176
    .line 177
    goto :goto_3

    .line 178
    :cond_5
    const v2, 0x27728c3f

    .line 179
    .line 180
    .line 181
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    invoke-static {v1, v6, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 189
    .line 190
    .line 191
    move-result-object v7

    .line 192
    const/16 v1, 0x14

    .line 193
    .line 194
    int-to-float v1, v1

    .line 195
    invoke-static {v4, v1}, Landroidx/compose/foundation/layout/d;->h(Lx2/s;F)Lx2/s;

    .line 196
    .line 197
    .line 198
    move-result-object v9

    .line 199
    const/16 v13, 0x1b0

    .line 200
    .line 201
    const/16 v14, 0x8

    .line 202
    .line 203
    const/4 v8, 0x0

    .line 204
    const-wide/16 v10, 0x0

    .line 205
    .line 206
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 207
    .line 208
    .line 209
    goto :goto_2

    .line 210
    :goto_3
    iget-object v7, v0, Li91/k;->g:Ljava/lang/String;

    .line 211
    .line 212
    if-nez v7, :cond_6

    .line 213
    .line 214
    const v0, 0x27777d4f

    .line 215
    .line 216
    .line 217
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 218
    .line 219
    .line 220
    :goto_4
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 221
    .line 222
    .line 223
    goto :goto_7

    .line 224
    :cond_6
    const v1, 0x27777d50

    .line 225
    .line 226
    .line 227
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 228
    .line 229
    .line 230
    iget-object v1, v0, Li91/k;->h:Li91/h1;

    .line 231
    .line 232
    iget-boolean v0, v0, Li91/k;->i:Z

    .line 233
    .line 234
    if-eqz v0, :cond_7

    .line 235
    .line 236
    iget-wide v0, v1, Li91/h1;->b:J

    .line 237
    .line 238
    :goto_5
    move-wide v10, v0

    .line 239
    goto :goto_6

    .line 240
    :cond_7
    iget-wide v0, v1, Li91/h1;->d:J

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :goto_6
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 244
    .line 245
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    check-cast v0, Lj91/f;

    .line 250
    .line 251
    invoke-virtual {v0}, Lj91/f;->l()Lg4/p0;

    .line 252
    .line 253
    .line 254
    move-result-object v8

    .line 255
    const/16 v27, 0x6180

    .line 256
    .line 257
    const v28, 0xaff4

    .line 258
    .line 259
    .line 260
    const/4 v9, 0x0

    .line 261
    move-object/from16 v25, v12

    .line 262
    .line 263
    const-wide/16 v12, 0x0

    .line 264
    .line 265
    const/4 v14, 0x0

    .line 266
    const-wide/16 v15, 0x0

    .line 267
    .line 268
    const/16 v17, 0x0

    .line 269
    .line 270
    const/16 v18, 0x0

    .line 271
    .line 272
    const-wide/16 v19, 0x0

    .line 273
    .line 274
    const/16 v21, 0x2

    .line 275
    .line 276
    const/16 v22, 0x0

    .line 277
    .line 278
    const/16 v23, 0x1

    .line 279
    .line 280
    const/16 v24, 0x0

    .line 281
    .line 282
    const/16 v26, 0x0

    .line 283
    .line 284
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 285
    .line 286
    .line 287
    move-object/from16 v12, v25

    .line 288
    .line 289
    goto :goto_4

    .line 290
    :goto_7
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 291
    .line 292
    .line 293
    :goto_8
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 294
    .line 295
    .line 296
    goto :goto_9

    .line 297
    :cond_8
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 298
    .line 299
    .line 300
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 301
    .line 302
    return-object v0

    .line 303
    :pswitch_0
    move-object/from16 v1, p1

    .line 304
    .line 305
    check-cast v1, Lk1/h1;

    .line 306
    .line 307
    move-object/from16 v2, p2

    .line 308
    .line 309
    check-cast v2, Ll2/o;

    .line 310
    .line 311
    move-object/from16 v3, p3

    .line 312
    .line 313
    check-cast v3, Ljava/lang/Integer;

    .line 314
    .line 315
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 316
    .line 317
    .line 318
    move-result v3

    .line 319
    const-string v4, "$this$Button"

    .line 320
    .line 321
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 322
    .line 323
    .line 324
    and-int/lit8 v4, v3, 0x6

    .line 325
    .line 326
    if-nez v4, :cond_a

    .line 327
    .line 328
    move-object v4, v2

    .line 329
    check-cast v4, Ll2/t;

    .line 330
    .line 331
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 332
    .line 333
    .line 334
    move-result v4

    .line 335
    if-eqz v4, :cond_9

    .line 336
    .line 337
    const/4 v4, 0x4

    .line 338
    goto :goto_a

    .line 339
    :cond_9
    const/4 v4, 0x2

    .line 340
    :goto_a
    or-int/2addr v3, v4

    .line 341
    :cond_a
    and-int/lit8 v4, v3, 0x13

    .line 342
    .line 343
    const/16 v5, 0x12

    .line 344
    .line 345
    const/4 v6, 0x1

    .line 346
    const/4 v8, 0x0

    .line 347
    if-eq v4, v5, :cond_b

    .line 348
    .line 349
    move v4, v6

    .line 350
    goto :goto_b

    .line 351
    :cond_b
    move v4, v8

    .line 352
    :goto_b
    and-int/lit8 v5, v3, 0x1

    .line 353
    .line 354
    check-cast v2, Ll2/t;

    .line 355
    .line 356
    invoke-virtual {v2, v5, v4}, Ll2/t;->O(IZ)Z

    .line 357
    .line 358
    .line 359
    move-result v4

    .line 360
    if-eqz v4, :cond_d

    .line 361
    .line 362
    iget-boolean v4, v0, Li91/k;->e:Z

    .line 363
    .line 364
    if-eqz v4, :cond_c

    .line 365
    .line 366
    const v0, -0x2a80297f

    .line 367
    .line 368
    .line 369
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 370
    .line 371
    .line 372
    const/4 v0, 0x0

    .line 373
    invoke-static {v8, v6, v2, v0}, Li91/j0;->N(IILl2/o;Lx2/s;)V

    .line 374
    .line 375
    .line 376
    invoke-virtual {v2, v8}, Ll2/t;->q(Z)V

    .line 377
    .line 378
    .line 379
    goto :goto_c

    .line 380
    :cond_c
    const v4, -0x2a801eee

    .line 381
    .line 382
    .line 383
    invoke-virtual {v2, v4}, Ll2/t;->Y(I)V

    .line 384
    .line 385
    .line 386
    and-int/lit8 v7, v3, 0xe

    .line 387
    .line 388
    move-object v6, v2

    .line 389
    iget-object v2, v0, Li91/k;->g:Ljava/lang/String;

    .line 390
    .line 391
    iget-object v3, v0, Li91/k;->f:Ljava/lang/Integer;

    .line 392
    .line 393
    iget-boolean v4, v0, Li91/k;->i:Z

    .line 394
    .line 395
    iget-object v5, v0, Li91/k;->h:Li91/h1;

    .line 396
    .line 397
    invoke-static/range {v1 .. v7}, Li91/j0;->t(Lk1/h1;Ljava/lang/String;Ljava/lang/Integer;ZLi91/h1;Ll2/o;I)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    .line 401
    .line 402
    .line 403
    goto :goto_c

    .line 404
    :cond_d
    move-object v6, v2

    .line 405
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 406
    .line 407
    .line 408
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 409
    .line 410
    return-object v0

    .line 411
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

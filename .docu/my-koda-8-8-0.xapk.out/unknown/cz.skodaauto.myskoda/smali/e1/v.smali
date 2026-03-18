.class public Le1/v;
.super Le1/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public N:Lp3/t;


# virtual methods
.method public final b1()Lp3/j0;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final h1(Landroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final i1(Landroid/view/KeyEvent;)V
    .locals 0

    .line 1
    iget-object p0, p0, Le1/h;->z:Lay0/a;

    .line 2
    .line 3
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final l0()V
    .locals 1

    .line 1
    invoke-super {p0}, Le1/h;->l0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Le1/v;->N:Lp3/t;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Le1/v;->N:Lp3/t;

    .line 10
    .line 11
    invoke-virtual {p0}, Le1/h;->e1()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final v0(Lp3/k;Lp3/l;J)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-wide/from16 v3, p3

    .line 8
    .line 9
    invoke-super/range {p0 .. p4}, Le1/h;->v0(Lp3/k;Lp3/l;J)V

    .line 10
    .line 11
    .line 12
    sget-object v5, Lp3/l;->e:Lp3/l;

    .line 13
    .line 14
    const/4 v6, 0x0

    .line 15
    const/4 v7, 0x0

    .line 16
    if-ne v2, v5, :cond_a

    .line 17
    .line 18
    iget-object v2, v1, Le1/v;->N:Lp3/t;

    .line 19
    .line 20
    const/4 v8, 0x3

    .line 21
    const/4 v5, 0x1

    .line 22
    if-nez v2, :cond_1

    .line 23
    .line 24
    invoke-static {v0, v5}, Lg1/g3;->f(Lp3/k;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_c

    .line 29
    .line 30
    iget-object v0, v0, Lp3/k;->a:Ljava/lang/Object;

    .line 31
    .line 32
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Lp3/t;

    .line 37
    .line 38
    invoke-virtual {v0}, Lp3/t;->a()V

    .line 39
    .line 40
    .line 41
    iput-object v0, v1, Le1/v;->N:Lp3/t;

    .line 42
    .line 43
    iget-boolean v2, v1, Le1/h;->y:Z

    .line 44
    .line 45
    if-eqz v2, :cond_c

    .line 46
    .line 47
    iget-wide v2, v0, Lp3/t;->c:J

    .line 48
    .line 49
    iget-object v0, v1, Le1/h;->t:Li1/l;

    .line 50
    .line 51
    if-eqz v0, :cond_c

    .line 52
    .line 53
    new-instance v4, Li1/n;

    .line 54
    .line 55
    invoke-direct {v4, v2, v3}, Li1/n;-><init>(J)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v1}, Le1/h;->c1()Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_0

    .line 63
    .line 64
    invoke-virtual {v1}, Lx2/r;->L0()Lvy0/b0;

    .line 65
    .line 66
    .line 67
    move-result-object v7

    .line 68
    move-object v2, v0

    .line 69
    new-instance v0, Le1/e;

    .line 70
    .line 71
    const/4 v1, 0x0

    .line 72
    move-object v3, v4

    .line 73
    move-object v5, v6

    .line 74
    move-object/from16 v4, p0

    .line 75
    .line 76
    invoke-direct/range {v0 .. v5}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 77
    .line 78
    .line 79
    move-object v1, v4

    .line 80
    move-object v9, v5

    .line 81
    invoke-static {v7, v9, v9, v0, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    iput-object v0, v1, Le1/h;->K:Lvy0/x1;

    .line 86
    .line 87
    return-void

    .line 88
    :cond_0
    move-object v2, v0

    .line 89
    move-object v3, v4

    .line 90
    move-object v9, v6

    .line 91
    iput-object v3, v1, Le1/h;->E:Li1/n;

    .line 92
    .line 93
    invoke-virtual {v1}, Lx2/r;->L0()Lvy0/b0;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    new-instance v1, Le1/d;

    .line 98
    .line 99
    invoke-direct {v1, v2, v3, v9}, Le1/d;-><init>(Li1/l;Li1/n;Lkotlin/coroutines/Continuation;)V

    .line 100
    .line 101
    .line 102
    invoke-static {v0, v9, v9, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 103
    .line 104
    .line 105
    return-void

    .line 106
    :cond_1
    move-object v9, v6

    .line 107
    iget-object v0, v0, Lp3/k;->a:Ljava/lang/Object;

    .line 108
    .line 109
    move-object v6, v0

    .line 110
    check-cast v6, Ljava/util/Collection;

    .line 111
    .line 112
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 113
    .line 114
    .line 115
    move-result v6

    .line 116
    move v10, v7

    .line 117
    :goto_0
    if-ge v10, v6, :cond_5

    .line 118
    .line 119
    invoke-interface {v0, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v11

    .line 123
    check-cast v11, Lp3/t;

    .line 124
    .line 125
    invoke-static {v11}, Lp3/s;->c(Lp3/t;)Z

    .line 126
    .line 127
    .line 128
    move-result v11

    .line 129
    if-nez v11, :cond_4

    .line 130
    .line 131
    sget-object v2, Lw3/h1;->s:Ll2/u2;

    .line 132
    .line 133
    invoke-static {v1, v2}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    check-cast v2, Lw3/h2;

    .line 138
    .line 139
    invoke-interface {v2}, Lw3/h2;->d()J

    .line 140
    .line 141
    .line 142
    move-result-wide v5

    .line 143
    invoke-static {v1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    iget-object v2, v2, Lv3/h0;->A:Lt4/c;

    .line 148
    .line 149
    invoke-interface {v2, v5, v6}, Lt4/c;->G0(J)J

    .line 150
    .line 151
    .line 152
    move-result-wide v5

    .line 153
    const/16 v2, 0x20

    .line 154
    .line 155
    shr-long v10, v5, v2

    .line 156
    .line 157
    long-to-int v8, v10

    .line 158
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 159
    .line 160
    .line 161
    move-result v8

    .line 162
    shr-long v10, v3, v2

    .line 163
    .line 164
    long-to-int v10, v10

    .line 165
    int-to-float v10, v10

    .line 166
    sub-float/2addr v8, v10

    .line 167
    const/4 v10, 0x0

    .line 168
    invoke-static {v10, v8}, Ljava/lang/Math;->max(FF)F

    .line 169
    .line 170
    .line 171
    move-result v8

    .line 172
    const/high16 v11, 0x40000000    # 2.0f

    .line 173
    .line 174
    div-float/2addr v8, v11

    .line 175
    const-wide v12, 0xffffffffL

    .line 176
    .line 177
    .line 178
    .line 179
    .line 180
    and-long/2addr v5, v12

    .line 181
    long-to-int v5, v5

    .line 182
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 183
    .line 184
    .line 185
    move-result v5

    .line 186
    and-long v14, v3, v12

    .line 187
    .line 188
    long-to-int v6, v14

    .line 189
    int-to-float v6, v6

    .line 190
    sub-float/2addr v5, v6

    .line 191
    invoke-static {v10, v5}, Ljava/lang/Math;->max(FF)F

    .line 192
    .line 193
    .line 194
    move-result v5

    .line 195
    div-float/2addr v5, v11

    .line 196
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 197
    .line 198
    .line 199
    move-result v6

    .line 200
    int-to-long v10, v6

    .line 201
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 202
    .line 203
    .line 204
    move-result v5

    .line 205
    int-to-long v5, v5

    .line 206
    shl-long/2addr v10, v2

    .line 207
    and-long/2addr v5, v12

    .line 208
    or-long/2addr v5, v10

    .line 209
    move-object v2, v0

    .line 210
    check-cast v2, Ljava/util/Collection;

    .line 211
    .line 212
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 213
    .line 214
    .line 215
    move-result v2

    .line 216
    :goto_1
    if-ge v7, v2, :cond_c

    .line 217
    .line 218
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v8

    .line 222
    check-cast v8, Lp3/t;

    .line 223
    .line 224
    invoke-virtual {v8}, Lp3/t;->b()Z

    .line 225
    .line 226
    .line 227
    move-result v10

    .line 228
    if-nez v10, :cond_3

    .line 229
    .line 230
    invoke-static {v8, v3, v4, v5, v6}, Lp3/s;->f(Lp3/t;JJ)Z

    .line 231
    .line 232
    .line 233
    move-result v8

    .line 234
    if-eqz v8, :cond_2

    .line 235
    .line 236
    goto :goto_2

    .line 237
    :cond_2
    add-int/lit8 v7, v7, 0x1

    .line 238
    .line 239
    goto :goto_1

    .line 240
    :cond_3
    :goto_2
    iput-object v9, v1, Le1/v;->N:Lp3/t;

    .line 241
    .line 242
    invoke-virtual {v1}, Le1/h;->e1()V

    .line 243
    .line 244
    .line 245
    return-void

    .line 246
    :cond_4
    add-int/lit8 v10, v10, 0x1

    .line 247
    .line 248
    goto/16 :goto_0

    .line 249
    .line 250
    :cond_5
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    check-cast v0, Lp3/t;

    .line 255
    .line 256
    invoke-virtual {v0}, Lp3/t;->a()V

    .line 257
    .line 258
    .line 259
    iget-boolean v0, v1, Le1/h;->y:Z

    .line 260
    .line 261
    if-eqz v0, :cond_9

    .line 262
    .line 263
    iget-wide v2, v2, Lp3/t;->c:J

    .line 264
    .line 265
    iget-object v4, v1, Le1/h;->t:Li1/l;

    .line 266
    .line 267
    if-eqz v4, :cond_8

    .line 268
    .line 269
    iget-object v0, v1, Le1/h;->K:Lvy0/x1;

    .line 270
    .line 271
    if-eqz v0, :cond_6

    .line 272
    .line 273
    invoke-virtual {v0}, Lvy0/p1;->a()Z

    .line 274
    .line 275
    .line 276
    move-result v0

    .line 277
    if-ne v0, v5, :cond_6

    .line 278
    .line 279
    invoke-virtual {v1}, Lx2/r;->L0()Lvy0/b0;

    .line 280
    .line 281
    .line 282
    move-result-object v7

    .line 283
    new-instance v0, Le1/b;

    .line 284
    .line 285
    const/4 v5, 0x0

    .line 286
    const/4 v6, 0x1

    .line 287
    invoke-direct/range {v0 .. v6}, Le1/b;-><init>(Ljava/lang/Object;JLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 288
    .line 289
    .line 290
    invoke-static {v7, v9, v9, v0, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 291
    .line 292
    .line 293
    goto :goto_3

    .line 294
    :cond_6
    iget-object v0, v1, Le1/h;->E:Li1/n;

    .line 295
    .line 296
    if-eqz v0, :cond_7

    .line 297
    .line 298
    invoke-virtual {v1}, Lx2/r;->L0()Lvy0/b0;

    .line 299
    .line 300
    .line 301
    move-result-object v2

    .line 302
    new-instance v3, Le1/d;

    .line 303
    .line 304
    const/4 v5, 0x1

    .line 305
    invoke-direct {v3, v0, v4, v9, v5}, Le1/d;-><init>(Li1/n;Li1/l;Lkotlin/coroutines/Continuation;I)V

    .line 306
    .line 307
    .line 308
    invoke-static {v2, v9, v9, v3, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 309
    .line 310
    .line 311
    :cond_7
    :goto_3
    iput-object v9, v1, Le1/h;->E:Li1/n;

    .line 312
    .line 313
    :cond_8
    iget-object v0, v1, Le1/h;->z:Lay0/a;

    .line 314
    .line 315
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    :cond_9
    iput-object v9, v1, Le1/v;->N:Lp3/t;

    .line 319
    .line 320
    return-void

    .line 321
    :cond_a
    move-object v9, v6

    .line 322
    sget-object v3, Lp3/l;->f:Lp3/l;

    .line 323
    .line 324
    if-ne v2, v3, :cond_c

    .line 325
    .line 326
    iget-object v2, v1, Le1/v;->N:Lp3/t;

    .line 327
    .line 328
    if-eqz v2, :cond_c

    .line 329
    .line 330
    iget-object v0, v0, Lp3/k;->a:Ljava/lang/Object;

    .line 331
    .line 332
    move-object v2, v0

    .line 333
    check-cast v2, Ljava/util/Collection;

    .line 334
    .line 335
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 336
    .line 337
    .line 338
    move-result v2

    .line 339
    :goto_4
    if-ge v7, v2, :cond_c

    .line 340
    .line 341
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v3

    .line 345
    check-cast v3, Lp3/t;

    .line 346
    .line 347
    invoke-virtual {v3}, Lp3/t;->b()Z

    .line 348
    .line 349
    .line 350
    move-result v4

    .line 351
    if-eqz v4, :cond_b

    .line 352
    .line 353
    iget-object v4, v1, Le1/v;->N:Lp3/t;

    .line 354
    .line 355
    invoke-virtual {v3, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    move-result v3

    .line 359
    if-nez v3, :cond_b

    .line 360
    .line 361
    iput-object v9, v1, Le1/v;->N:Lp3/t;

    .line 362
    .line 363
    invoke-virtual {v1}, Le1/h;->e1()V

    .line 364
    .line 365
    .line 366
    return-void

    .line 367
    :cond_b
    add-int/lit8 v7, v7, 0x1

    .line 368
    .line 369
    goto :goto_4

    .line 370
    :cond_c
    return-void
.end method

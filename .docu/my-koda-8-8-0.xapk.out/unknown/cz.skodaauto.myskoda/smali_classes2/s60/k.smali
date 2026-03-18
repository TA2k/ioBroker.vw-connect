.class public final synthetic Ls60/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lr60/i;

.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lr60/i;Lay0/k;Ll2/b1;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ls60/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ls60/k;->e:Lr60/i;

    iput-object p2, p0, Ls60/k;->g:Lay0/k;

    iput-object p3, p0, Ls60/k;->f:Ll2/b1;

    return-void
.end method

.method public synthetic constructor <init>(Lr60/i;Ll2/b1;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Ls60/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ls60/k;->e:Lr60/i;

    iput-object p2, p0, Ls60/k;->f:Ll2/b1;

    iput-object p3, p0, Ls60/k;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ls60/k;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v2, p1

    .line 9
    .line 10
    check-cast v2, Landroidx/compose/material3/a;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ll2/o;

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
    const-string v4, "$this$ExposedDropdownMenuBox"

    .line 25
    .line 26
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v4, v3, 0x6

    .line 30
    .line 31
    if-nez v4, :cond_2

    .line 32
    .line 33
    and-int/lit8 v4, v3, 0x8

    .line 34
    .line 35
    if-nez v4, :cond_0

    .line 36
    .line 37
    move-object v4, v1

    .line 38
    check-cast v4, Ll2/t;

    .line 39
    .line 40
    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    move-object v4, v1

    .line 46
    check-cast v4, Ll2/t;

    .line 47
    .line 48
    invoke-virtual {v4, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    :goto_0
    if-eqz v4, :cond_1

    .line 53
    .line 54
    const/4 v4, 0x4

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    const/4 v4, 0x2

    .line 57
    :goto_1
    or-int/2addr v3, v4

    .line 58
    :cond_2
    and-int/lit8 v4, v3, 0x13

    .line 59
    .line 60
    const/16 v5, 0x12

    .line 61
    .line 62
    if-eq v4, v5, :cond_3

    .line 63
    .line 64
    const/4 v4, 0x1

    .line 65
    goto :goto_2

    .line 66
    :cond_3
    const/4 v4, 0x0

    .line 67
    :goto_2
    and-int/lit8 v5, v3, 0x1

    .line 68
    .line 69
    move-object v14, v1

    .line 70
    check-cast v14, Ll2/t;

    .line 71
    .line 72
    invoke-virtual {v14, v5, v4}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-eqz v1, :cond_6

    .line 77
    .line 78
    iget-object v1, v0, Ls60/k;->e:Lr60/i;

    .line 79
    .line 80
    iget-object v6, v1, Lr60/i;->h:Ljava/lang/String;

    .line 81
    .line 82
    const v4, 0x7f120dbf

    .line 83
    .line 84
    .line 85
    invoke-static {v14, v4}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v7

    .line 89
    invoke-static {v2}, Landroidx/compose/material3/a;->b(Landroidx/compose/material3/a;)Lx2/s;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    iget-boolean v5, v1, Lr60/i;->j:Z

    .line 94
    .line 95
    invoke-static {v4, v5}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    const/high16 v5, 0x3f800000    # 1.0f

    .line 100
    .line 101
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 102
    .line 103
    .line 104
    move-result-object v9

    .line 105
    iget-object v4, v0, Ls60/k;->f:Ll2/b1;

    .line 106
    .line 107
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    check-cast v5, Ljava/lang/Boolean;

    .line 112
    .line 113
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    if-eqz v5, :cond_4

    .line 118
    .line 119
    const v5, 0x7f08033d

    .line 120
    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_4
    const v5, 0x7f080333

    .line 124
    .line 125
    .line 126
    :goto_3
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object v18

    .line 130
    const/16 v25, 0x0

    .line 131
    .line 132
    const v26, 0x3dfd0

    .line 133
    .line 134
    .line 135
    iget-object v8, v0, Ls60/k;->g:Lay0/k;

    .line 136
    .line 137
    const/4 v10, 0x0

    .line 138
    const/4 v11, 0x1

    .line 139
    const/4 v12, 0x0

    .line 140
    const/4 v13, 0x0

    .line 141
    move-object/from16 v23, v14

    .line 142
    .line 143
    const/4 v14, 0x0

    .line 144
    const/4 v15, 0x0

    .line 145
    const/16 v16, 0x0

    .line 146
    .line 147
    const/16 v17, 0x0

    .line 148
    .line 149
    const/16 v19, 0x0

    .line 150
    .line 151
    const/16 v20, 0x0

    .line 152
    .line 153
    const/16 v21, 0x0

    .line 154
    .line 155
    const/16 v22, 0x0

    .line 156
    .line 157
    const/high16 v24, 0x30000

    .line 158
    .line 159
    invoke-static/range {v6 .. v26}, Li91/j4;->c(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lx2/s;ZZZLjava/lang/String;Ljava/lang/String;ILjava/lang/Integer;ZLjava/lang/Integer;Lay0/a;Ll4/d0;Lt1/o0;Lt1/n0;Ll2/o;III)V

    .line 160
    .line 161
    .line 162
    move-object/from16 v14, v23

    .line 163
    .line 164
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    check-cast v0, Ljava/lang/Boolean;

    .line 169
    .line 170
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v5

    .line 178
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 179
    .line 180
    if-ne v5, v6, :cond_5

    .line 181
    .line 182
    new-instance v5, Lio0/f;

    .line 183
    .line 184
    const/16 v6, 0xe

    .line 185
    .line 186
    invoke-direct {v5, v4, v6}, Lio0/f;-><init>(Ll2/b1;I)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    :cond_5
    check-cast v5, Lay0/a;

    .line 193
    .line 194
    new-instance v6, Ls60/k;

    .line 195
    .line 196
    invoke-direct {v6, v1, v8, v4}, Ls60/k;-><init>(Lr60/i;Lay0/k;Ll2/b1;)V

    .line 197
    .line 198
    .line 199
    const v1, 0x43d8529

    .line 200
    .line 201
    .line 202
    invoke-static {v1, v14, v6}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 203
    .line 204
    .line 205
    move-result-object v13

    .line 206
    shl-int/lit8 v1, v3, 0x3

    .line 207
    .line 208
    and-int/lit8 v1, v1, 0x70

    .line 209
    .line 210
    const/4 v3, 0x6

    .line 211
    or-int v16, v3, v1

    .line 212
    .line 213
    move-object v4, v5

    .line 214
    const/4 v5, 0x0

    .line 215
    const/4 v6, 0x0

    .line 216
    const/4 v7, 0x0

    .line 217
    const/4 v8, 0x0

    .line 218
    const-wide/16 v9, 0x0

    .line 219
    .line 220
    const/4 v11, 0x0

    .line 221
    const/4 v12, 0x0

    .line 222
    const/16 v15, 0x30

    .line 223
    .line 224
    move v3, v0

    .line 225
    invoke-virtual/range {v2 .. v16}, Landroidx/compose/material3/a;->a(ZLay0/a;Lx2/s;Le1/n1;ZLe3/n0;JFFLt2/b;Ll2/o;II)V

    .line 226
    .line 227
    .line 228
    goto :goto_4

    .line 229
    :cond_6
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 230
    .line 231
    .line 232
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 233
    .line 234
    return-object v0

    .line 235
    :pswitch_0
    move-object/from16 v1, p1

    .line 236
    .line 237
    check-cast v1, Lk1/t;

    .line 238
    .line 239
    move-object/from16 v2, p2

    .line 240
    .line 241
    check-cast v2, Ll2/o;

    .line 242
    .line 243
    move-object/from16 v3, p3

    .line 244
    .line 245
    check-cast v3, Ljava/lang/Integer;

    .line 246
    .line 247
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 248
    .line 249
    .line 250
    move-result v3

    .line 251
    const-string v4, "$this$ExposedDropdownMenu"

    .line 252
    .line 253
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    and-int/lit8 v1, v3, 0x11

    .line 257
    .line 258
    const/16 v4, 0x10

    .line 259
    .line 260
    const/4 v5, 0x1

    .line 261
    if-eq v1, v4, :cond_7

    .line 262
    .line 263
    move v1, v5

    .line 264
    goto :goto_5

    .line 265
    :cond_7
    const/4 v1, 0x0

    .line 266
    :goto_5
    and-int/2addr v3, v5

    .line 267
    move-object v10, v2

    .line 268
    check-cast v10, Ll2/t;

    .line 269
    .line 270
    invoke-virtual {v10, v3, v1}, Ll2/t;->O(IZ)Z

    .line 271
    .line 272
    .line 273
    move-result v1

    .line 274
    if-eqz v1, :cond_a

    .line 275
    .line 276
    iget-object v1, v0, Ls60/k;->e:Lr60/i;

    .line 277
    .line 278
    iget-object v1, v1, Lr60/i;->l:Ljava/util/List;

    .line 279
    .line 280
    check-cast v1, Ljava/lang/Iterable;

    .line 281
    .line 282
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 283
    .line 284
    .line 285
    move-result-object v1

    .line 286
    :goto_6
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 287
    .line 288
    .line 289
    move-result v2

    .line 290
    if-eqz v2, :cond_b

    .line 291
    .line 292
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v2

    .line 296
    check-cast v2, Lr60/j;

    .line 297
    .line 298
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 299
    .line 300
    invoke-virtual {v10, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v3

    .line 304
    check-cast v3, Lj91/e;

    .line 305
    .line 306
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 307
    .line 308
    .line 309
    move-result-wide v3

    .line 310
    sget-object v5, Le3/j0;->a:Le3/i0;

    .line 311
    .line 312
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 313
    .line 314
    invoke-static {v6, v3, v4, v5}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 315
    .line 316
    .line 317
    move-result-object v6

    .line 318
    new-instance v3, Llk/c;

    .line 319
    .line 320
    const/16 v4, 0x15

    .line 321
    .line 322
    invoke-direct {v3, v2, v4}, Llk/c;-><init>(Ljava/lang/Object;I)V

    .line 323
    .line 324
    .line 325
    const v4, 0x7bcab24b

    .line 326
    .line 327
    .line 328
    invoke-static {v4, v10, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 329
    .line 330
    .line 331
    move-result-object v4

    .line 332
    iget-object v3, v0, Ls60/k;->g:Lay0/k;

    .line 333
    .line 334
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 335
    .line 336
    .line 337
    move-result v5

    .line 338
    invoke-virtual {v10, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 339
    .line 340
    .line 341
    move-result v7

    .line 342
    or-int/2addr v5, v7

    .line 343
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    move-result-object v7

    .line 347
    if-nez v5, :cond_8

    .line 348
    .line 349
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 350
    .line 351
    if-ne v7, v5, :cond_9

    .line 352
    .line 353
    :cond_8
    new-instance v7, Lc41/b;

    .line 354
    .line 355
    iget-object v5, v0, Ls60/k;->f:Ll2/b1;

    .line 356
    .line 357
    invoke-direct {v7, v5, v3, v2}, Lc41/b;-><init>(Ll2/b1;Lay0/k;Lr60/j;)V

    .line 358
    .line 359
    .line 360
    invoke-virtual {v10, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 361
    .line 362
    .line 363
    :cond_9
    move-object v5, v7

    .line 364
    check-cast v5, Lay0/a;

    .line 365
    .line 366
    const/4 v9, 0x0

    .line 367
    const/4 v11, 0x6

    .line 368
    const/4 v7, 0x0

    .line 369
    const/4 v8, 0x0

    .line 370
    invoke-static/range {v4 .. v11}, Lh2/m;->a(Lt2/b;Lay0/a;Lx2/s;ZLh2/n5;Lk1/z0;Ll2/o;I)V

    .line 371
    .line 372
    .line 373
    goto :goto_6

    .line 374
    :cond_a
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 375
    .line 376
    .line 377
    :cond_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 378
    .line 379
    return-object v0

    .line 380
    nop

    .line 381
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

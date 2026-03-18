.class public final synthetic Li40/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;I)V
    .locals 0

    .line 1
    iput p3, p0, Li40/c1;->d:I

    .line 2
    .line 3
    iput p1, p0, Li40/c1;->e:I

    .line 4
    .line 5
    iput-object p2, p0, Li40/c1;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/c1;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li40/c1;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/lang/String;

    .line 11
    .line 12
    move-object/from16 v2, p1

    .line 13
    .line 14
    check-cast v2, Lx2/s;

    .line 15
    .line 16
    move-object/from16 v3, p2

    .line 17
    .line 18
    check-cast v3, Ll2/o;

    .line 19
    .line 20
    move-object/from16 v4, p3

    .line 21
    .line 22
    check-cast v4, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    const-string v4, "$this$composed"

    .line 28
    .line 29
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    check-cast v3, Ll2/t;

    .line 33
    .line 34
    const v4, -0x2c0a41f5

    .line 35
    .line 36
    .line 37
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 38
    .line 39
    .line 40
    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->c:Ll2/e0;

    .line 41
    .line 42
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    check-cast v4, Landroid/content/res/Resources;

    .line 47
    .line 48
    iget v0, v0, Li40/c1;->e:I

    .line 49
    .line 50
    invoke-virtual {v4, v0}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    or-int/2addr v4, v5

    .line 63
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v5

    .line 67
    if-nez v4, :cond_0

    .line 68
    .line 69
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 70
    .line 71
    if-ne v5, v4, :cond_1

    .line 72
    .line 73
    :cond_0
    new-instance v5, Lh70/n;

    .line 74
    .line 75
    const/4 v4, 0x2

    .line 76
    invoke-direct {v5, v0, v1, v4}, Lh70/n;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :cond_1
    check-cast v5, Lay0/a;

    .line 83
    .line 84
    invoke-static {v2, v5}, Lxf0/i0;->K(Lx2/s;Lay0/a;)Lx2/s;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    invoke-static {v1, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    const/4 v1, 0x0

    .line 96
    invoke-virtual {v3, v1}, Ll2/t;->q(Z)V

    .line 97
    .line 98
    .line 99
    return-object v0

    .line 100
    :pswitch_0
    iget-object v1, v0, Li40/c1;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v1, Lh40/j4;

    .line 103
    .line 104
    move-object/from16 v2, p1

    .line 105
    .line 106
    check-cast v2, Landroidx/compose/foundation/lazy/a;

    .line 107
    .line 108
    move-object/from16 v3, p2

    .line 109
    .line 110
    check-cast v3, Ll2/o;

    .line 111
    .line 112
    move-object/from16 v4, p3

    .line 113
    .line 114
    check-cast v4, Ljava/lang/Integer;

    .line 115
    .line 116
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    const-string v5, "$this$item"

    .line 121
    .line 122
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    and-int/lit8 v2, v4, 0x11

    .line 126
    .line 127
    const/16 v5, 0x10

    .line 128
    .line 129
    const/4 v6, 0x1

    .line 130
    const/4 v7, 0x0

    .line 131
    if-eq v2, v5, :cond_2

    .line 132
    .line 133
    move v2, v6

    .line 134
    goto :goto_0

    .line 135
    :cond_2
    move v2, v7

    .line 136
    :goto_0
    and-int/2addr v4, v6

    .line 137
    check-cast v3, Ll2/t;

    .line 138
    .line 139
    invoke-virtual {v3, v4, v2}, Ll2/t;->O(IZ)Z

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    if-eqz v2, :cond_4

    .line 144
    .line 145
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 146
    .line 147
    iget v0, v0, Li40/c1;->e:I

    .line 148
    .line 149
    if-eqz v0, :cond_3

    .line 150
    .line 151
    const v0, -0x665458b

    .line 152
    .line 153
    .line 154
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 155
    .line 156
    .line 157
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 158
    .line 159
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    check-cast v0, Lj91/c;

    .line 164
    .line 165
    iget v0, v0, Lj91/c;->k:F

    .line 166
    .line 167
    const/4 v4, 0x0

    .line 168
    const/4 v5, 0x2

    .line 169
    invoke-static {v2, v0, v4, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    invoke-static {v7, v7, v3, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 174
    .line 175
    .line 176
    :goto_1
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 177
    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_3
    const v0, 0x396eca8d

    .line 181
    .line 182
    .line 183
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 184
    .line 185
    .line 186
    goto :goto_1

    .line 187
    :goto_2
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 188
    .line 189
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    check-cast v4, Lj91/c;

    .line 194
    .line 195
    iget v4, v4, Lj91/c;->k:F

    .line 196
    .line 197
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    check-cast v0, Lj91/c;

    .line 202
    .line 203
    iget v0, v0, Lj91/c;->c:F

    .line 204
    .line 205
    invoke-static {v2, v4, v0}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    invoke-static {v1, v0, v3, v7}, Li40/l1;->q0(Lh40/j4;Lx2/s;Ll2/o;I)V

    .line 210
    .line 211
    .line 212
    goto :goto_3

    .line 213
    :cond_4
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 214
    .line 215
    .line 216
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 217
    .line 218
    return-object v0

    .line 219
    :pswitch_1
    iget-object v1, v0, Li40/c1;->f:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v1, Lh40/n1;

    .line 222
    .line 223
    move-object/from16 v2, p1

    .line 224
    .line 225
    check-cast v2, Landroidx/compose/foundation/lazy/a;

    .line 226
    .line 227
    move-object/from16 v3, p2

    .line 228
    .line 229
    check-cast v3, Ll2/o;

    .line 230
    .line 231
    move-object/from16 v4, p3

    .line 232
    .line 233
    check-cast v4, Ljava/lang/Integer;

    .line 234
    .line 235
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 236
    .line 237
    .line 238
    move-result v4

    .line 239
    const-string v5, "$this$item"

    .line 240
    .line 241
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    and-int/lit8 v2, v4, 0x11

    .line 245
    .line 246
    const/16 v5, 0x10

    .line 247
    .line 248
    const/4 v6, 0x1

    .line 249
    const/4 v7, 0x0

    .line 250
    if-eq v2, v5, :cond_5

    .line 251
    .line 252
    move v2, v6

    .line 253
    goto :goto_4

    .line 254
    :cond_5
    move v2, v7

    .line 255
    :goto_4
    and-int/2addr v4, v6

    .line 256
    check-cast v3, Ll2/t;

    .line 257
    .line 258
    invoke-virtual {v3, v4, v2}, Ll2/t;->O(IZ)Z

    .line 259
    .line 260
    .line 261
    move-result v2

    .line 262
    if-eqz v2, :cond_7

    .line 263
    .line 264
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 265
    .line 266
    iget v0, v0, Li40/c1;->e:I

    .line 267
    .line 268
    if-eqz v0, :cond_6

    .line 269
    .line 270
    const v0, -0x1e120870

    .line 271
    .line 272
    .line 273
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 274
    .line 275
    .line 276
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 277
    .line 278
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    check-cast v0, Lj91/c;

    .line 283
    .line 284
    iget v0, v0, Lj91/c;->f:F

    .line 285
    .line 286
    invoke-static {v2, v0, v3, v7}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 287
    .line 288
    .line 289
    goto :goto_5

    .line 290
    :cond_6
    const v0, 0x5b8cf831

    .line 291
    .line 292
    .line 293
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 297
    .line 298
    .line 299
    :goto_5
    iget-object v8, v1, Lh40/n1;->a:Ljava/lang/String;

    .line 300
    .line 301
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 302
    .line 303
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    check-cast v0, Lj91/f;

    .line 308
    .line 309
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 310
    .line 311
    .line 312
    move-result-object v9

    .line 313
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 314
    .line 315
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v1

    .line 319
    check-cast v1, Lj91/c;

    .line 320
    .line 321
    iget v1, v1, Lj91/c;->k:F

    .line 322
    .line 323
    const/4 v4, 0x0

    .line 324
    const/4 v5, 0x2

    .line 325
    invoke-static {v2, v1, v4, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 326
    .line 327
    .line 328
    move-result-object v10

    .line 329
    const/16 v28, 0x0

    .line 330
    .line 331
    const v29, 0xfff8

    .line 332
    .line 333
    .line 334
    const-wide/16 v11, 0x0

    .line 335
    .line 336
    const-wide/16 v13, 0x0

    .line 337
    .line 338
    const/4 v15, 0x0

    .line 339
    const-wide/16 v16, 0x0

    .line 340
    .line 341
    const/16 v18, 0x0

    .line 342
    .line 343
    const/16 v19, 0x0

    .line 344
    .line 345
    const-wide/16 v20, 0x0

    .line 346
    .line 347
    const/16 v22, 0x0

    .line 348
    .line 349
    const/16 v23, 0x0

    .line 350
    .line 351
    const/16 v24, 0x0

    .line 352
    .line 353
    const/16 v25, 0x0

    .line 354
    .line 355
    const/16 v27, 0x0

    .line 356
    .line 357
    move-object/from16 v26, v3

    .line 358
    .line 359
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 360
    .line 361
    .line 362
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v0

    .line 366
    check-cast v0, Lj91/c;

    .line 367
    .line 368
    iget v0, v0, Lj91/c;->d:F

    .line 369
    .line 370
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 371
    .line 372
    .line 373
    move-result-object v0

    .line 374
    invoke-static {v3, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 375
    .line 376
    .line 377
    goto :goto_6

    .line 378
    :cond_7
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 379
    .line 380
    .line 381
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 382
    .line 383
    return-object v0

    .line 384
    nop

    .line 385
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

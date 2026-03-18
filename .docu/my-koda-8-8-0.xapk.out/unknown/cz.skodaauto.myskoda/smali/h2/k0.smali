.class public final Lh2/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/a;Lx2/s;ZLj3/f;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh2/k0;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/k0;->f:Ljava/lang/Object;

    iput-object p2, p0, Lh2/k0;->g:Ljava/lang/Object;

    iput-boolean p3, p0, Lh2/k0;->e:Z

    iput-object p4, p0, Lh2/k0;->h:Ljava/lang/Object;

    iput-object p5, p0, Lh2/k0;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh2/r8;Lay0/n;Lt2/b;Lvy0/b0;Z)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lh2/k0;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/k0;->f:Ljava/lang/Object;

    iput-object p2, p0, Lh2/k0;->g:Ljava/lang/Object;

    iput-object p3, p0, Lh2/k0;->h:Ljava/lang/Object;

    iput-object p4, p0, Lh2/k0;->i:Ljava/lang/Object;

    iput-boolean p5, p0, Lh2/k0;->e:Z

    return-void
.end method

.method public constructor <init>(Lx2/s;ZLh2/x7;Lay0/a;Lt2/b;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lh2/k0;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/k0;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Lh2/k0;->e:Z

    iput-object p3, p0, Lh2/k0;->g:Ljava/lang/Object;

    iput-object p4, p0, Lh2/k0;->i:Ljava/lang/Object;

    iput-object p5, p0, Lh2/k0;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lh2/k0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eqz p2, :cond_4

    .line 31
    .line 32
    iget-object p2, p0, Lh2/k0;->f:Ljava/lang/Object;

    .line 33
    .line 34
    move-object v3, p2

    .line 35
    check-cast v3, Lx2/s;

    .line 36
    .line 37
    iget-object p2, p0, Lh2/k0;->g:Ljava/lang/Object;

    .line 38
    .line 39
    move-object v6, p2

    .line 40
    check-cast v6, Le1/s0;

    .line 41
    .line 42
    new-instance v8, Ld4/i;

    .line 43
    .line 44
    const/4 p2, 0x4

    .line 45
    invoke-direct {v8, p2}, Ld4/i;-><init>(I)V

    .line 46
    .line 47
    .line 48
    iget-object p2, p0, Lh2/k0;->i:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v9, p2

    .line 51
    check-cast v9, Lay0/a;

    .line 52
    .line 53
    iget-boolean v4, p0, Lh2/k0;->e:Z

    .line 54
    .line 55
    const/4 v5, 0x0

    .line 56
    const/4 v7, 0x1

    .line 57
    invoke-static/range {v3 .. v9}, Landroidx/compose/foundation/selection/b;->a(Lx2/s;ZLi1/l;Le1/s0;ZLd4/i;Lay0/a;)Lx2/s;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    const/high16 v0, 0x3f800000    # 1.0f

    .line 62
    .line 63
    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    sget-object v0, Lx2/c;->q:Lx2/h;

    .line 68
    .line 69
    sget-object v1, Lk1/j;->e:Lk1/f;

    .line 70
    .line 71
    iget-object p0, p0, Lh2/k0;->h:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p0, Lt2/b;

    .line 74
    .line 75
    const/16 v3, 0x36

    .line 76
    .line 77
    invoke-static {v1, v0, p1, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    iget-wide v3, p1, Ll2/t;->T:J

    .line 82
    .line 83
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 96
    .line 97
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 101
    .line 102
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 103
    .line 104
    .line 105
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 106
    .line 107
    if-eqz v5, :cond_1

    .line 108
    .line 109
    invoke-virtual {p1, v4}, Ll2/t;->l(Lay0/a;)V

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 114
    .line 115
    .line 116
    :goto_1
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 117
    .line 118
    invoke-static {v4, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 119
    .line 120
    .line 121
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 122
    .line 123
    invoke-static {v0, v3, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 124
    .line 125
    .line 126
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 127
    .line 128
    iget-boolean v3, p1, Ll2/t;->S:Z

    .line 129
    .line 130
    if-nez v3, :cond_2

    .line 131
    .line 132
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v3

    .line 144
    if-nez v3, :cond_3

    .line 145
    .line 146
    :cond_2
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 147
    .line 148
    .line 149
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 150
    .line 151
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 152
    .line 153
    .line 154
    const/4 p2, 0x6

    .line 155
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object p2

    .line 159
    sget-object v0, Lk1/t;->a:Lk1/t;

    .line 160
    .line 161
    invoke-virtual {p0, v0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 165
    .line 166
    .line 167
    goto :goto_2

    .line 168
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 169
    .line 170
    .line 171
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 172
    .line 173
    return-object p0

    .line 174
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 175
    .line 176
    check-cast p2, Ljava/lang/Number;

    .line 177
    .line 178
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 179
    .line 180
    .line 181
    move-result p2

    .line 182
    and-int/lit8 v0, p2, 0x3

    .line 183
    .line 184
    const/4 v1, 0x2

    .line 185
    const/4 v2, 0x1

    .line 186
    if-eq v0, v1, :cond_5

    .line 187
    .line 188
    move v0, v2

    .line 189
    goto :goto_3

    .line 190
    :cond_5
    const/4 v0, 0x0

    .line 191
    :goto_3
    and-int/2addr p2, v2

    .line 192
    move-object v7, p1

    .line 193
    check-cast v7, Ll2/t;

    .line 194
    .line 195
    invoke-virtual {v7, p2, v0}, Ll2/t;->O(IZ)Z

    .line 196
    .line 197
    .line 198
    move-result p1

    .line 199
    if-eqz p1, :cond_6

    .line 200
    .line 201
    iget-object p1, p0, Lh2/k0;->f:Ljava/lang/Object;

    .line 202
    .line 203
    move-object v1, p1

    .line 204
    check-cast v1, Lay0/a;

    .line 205
    .line 206
    iget-object p1, p0, Lh2/k0;->g:Ljava/lang/Object;

    .line 207
    .line 208
    move-object v2, p1

    .line 209
    check-cast v2, Lx2/s;

    .line 210
    .line 211
    new-instance p1, Laa/p;

    .line 212
    .line 213
    iget-object p2, p0, Lh2/k0;->h:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast p2, Lj3/f;

    .line 216
    .line 217
    iget-object v0, p0, Lh2/k0;->i:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v0, Ljava/lang/String;

    .line 220
    .line 221
    const/4 v3, 0x6

    .line 222
    invoke-direct {p1, v3, p2, v0}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    const p2, -0x4d8cfcf8

    .line 226
    .line 227
    .line 228
    invoke-static {p2, v7, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 229
    .line 230
    .line 231
    move-result-object v6

    .line 232
    const/high16 v8, 0x180000

    .line 233
    .line 234
    const/16 v9, 0x38

    .line 235
    .line 236
    iget-boolean v3, p0, Lh2/k0;->e:Z

    .line 237
    .line 238
    const/4 v4, 0x0

    .line 239
    const/4 v5, 0x0

    .line 240
    invoke-static/range {v1 .. v9}, Lh2/r;->l(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;Ll2/o;II)V

    .line 241
    .line 242
    .line 243
    goto :goto_4

    .line 244
    :cond_6
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 245
    .line 246
    .line 247
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 248
    .line 249
    return-object p0

    .line 250
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 251
    .line 252
    check-cast p2, Ljava/lang/Number;

    .line 253
    .line 254
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 255
    .line 256
    .line 257
    move-result p2

    .line 258
    and-int/lit8 v0, p2, 0x3

    .line 259
    .line 260
    const/4 v1, 0x2

    .line 261
    const/4 v2, 0x1

    .line 262
    const/4 v3, 0x0

    .line 263
    if-eq v0, v1, :cond_7

    .line 264
    .line 265
    move v0, v2

    .line 266
    goto :goto_5

    .line 267
    :cond_7
    move v0, v3

    .line 268
    :goto_5
    and-int/2addr p2, v2

    .line 269
    check-cast p1, Ll2/t;

    .line 270
    .line 271
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 272
    .line 273
    .line 274
    move-result p2

    .line 275
    if-eqz p2, :cond_c

    .line 276
    .line 277
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 278
    .line 279
    const/high16 v0, 0x3f800000    # 1.0f

    .line 280
    .line 281
    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 282
    .line 283
    .line 284
    move-result-object p2

    .line 285
    iget-object v0, p0, Lh2/k0;->f:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast v0, Lh2/r8;

    .line 288
    .line 289
    new-instance v1, Lh2/z;

    .line 290
    .line 291
    const/4 v4, 0x0

    .line 292
    invoke-direct {v1, v0, v4}, Lh2/z;-><init>(Lh2/r8;I)V

    .line 293
    .line 294
    .line 295
    invoke-static {p2, v1}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 296
    .line 297
    .line 298
    move-result-object p2

    .line 299
    iget-object v0, p0, Lh2/k0;->g:Ljava/lang/Object;

    .line 300
    .line 301
    move-object v11, v0

    .line 302
    check-cast v11, Lay0/n;

    .line 303
    .line 304
    iget-object v0, p0, Lh2/k0;->h:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast v0, Lt2/b;

    .line 307
    .line 308
    iget-object v1, p0, Lh2/k0;->f:Ljava/lang/Object;

    .line 309
    .line 310
    move-object v5, v1

    .line 311
    check-cast v5, Lh2/r8;

    .line 312
    .line 313
    iget-object v1, p0, Lh2/k0;->i:Ljava/lang/Object;

    .line 314
    .line 315
    move-object v6, v1

    .line 316
    check-cast v6, Lvy0/b0;

    .line 317
    .line 318
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 319
    .line 320
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 321
    .line 322
    invoke-static {v1, v4, p1, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 323
    .line 324
    .line 325
    move-result-object v1

    .line 326
    iget-wide v7, p1, Ll2/t;->T:J

    .line 327
    .line 328
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 329
    .line 330
    .line 331
    move-result v4

    .line 332
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 333
    .line 334
    .line 335
    move-result-object v7

    .line 336
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 337
    .line 338
    .line 339
    move-result-object p2

    .line 340
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 341
    .line 342
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 343
    .line 344
    .line 345
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 346
    .line 347
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 348
    .line 349
    .line 350
    iget-boolean v9, p1, Ll2/t;->S:Z

    .line 351
    .line 352
    if-eqz v9, :cond_8

    .line 353
    .line 354
    invoke-virtual {p1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 355
    .line 356
    .line 357
    goto :goto_6

    .line 358
    :cond_8
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 359
    .line 360
    .line 361
    :goto_6
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 362
    .line 363
    invoke-static {v8, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 364
    .line 365
    .line 366
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 367
    .line 368
    invoke-static {v1, v7, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 369
    .line 370
    .line 371
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 372
    .line 373
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 374
    .line 375
    if-nez v7, :cond_9

    .line 376
    .line 377
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v7

    .line 381
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 382
    .line 383
    .line 384
    move-result-object v8

    .line 385
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 386
    .line 387
    .line 388
    move-result v7

    .line 389
    if-nez v7, :cond_a

    .line 390
    .line 391
    :cond_9
    invoke-static {v4, p1, v4, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 392
    .line 393
    .line 394
    :cond_a
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 395
    .line 396
    invoke-static {v1, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 397
    .line 398
    .line 399
    if-eqz v11, :cond_b

    .line 400
    .line 401
    const p2, -0x3e3b373f

    .line 402
    .line 403
    .line 404
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 405
    .line 406
    .line 407
    const p2, 0x7f12058e

    .line 408
    .line 409
    .line 410
    invoke-static {p1, p2}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v9

    .line 414
    const p2, 0x7f12058f

    .line 415
    .line 416
    .line 417
    invoke-static {p1, p2}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object v10

    .line 421
    const p2, 0x7f120591

    .line 422
    .line 423
    .line 424
    invoke-static {p1, p2}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 425
    .line 426
    .line 427
    move-result-object v8

    .line 428
    new-instance v4, Lh2/j0;

    .line 429
    .line 430
    iget-boolean v7, p0, Lh2/k0;->e:Z

    .line 431
    .line 432
    invoke-direct/range {v4 .. v11}, Lh2/j0;-><init>(Lh2/r8;Lvy0/b0;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/n;)V

    .line 433
    .line 434
    .line 435
    const p0, -0x1e7fc9a8

    .line 436
    .line 437
    .line 438
    invoke-static {p0, p1, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 439
    .line 440
    .line 441
    move-result-object p0

    .line 442
    const/16 p2, 0x36

    .line 443
    .line 444
    invoke-static {p0, p1, p2}, Lh2/m8;->a(Lt2/b;Ll2/o;I)V

    .line 445
    .line 446
    .line 447
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 448
    .line 449
    .line 450
    goto :goto_7

    .line 451
    :cond_b
    const p0, -0x3e011e45

    .line 452
    .line 453
    .line 454
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 455
    .line 456
    .line 457
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 458
    .line 459
    .line 460
    :goto_7
    const/4 p0, 0x6

    .line 461
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 462
    .line 463
    .line 464
    move-result-object p0

    .line 465
    sget-object p2, Lk1/t;->a:Lk1/t;

    .line 466
    .line 467
    invoke-virtual {v0, p2, p1, p0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 468
    .line 469
    .line 470
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 471
    .line 472
    .line 473
    goto :goto_8

    .line 474
    :cond_c
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 475
    .line 476
    .line 477
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 478
    .line 479
    return-object p0

    .line 480
    nop

    .line 481
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

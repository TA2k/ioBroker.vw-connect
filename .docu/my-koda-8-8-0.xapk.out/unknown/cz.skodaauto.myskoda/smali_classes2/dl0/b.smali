.class public final synthetic Ldl0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Ldl0/b;->d:I

    iput-object p1, p0, Ldl0/b;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Ldl0/b;->e:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Object;I)V
    .locals 0

    .line 2
    iput p3, p0, Ldl0/b;->d:I

    iput-boolean p1, p0, Ldl0/b;->e:Z

    iput-object p2, p0, Ldl0/b;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ldl0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ldl0/b;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v8, v0

    .line 9
    check-cast v8, Le3/n0;

    .line 10
    .line 11
    check-cast p1, Lx2/s;

    .line 12
    .line 13
    check-cast p2, Ll2/o;

    .line 14
    .line 15
    check-cast p3, Ljava/lang/Integer;

    .line 16
    .line 17
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    const-string p3, "$this$composed"

    .line 21
    .line 22
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    check-cast p2, Ll2/t;

    .line 26
    .line 27
    const p3, -0x6fc7c85a

    .line 28
    .line 29
    .line 30
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 31
    .line 32
    .line 33
    sget-object p3, Lj91/h;->a:Ll2/u2;

    .line 34
    .line 35
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Lj91/e;

    .line 40
    .line 41
    invoke-virtual {v0}, Lj91/e;->o()J

    .line 42
    .line 43
    .line 44
    move-result-wide v0

    .line 45
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    check-cast v2, Lj91/e;

    .line 50
    .line 51
    invoke-virtual {v2}, Lj91/e;->h()J

    .line 52
    .line 53
    .line 54
    move-result-wide v2

    .line 55
    invoke-static {v0, v1, v2, v3}, Le3/j0;->l(JJ)J

    .line 56
    .line 57
    .line 58
    move-result-wide v0

    .line 59
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 64
    .line 65
    if-ne v2, v3, :cond_0

    .line 66
    .line 67
    const/16 v2, 0x320

    .line 68
    .line 69
    const/16 v3, 0xc8

    .line 70
    .line 71
    const/4 v4, 0x0

    .line 72
    const/4 v5, 0x4

    .line 73
    invoke-static {v2, v3, v4, v5}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    sget-object v3, Lc1/t0;->e:Lc1/t0;

    .line 78
    .line 79
    invoke-static {v2, v3, v5}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    new-instance v3, Lmn/a;

    .line 84
    .line 85
    invoke-direct {v3, v0, v1, v2}, Lmn/a;-><init>(JLc1/f0;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move-object v2, v3

    .line 92
    :cond_0
    move-object v4, v2

    .line 93
    check-cast v4, Lmn/a;

    .line 94
    .line 95
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p3

    .line 99
    check-cast p3, Lj91/e;

    .line 100
    .line 101
    invoke-virtual {p3}, Lj91/e;->d()J

    .line 102
    .line 103
    .line 104
    move-result-wide v6

    .line 105
    sget-object v2, Lmn/b;->g:Lmn/b;

    .line 106
    .line 107
    sget-object v3, Lmn/b;->h:Lmn/b;

    .line 108
    .line 109
    const-string p3, "shape"

    .line 110
    .line 111
    invoke-static {v8, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    new-instance v1, Lmn/d;

    .line 115
    .line 116
    iget-boolean v5, p0, Ldl0/b;->e:Z

    .line 117
    .line 118
    invoke-direct/range {v1 .. v8}, Lmn/d;-><init>(Lay0/o;Lay0/o;Lmn/a;ZJLe3/n0;)V

    .line 119
    .line 120
    .line 121
    invoke-static {p1, v1}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    const/4 p1, 0x0

    .line 126
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 127
    .line 128
    .line 129
    return-object p0

    .line 130
    :pswitch_0
    iget-object v0, p0, Ldl0/b;->f:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v0, Lm70/x0;

    .line 133
    .line 134
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 135
    .line 136
    check-cast p2, Ll2/o;

    .line 137
    .line 138
    check-cast p3, Ljava/lang/Integer;

    .line 139
    .line 140
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 141
    .line 142
    .line 143
    move-result p3

    .line 144
    const-string v1, "$this$item"

    .line 145
    .line 146
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    and-int/lit8 p1, p3, 0x11

    .line 150
    .line 151
    const/16 v1, 0x10

    .line 152
    .line 153
    const/4 v2, 0x0

    .line 154
    const/4 v3, 0x1

    .line 155
    if-eq p1, v1, :cond_1

    .line 156
    .line 157
    move p1, v3

    .line 158
    goto :goto_0

    .line 159
    :cond_1
    move p1, v2

    .line 160
    :goto_0
    and-int/2addr p3, v3

    .line 161
    check-cast p2, Ll2/t;

    .line 162
    .line 163
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 164
    .line 165
    .line 166
    move-result p1

    .line 167
    if-eqz p1, :cond_2

    .line 168
    .line 169
    iget-boolean p0, p0, Ldl0/b;->e:Z

    .line 170
    .line 171
    invoke-static {v0, p0, p2, v2}, Ln70/a;->g(Lm70/x0;ZLl2/o;I)V

    .line 172
    .line 173
    .line 174
    goto :goto_1

    .line 175
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 176
    .line 177
    .line 178
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    return-object p0

    .line 181
    :pswitch_1
    iget-object v0, p0, Ldl0/b;->f:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v0, Lj2/p;

    .line 184
    .line 185
    check-cast p1, Lk1/q;

    .line 186
    .line 187
    check-cast p2, Ll2/o;

    .line 188
    .line 189
    check-cast p3, Ljava/lang/Integer;

    .line 190
    .line 191
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 192
    .line 193
    .line 194
    move-result p3

    .line 195
    const-string v1, "$this$PullToRefreshBox"

    .line 196
    .line 197
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    and-int/lit8 v1, p3, 0x6

    .line 201
    .line 202
    if-nez v1, :cond_4

    .line 203
    .line 204
    move-object v1, p2

    .line 205
    check-cast v1, Ll2/t;

    .line 206
    .line 207
    invoke-virtual {v1, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    if-eqz v1, :cond_3

    .line 212
    .line 213
    const/4 v1, 0x4

    .line 214
    goto :goto_2

    .line 215
    :cond_3
    const/4 v1, 0x2

    .line 216
    :goto_2
    or-int/2addr p3, v1

    .line 217
    :cond_4
    and-int/lit8 v1, p3, 0x13

    .line 218
    .line 219
    const/16 v2, 0x12

    .line 220
    .line 221
    if-eq v1, v2, :cond_5

    .line 222
    .line 223
    const/4 v1, 0x1

    .line 224
    goto :goto_3

    .line 225
    :cond_5
    const/4 v1, 0x0

    .line 226
    :goto_3
    and-int/lit8 v2, p3, 0x1

    .line 227
    .line 228
    check-cast p2, Ll2/t;

    .line 229
    .line 230
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 231
    .line 232
    .line 233
    move-result v1

    .line 234
    if-eqz v1, :cond_6

    .line 235
    .line 236
    and-int/lit8 p3, p3, 0xe

    .line 237
    .line 238
    iget-boolean p0, p0, Ldl0/b;->e:Z

    .line 239
    .line 240
    invoke-static {p1, v0, p0, p2, p3}, Lxf0/y1;->j(Lk1/q;Lj2/p;ZLl2/o;I)V

    .line 241
    .line 242
    .line 243
    goto :goto_4

    .line 244
    :cond_6
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 245
    .line 246
    .line 247
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 248
    .line 249
    return-object p0

    .line 250
    :pswitch_2
    iget-object v0, p0, Ldl0/b;->f:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v0, Lay0/a;

    .line 253
    .line 254
    move-object v1, p1

    .line 255
    check-cast v1, Li91/k2;

    .line 256
    .line 257
    check-cast p2, Ll2/o;

    .line 258
    .line 259
    check-cast p3, Ljava/lang/Integer;

    .line 260
    .line 261
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 262
    .line 263
    .line 264
    move-result p1

    .line 265
    const-string p3, "$this$MaulBasicListItem"

    .line 266
    .line 267
    invoke-static {v1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    and-int/lit8 p3, p1, 0x6

    .line 271
    .line 272
    if-nez p3, :cond_9

    .line 273
    .line 274
    and-int/lit8 p3, p1, 0x8

    .line 275
    .line 276
    if-nez p3, :cond_7

    .line 277
    .line 278
    move-object p3, p2

    .line 279
    check-cast p3, Ll2/t;

    .line 280
    .line 281
    invoke-virtual {p3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result p3

    .line 285
    goto :goto_5

    .line 286
    :cond_7
    move-object p3, p2

    .line 287
    check-cast p3, Ll2/t;

    .line 288
    .line 289
    invoke-virtual {p3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    move-result p3

    .line 293
    :goto_5
    if-eqz p3, :cond_8

    .line 294
    .line 295
    const/4 p3, 0x4

    .line 296
    goto :goto_6

    .line 297
    :cond_8
    const/4 p3, 0x2

    .line 298
    :goto_6
    or-int/2addr p1, p3

    .line 299
    :cond_9
    and-int/lit8 p3, p1, 0x13

    .line 300
    .line 301
    const/16 v2, 0x12

    .line 302
    .line 303
    if-eq p3, v2, :cond_a

    .line 304
    .line 305
    const/4 p3, 0x1

    .line 306
    goto :goto_7

    .line 307
    :cond_a
    const/4 p3, 0x0

    .line 308
    :goto_7
    and-int/lit8 v2, p1, 0x1

    .line 309
    .line 310
    move-object v7, p2

    .line 311
    check-cast v7, Ll2/t;

    .line 312
    .line 313
    invoke-virtual {v7, v2, p3}, Ll2/t;->O(IZ)Z

    .line 314
    .line 315
    .line 316
    move-result p2

    .line 317
    if-eqz p2, :cond_c

    .line 318
    .line 319
    new-instance v2, Li91/o1;

    .line 320
    .line 321
    iget-boolean p0, p0, Ldl0/b;->e:Z

    .line 322
    .line 323
    if-eqz p0, :cond_b

    .line 324
    .line 325
    sget-object p0, Li91/i1;->e:Li91/i1;

    .line 326
    .line 327
    goto :goto_8

    .line 328
    :cond_b
    sget-object p0, Li91/i1;->f:Li91/i1;

    .line 329
    .line 330
    :goto_8
    invoke-direct {v2, p0, v0}, Li91/o1;-><init>(Li91/i1;Lay0/a;)V

    .line 331
    .line 332
    .line 333
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 334
    .line 335
    invoke-virtual {v7, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object p0

    .line 339
    check-cast p0, Lj91/e;

    .line 340
    .line 341
    invoke-virtual {p0}, Lj91/e;->q()J

    .line 342
    .line 343
    .line 344
    move-result-wide v4

    .line 345
    shl-int/lit8 p0, p1, 0xc

    .line 346
    .line 347
    const p1, 0xe000

    .line 348
    .line 349
    .line 350
    and-int/2addr p0, p1

    .line 351
    const/16 p1, 0xc30

    .line 352
    .line 353
    or-int v8, p1, p0

    .line 354
    .line 355
    const/4 v3, 0x1

    .line 356
    const/4 v6, 0x0

    .line 357
    invoke-virtual/range {v1 .. v8}, Li91/k2;->c(Li91/v1;ZJLjava/lang/String;Ll2/o;I)V

    .line 358
    .line 359
    .line 360
    goto :goto_9

    .line 361
    :cond_c
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 362
    .line 363
    .line 364
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 365
    .line 366
    return-object p0

    .line 367
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

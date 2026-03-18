.class public abstract Lmc/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Llk/b;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1}, Llk/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lt2/b;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const v3, 0x253f8b6

    .line 11
    .line 12
    .line 13
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 14
    .line 15
    .line 16
    sput-object v1, Lmc/s;->a:Lt2/b;

    .line 17
    .line 18
    return-void
.end method

.method public static final a(Lmc/r;Lac/e;Lay0/k;Lay0/a;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v0, "goForward"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "goBack"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v6, p4

    .line 12
    check-cast v6, Ll2/t;

    .line 13
    .line 14
    const p4, -0x7cba45eb

    .line 15
    .line 16
    .line 17
    invoke-virtual {v6, p4}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    and-int/lit8 p4, p5, 0x30

    .line 21
    .line 22
    const/16 v0, 0x20

    .line 23
    .line 24
    if-nez p4, :cond_1

    .line 25
    .line 26
    invoke-virtual {v6, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result p4

    .line 30
    if-eqz p4, :cond_0

    .line 31
    .line 32
    move p4, v0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/16 p4, 0x10

    .line 35
    .line 36
    :goto_0
    or-int/2addr p4, p5

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move p4, p5

    .line 39
    :goto_1
    invoke-virtual {v6, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    const/16 v2, 0x100

    .line 44
    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    move v1, v2

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v1, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr p4, v1

    .line 52
    invoke-virtual {v6, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    const/16 v3, 0x800

    .line 57
    .line 58
    if-eqz v1, :cond_3

    .line 59
    .line 60
    move v1, v3

    .line 61
    goto :goto_3

    .line 62
    :cond_3
    const/16 v1, 0x400

    .line 63
    .line 64
    :goto_3
    or-int/2addr p4, v1

    .line 65
    and-int/lit16 v1, p4, 0x493

    .line 66
    .line 67
    const/16 v4, 0x492

    .line 68
    .line 69
    const/4 v7, 0x1

    .line 70
    const/4 v8, 0x0

    .line 71
    if-eq v1, v4, :cond_4

    .line 72
    .line 73
    move v1, v7

    .line 74
    goto :goto_4

    .line 75
    :cond_4
    move v1, v8

    .line 76
    :goto_4
    and-int/lit8 v4, p4, 0x1

    .line 77
    .line 78
    invoke-virtual {v6, v4, v1}, Ll2/t;->O(IZ)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_10

    .line 83
    .line 84
    and-int/lit8 v1, p4, 0x70

    .line 85
    .line 86
    if-eq v1, v0, :cond_5

    .line 87
    .line 88
    move v0, v8

    .line 89
    goto :goto_5

    .line 90
    :cond_5
    move v0, v7

    .line 91
    :goto_5
    and-int/lit16 v1, p4, 0x380

    .line 92
    .line 93
    if-ne v1, v2, :cond_6

    .line 94
    .line 95
    move v1, v7

    .line 96
    goto :goto_6

    .line 97
    :cond_6
    move v1, v8

    .line 98
    :goto_6
    or-int/2addr v0, v1

    .line 99
    and-int/lit16 p4, p4, 0x1c00

    .line 100
    .line 101
    if-ne p4, v3, :cond_7

    .line 102
    .line 103
    move p4, v7

    .line 104
    goto :goto_7

    .line 105
    :cond_7
    move p4, v8

    .line 106
    :goto_7
    or-int/2addr p4, v0

    .line 107
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 112
    .line 113
    if-nez p4, :cond_8

    .line 114
    .line 115
    if-ne v0, v9, :cond_9

    .line 116
    .line 117
    :cond_8
    new-instance v0, Lkv0/e;

    .line 118
    .line 119
    const/4 p4, 0x2

    .line 120
    invoke-direct {v0, p1, p2, p3, p4}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :cond_9
    check-cast v0, Lay0/k;

    .line 127
    .line 128
    sget-object p4, Lw3/q1;->a:Ll2/u2;

    .line 129
    .line 130
    invoke-virtual {v6, p4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p4

    .line 134
    check-cast p4, Ljava/lang/Boolean;

    .line 135
    .line 136
    invoke-virtual {p4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 137
    .line 138
    .line 139
    move-result p4

    .line 140
    if-eqz p4, :cond_a

    .line 141
    .line 142
    const p4, -0x105bcaaa

    .line 143
    .line 144
    .line 145
    invoke-virtual {v6, p4}, Ll2/t;->Y(I)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    const/4 p4, 0x0

    .line 152
    goto :goto_8

    .line 153
    :cond_a
    const p4, 0x31054eee

    .line 154
    .line 155
    .line 156
    invoke-virtual {v6, p4}, Ll2/t;->Y(I)V

    .line 157
    .line 158
    .line 159
    sget-object p4, Lzb/x;->a:Ll2/u2;

    .line 160
    .line 161
    invoke-virtual {v6, p4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p4

    .line 165
    check-cast p4, Lhi/a;

    .line 166
    .line 167
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    .line 168
    .line 169
    .line 170
    :goto_8
    new-instance v4, Lvh/i;

    .line 171
    .line 172
    const/16 v1, 0x9

    .line 173
    .line 174
    invoke-direct {v4, v1, p4, v0}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    invoke-static {v6}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 178
    .line 179
    .line 180
    move-result-object v2

    .line 181
    if-eqz v2, :cond_f

    .line 182
    .line 183
    instance-of p4, v2, Landroidx/lifecycle/k;

    .line 184
    .line 185
    if-eqz p4, :cond_b

    .line 186
    .line 187
    move-object p4, v2

    .line 188
    check-cast p4, Landroidx/lifecycle/k;

    .line 189
    .line 190
    invoke-interface {p4}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 191
    .line 192
    .line 193
    move-result-object p4

    .line 194
    :goto_9
    move-object v5, p4

    .line 195
    goto :goto_a

    .line 196
    :cond_b
    sget-object p4, Lp7/a;->b:Lp7/a;

    .line 197
    .line 198
    goto :goto_9

    .line 199
    :goto_a
    const-class p4, Lmc/p;

    .line 200
    .line 201
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 202
    .line 203
    invoke-virtual {v0, p4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 204
    .line 205
    .line 206
    move-result-object v1

    .line 207
    const/4 v3, 0x0

    .line 208
    invoke-static/range {v1 .. v6}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 209
    .line 210
    .line 211
    move-result-object p4

    .line 212
    check-cast p4, Lmc/p;

    .line 213
    .line 214
    invoke-virtual {v6, p4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v0

    .line 218
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v1

    .line 222
    if-nez v0, :cond_c

    .line 223
    .line 224
    if-ne v1, v9, :cond_d

    .line 225
    .line 226
    :cond_c
    new-instance v1, Lmc/e;

    .line 227
    .line 228
    const/4 v0, 0x0

    .line 229
    invoke-direct {v1, p4, v0}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v6, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    :cond_d
    check-cast v1, Lay0/a;

    .line 236
    .line 237
    invoke-static {v8, v1, v6, v8, v7}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 238
    .line 239
    .line 240
    iget-object v0, p4, Lmc/p;->n:Lyy0/l1;

    .line 241
    .line 242
    invoke-static {v0, v6}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 243
    .line 244
    .line 245
    move-result-object v0

    .line 246
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    check-cast v0, Ljava/lang/Boolean;

    .line 251
    .line 252
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 253
    .line 254
    .line 255
    move-result v0

    .line 256
    if-eqz v0, :cond_e

    .line 257
    .line 258
    const v0, 0x4f3d1c5e

    .line 259
    .line 260
    .line 261
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 262
    .line 263
    .line 264
    sget-object v0, Lzb/x;->b:Ll2/u2;

    .line 265
    .line 266
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    check-cast v0, Lzb/j;

    .line 271
    .line 272
    new-instance v1, Lmc/f;

    .line 273
    .line 274
    const/4 v2, 0x0

    .line 275
    invoke-direct {v1, p0, p4, v2}, Lmc/f;-><init>(Lmc/r;Lmc/p;I)V

    .line 276
    .line 277
    .line 278
    const p4, 0x54fe2cb1

    .line 279
    .line 280
    .line 281
    invoke-static {p4, v6, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 282
    .line 283
    .line 284
    move-result-object p4

    .line 285
    const/16 v1, 0x36

    .line 286
    .line 287
    invoke-interface {v0, v8, p4, v6, v1}, Lzb/j;->l(ZLt2/b;Ll2/o;I)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    .line 291
    .line 292
    .line 293
    goto :goto_b

    .line 294
    :cond_e
    const v0, 0x4f468f56

    .line 295
    .line 296
    .line 297
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 298
    .line 299
    .line 300
    sget-object v0, Lzb/x;->b:Ll2/u2;

    .line 301
    .line 302
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    check-cast v0, Lzb/j;

    .line 307
    .line 308
    sget-object v1, Lzb/x;->d:Ll2/u2;

    .line 309
    .line 310
    invoke-virtual {v6, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v1

    .line 314
    check-cast v1, Ljava/lang/Boolean;

    .line 315
    .line 316
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 317
    .line 318
    .line 319
    move-result v1

    .line 320
    new-instance v2, Lmc/f;

    .line 321
    .line 322
    const/4 v3, 0x1

    .line 323
    invoke-direct {v2, p0, p4, v3}, Lmc/f;-><init>(Lmc/r;Lmc/p;I)V

    .line 324
    .line 325
    .line 326
    const p4, 0x383c2348

    .line 327
    .line 328
    .line 329
    invoke-static {p4, v6, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 330
    .line 331
    .line 332
    move-result-object p4

    .line 333
    const/16 v2, 0x30

    .line 334
    .line 335
    invoke-interface {v0, v1, p4, v6, v2}, Lzb/j;->l(ZLt2/b;Ll2/o;I)V

    .line 336
    .line 337
    .line 338
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    .line 339
    .line 340
    .line 341
    goto :goto_b

    .line 342
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 343
    .line 344
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 345
    .line 346
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    throw p0

    .line 350
    :cond_10
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 351
    .line 352
    .line 353
    :goto_b
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 354
    .line 355
    .line 356
    move-result-object p4

    .line 357
    if-eqz p4, :cond_11

    .line 358
    .line 359
    new-instance v0, La71/e;

    .line 360
    .line 361
    const/16 v6, 0x17

    .line 362
    .line 363
    move-object v1, p0

    .line 364
    move-object v2, p1

    .line 365
    move-object v3, p2

    .line 366
    move-object v4, p3

    .line 367
    move v5, p5

    .line 368
    invoke-direct/range {v0 .. v6}, La71/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 369
    .line 370
    .line 371
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 372
    .line 373
    :cond_11
    return-void
.end method

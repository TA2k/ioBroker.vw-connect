.class public final Lkn/p;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lx2/s;

.field public final synthetic g:J

.field public final synthetic h:Le3/n0;

.field public final synthetic i:Lkn/c0;

.field public final synthetic j:Ll2/b1;

.field public final synthetic k:Lvy0/b0;

.field public final synthetic l:Lay0/n;

.field public final synthetic m:Lay0/n;


# direct methods
.method public constructor <init>(Lx2/s;JLe3/n0;Lkn/j0;Lkn/c0;Ll2/b1;Lvy0/b0;Lay0/n;Lay0/n;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkn/p;->f:Lx2/s;

    .line 2
    .line 3
    iput-wide p2, p0, Lkn/p;->g:J

    .line 4
    .line 5
    iput-object p4, p0, Lkn/p;->h:Le3/n0;

    .line 6
    .line 7
    iput-object p6, p0, Lkn/p;->i:Lkn/c0;

    .line 8
    .line 9
    iput-object p7, p0, Lkn/p;->j:Ll2/b1;

    .line 10
    .line 11
    iput-object p8, p0, Lkn/p;->k:Lvy0/b0;

    .line 12
    .line 13
    iput-object p9, p0, Lkn/p;->l:Lay0/n;

    .line 14
    .line 15
    iput-object p10, p0, Lkn/p;->m:Lay0/n;

    .line 16
    .line 17
    const/4 p1, 0x2

    .line 18
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    and-int/lit8 v2, v2, 0xb

    .line 21
    .line 22
    const/4 v5, 0x2

    .line 23
    if-ne v2, v5, :cond_1

    .line 24
    .line 25
    move-object v2, v1

    .line 26
    check-cast v2, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-nez v5, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 36
    .line 37
    .line 38
    goto/16 :goto_2

    .line 39
    .line 40
    :cond_1
    :goto_0
    iget-object v2, v0, Lkn/p;->f:Lx2/s;

    .line 41
    .line 42
    const/high16 v5, 0x3f800000    # 1.0f

    .line 43
    .line 44
    invoke-static {v2, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    sget-object v5, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 49
    .line 50
    invoke-static {v1}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    iget-object v5, v5, Lk1/r1;->e:Lk1/b;

    .line 55
    .line 56
    const-string v6, "$this$sheetBackgroundWithInsets"

    .line 57
    .line 58
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string v6, "navigationBarInsets"

    .line 62
    .line 63
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    const-string v6, "backgroundShape"

    .line 67
    .line 68
    iget-object v7, v0, Lkn/p;->h:Le3/n0;

    .line 69
    .line 70
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    sget v6, Lk1/d;->h:I

    .line 74
    .line 75
    new-instance v8, Lk1/v0;

    .line 76
    .line 77
    invoke-direct {v8, v5, v6}, Lk1/v0;-><init>(Lk1/q1;I)V

    .line 78
    .line 79
    .line 80
    invoke-static {v2, v8}, Lk1/d;->r(Lx2/s;Lk1/q1;)Lx2/s;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    iget-wide v8, v0, Lkn/p;->g:J

    .line 85
    .line 86
    invoke-static {v2, v8, v9, v7}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    invoke-static {v2, v5}, Lk1/d;->r(Lx2/s;Lk1/q1;)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    check-cast v1, Ll2/t;

    .line 95
    .line 96
    const v5, 0x91c5890

    .line 97
    .line 98
    .line 99
    invoke-virtual {v1, v5}, Ll2/t;->Z(I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v5

    .line 106
    const/4 v6, 0x1

    .line 107
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 108
    .line 109
    if-ne v5, v7, :cond_2

    .line 110
    .line 111
    new-instance v5, Lkn/m;

    .line 112
    .line 113
    iget-object v8, v0, Lkn/p;->j:Ll2/b1;

    .line 114
    .line 115
    invoke-direct {v5, v8, v6}, Lkn/m;-><init>(Ll2/b1;I)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v1, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_2
    check-cast v5, Lay0/k;

    .line 122
    .line 123
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 124
    .line 125
    .line 126
    invoke-static {v2, v5}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 127
    .line 128
    .line 129
    move-result-object v8

    .line 130
    const v2, 0x91c5986

    .line 131
    .line 132
    .line 133
    invoke-virtual {v1, v2}, Ll2/t;->Z(I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    if-ne v2, v7, :cond_3

    .line 141
    .line 142
    invoke-static {v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    :cond_3
    move-object v9, v2

    .line 147
    check-cast v9, Li1/l;

    .line 148
    .line 149
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 150
    .line 151
    .line 152
    sget-object v13, Lkn/c;->h:Lkn/c;

    .line 153
    .line 154
    const/16 v14, 0x1c

    .line 155
    .line 156
    const/4 v10, 0x0

    .line 157
    const/4 v11, 0x0

    .line 158
    const/4 v12, 0x0

    .line 159
    invoke-static/range {v8 .. v14}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 160
    .line 161
    .line 162
    move-result-object v15

    .line 163
    new-instance v2, Lkn/h;

    .line 164
    .line 165
    iget-object v5, v0, Lkn/p;->k:Lvy0/b0;

    .line 166
    .line 167
    iget-object v8, v0, Lkn/p;->i:Lkn/c0;

    .line 168
    .line 169
    invoke-direct {v2, v5, v8}, Lkn/h;-><init>(Lvy0/b0;Lkn/c0;)V

    .line 170
    .line 171
    .line 172
    invoke-static {v2, v1}, Lg1/f1;->b(Lay0/k;Ll2/o;)Lg1/i1;

    .line 173
    .line 174
    .line 175
    move-result-object v16

    .line 176
    sget-object v17, Lg1/w1;->d:Lg1/w1;

    .line 177
    .line 178
    new-instance v2, Lg1/e1;

    .line 179
    .line 180
    const/4 v5, 0x3

    .line 181
    const/4 v9, 0x4

    .line 182
    invoke-direct {v2, v5, v10, v9}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 183
    .line 184
    .line 185
    const v5, 0x91c5bd7    # 1.8821E-33f

    .line 186
    .line 187
    .line 188
    invoke-virtual {v1, v5}, Ll2/t;->Z(I)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v1, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result v5

    .line 195
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v9

    .line 199
    if-nez v5, :cond_4

    .line 200
    .line 201
    if-ne v9, v7, :cond_5

    .line 202
    .line 203
    :cond_4
    new-instance v9, Lkn/o;

    .line 204
    .line 205
    invoke-direct {v9, v8, v10, v3}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v1, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    :cond_5
    move-object/from16 v22, v9

    .line 212
    .line 213
    check-cast v22, Lay0/o;

    .line 214
    .line 215
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 216
    .line 217
    .line 218
    const/16 v23, 0x0

    .line 219
    .line 220
    const/16 v24, 0x9c

    .line 221
    .line 222
    const/16 v18, 0x0

    .line 223
    .line 224
    const/16 v19, 0x0

    .line 225
    .line 226
    const/16 v20, 0x0

    .line 227
    .line 228
    move-object/from16 v21, v2

    .line 229
    .line 230
    invoke-static/range {v15 .. v24}, Lg1/f1;->a(Lx2/s;Lg1/i1;Lg1/w1;ZLi1/l;ZLg1/e1;Lay0/o;ZI)Lx2/s;

    .line 231
    .line 232
    .line 233
    move-result-object v2

    .line 234
    const v5, -0x1cd0f17e

    .line 235
    .line 236
    .line 237
    invoke-virtual {v1, v5}, Ll2/t;->Z(I)V

    .line 238
    .line 239
    .line 240
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 241
    .line 242
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 243
    .line 244
    invoke-static {v5, v7, v1, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 245
    .line 246
    .line 247
    move-result-object v5

    .line 248
    const v7, -0x4ee9b9da

    .line 249
    .line 250
    .line 251
    invoke-virtual {v1, v7}, Ll2/t;->Z(I)V

    .line 252
    .line 253
    .line 254
    iget-wide v7, v1, Ll2/t;->T:J

    .line 255
    .line 256
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 257
    .line 258
    .line 259
    move-result v7

    .line 260
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 261
    .line 262
    .line 263
    move-result-object v8

    .line 264
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 265
    .line 266
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 267
    .line 268
    .line 269
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 270
    .line 271
    invoke-static {v2}, Lt3/k1;->k(Lx2/s;)Lt2/b;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 276
    .line 277
    .line 278
    iget-boolean v10, v1, Ll2/t;->S:Z

    .line 279
    .line 280
    if-eqz v10, :cond_6

    .line 281
    .line 282
    invoke-virtual {v1, v9}, Ll2/t;->l(Lay0/a;)V

    .line 283
    .line 284
    .line 285
    goto :goto_1

    .line 286
    :cond_6
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 287
    .line 288
    .line 289
    :goto_1
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 290
    .line 291
    invoke-static {v9, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 292
    .line 293
    .line 294
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 295
    .line 296
    invoke-static {v5, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 297
    .line 298
    .line 299
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 300
    .line 301
    iget-boolean v8, v1, Ll2/t;->S:Z

    .line 302
    .line 303
    if-nez v8, :cond_7

    .line 304
    .line 305
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v8

    .line 309
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 310
    .line 311
    .line 312
    move-result-object v9

    .line 313
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    move-result v8

    .line 317
    if-nez v8, :cond_8

    .line 318
    .line 319
    :cond_7
    invoke-static {v7, v1, v7, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 320
    .line 321
    .line 322
    :cond_8
    new-instance v5, Ll2/d2;

    .line 323
    .line 324
    invoke-direct {v5, v1}, Ll2/d2;-><init>(Ll2/o;)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {v2, v5, v1, v4}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    const v2, 0x7ab4aae9

    .line 331
    .line 332
    .line 333
    invoke-virtual {v1, v2}, Ll2/t;->Z(I)V

    .line 334
    .line 335
    .line 336
    iget-object v2, v0, Lkn/p;->l:Lay0/n;

    .line 337
    .line 338
    invoke-interface {v2, v1, v4}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    iget-object v0, v0, Lkn/p;->m:Lay0/n;

    .line 342
    .line 343
    invoke-interface {v0, v1, v4}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 347
    .line 348
    .line 349
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 350
    .line 351
    .line 352
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 353
    .line 354
    .line 355
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 356
    .line 357
    .line 358
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 359
    .line 360
    return-object v0
.end method

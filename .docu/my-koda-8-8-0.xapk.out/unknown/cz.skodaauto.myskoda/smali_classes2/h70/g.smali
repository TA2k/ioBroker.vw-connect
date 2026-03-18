.class public final synthetic Lh70/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/k;

.field public final synthetic m:Lg61/p;

.field public final synthetic n:Lg61/q;

.field public final synthetic o:Lay0/k;

.field public final synthetic p:Lay0/a;

.field public final synthetic q:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lg61/p;Lg61/q;Lvy0/b0;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p14, p0, Lh70/g;->d:Z

    .line 5
    .line 6
    iput-object p13, p0, Lh70/g;->e:Lvy0/b0;

    .line 7
    .line 8
    iput-object p1, p0, Lh70/g;->f:Lay0/a;

    .line 9
    .line 10
    iput-object p2, p0, Lh70/g;->g:Lay0/a;

    .line 11
    .line 12
    iput-object p3, p0, Lh70/g;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p4, p0, Lh70/g;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p8, p0, Lh70/g;->j:Lay0/k;

    .line 17
    .line 18
    iput-object p5, p0, Lh70/g;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, Lh70/g;->l:Lay0/k;

    .line 21
    .line 22
    iput-object p11, p0, Lh70/g;->m:Lg61/p;

    .line 23
    .line 24
    iput-object p12, p0, Lh70/g;->n:Lg61/q;

    .line 25
    .line 26
    iput-object p10, p0, Lh70/g;->o:Lay0/k;

    .line 27
    .line 28
    iput-object p6, p0, Lh70/g;->p:Lay0/a;

    .line 29
    .line 30
    iput-object p7, p0, Lh70/g;->q:Lay0/a;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/q;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const-string v4, "$this$GradientBox"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v1, v3, 0x11

    .line 25
    .line 26
    const/16 v4, 0x10

    .line 27
    .line 28
    const/4 v5, 0x1

    .line 29
    const/4 v6, 0x0

    .line 30
    if-eq v1, v4, :cond_0

    .line 31
    .line 32
    move v1, v5

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v1, v6

    .line 35
    :goto_0
    and-int/2addr v3, v5

    .line 36
    move-object v12, v2

    .line 37
    check-cast v12, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {v12, v3, v1}, Ll2/t;->O(IZ)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_9

    .line 44
    .line 45
    sget-object v1, Lx2/c;->q:Lx2/h;

    .line 46
    .line 47
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 48
    .line 49
    const/16 v3, 0x30

    .line 50
    .line 51
    invoke-static {v2, v1, v12, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    iget-wide v2, v12, Ll2/t;->T:J

    .line 56
    .line 57
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 66
    .line 67
    invoke-static {v12, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 68
    .line 69
    .line 70
    move-result-object v7

    .line 71
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 72
    .line 73
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 77
    .line 78
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 79
    .line 80
    .line 81
    iget-boolean v9, v12, Ll2/t;->S:Z

    .line 82
    .line 83
    if-eqz v9, :cond_1

    .line 84
    .line 85
    invoke-virtual {v12, v8}, Ll2/t;->l(Lay0/a;)V

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 90
    .line 91
    .line 92
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 93
    .line 94
    invoke-static {v8, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 95
    .line 96
    .line 97
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 98
    .line 99
    invoke-static {v1, v3, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 100
    .line 101
    .line 102
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 103
    .line 104
    iget-boolean v3, v12, Ll2/t;->S:Z

    .line 105
    .line 106
    if-nez v3, :cond_2

    .line 107
    .line 108
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 113
    .line 114
    .line 115
    move-result-object v8

    .line 116
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v3

    .line 120
    if-nez v3, :cond_3

    .line 121
    .line 122
    :cond_2
    invoke-static {v2, v12, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 123
    .line 124
    .line 125
    :cond_3
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 126
    .line 127
    invoke-static {v1, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 128
    .line 129
    .line 130
    sget-object v1, Lh70/m;->a:Ll2/j1;

    .line 131
    .line 132
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    check-cast v1, Lg61/e;

    .line 137
    .line 138
    const/4 v2, 0x0

    .line 139
    if-eqz v1, :cond_4

    .line 140
    .line 141
    invoke-interface {v1}, Lg61/e;->isBluetoothEnabled()Lyy0/a2;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    goto :goto_2

    .line 146
    :cond_4
    move-object v1, v2

    .line 147
    :goto_2
    if-nez v1, :cond_5

    .line 148
    .line 149
    const v1, 0x42b6fa3f

    .line 150
    .line 151
    .line 152
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 153
    .line 154
    .line 155
    :goto_3
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 156
    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_5
    const v3, 0x6d81c602

    .line 160
    .line 161
    .line 162
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 163
    .line 164
    .line 165
    invoke-static {v1, v2, v12, v5}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 166
    .line 167
    .line 168
    move-result-object v2

    .line 169
    goto :goto_3

    .line 170
    :goto_4
    if-eqz v2, :cond_6

    .line 171
    .line 172
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    check-cast v1, Ljava/lang/Boolean;

    .line 177
    .line 178
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    if-ne v1, v5, :cond_6

    .line 183
    .line 184
    move v1, v5

    .line 185
    goto :goto_5

    .line 186
    :cond_6
    move v1, v6

    .line 187
    :goto_5
    if-nez v1, :cond_7

    .line 188
    .line 189
    const v2, 0x42b8178c    # 92.04599f

    .line 190
    .line 191
    .line 192
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 193
    .line 194
    .line 195
    const v2, 0x7f120f64

    .line 196
    .line 197
    .line 198
    invoke-static {v12, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v7

    .line 202
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 203
    .line 204
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v2

    .line 208
    check-cast v2, Lj91/f;

    .line 209
    .line 210
    invoke-virtual {v2}, Lj91/f;->e()Lg4/p0;

    .line 211
    .line 212
    .line 213
    move-result-object v8

    .line 214
    const/16 v27, 0x0

    .line 215
    .line 216
    const v28, 0xfffc

    .line 217
    .line 218
    .line 219
    const/4 v9, 0x0

    .line 220
    const-wide/16 v10, 0x0

    .line 221
    .line 222
    move-object/from16 v16, v12

    .line 223
    .line 224
    const-wide/16 v12, 0x0

    .line 225
    .line 226
    const/4 v14, 0x0

    .line 227
    move-object/from16 v25, v16

    .line 228
    .line 229
    const-wide/16 v15, 0x0

    .line 230
    .line 231
    const/16 v17, 0x0

    .line 232
    .line 233
    const/16 v18, 0x0

    .line 234
    .line 235
    const-wide/16 v19, 0x0

    .line 236
    .line 237
    const/16 v21, 0x0

    .line 238
    .line 239
    const/16 v22, 0x0

    .line 240
    .line 241
    const/16 v23, 0x0

    .line 242
    .line 243
    const/16 v24, 0x0

    .line 244
    .line 245
    const/16 v26, 0x0

    .line 246
    .line 247
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 248
    .line 249
    .line 250
    move-object/from16 v12, v25

    .line 251
    .line 252
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 253
    .line 254
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v2

    .line 258
    check-cast v2, Lj91/c;

    .line 259
    .line 260
    iget v2, v2, Lj91/c;->d:F

    .line 261
    .line 262
    invoke-static {v4, v2, v12, v6}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 263
    .line 264
    .line 265
    goto :goto_6

    .line 266
    :cond_7
    const v2, 0x41dc4270

    .line 267
    .line 268
    .line 269
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 273
    .line 274
    .line 275
    :goto_6
    iget-boolean v2, v0, Lh70/g;->d:Z

    .line 276
    .line 277
    if-nez v2, :cond_8

    .line 278
    .line 279
    const v2, 0x42bd124d

    .line 280
    .line 281
    .line 282
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 283
    .line 284
    .line 285
    const/16 v17, 0x0

    .line 286
    .line 287
    iget-object v7, v0, Lh70/g;->e:Lvy0/b0;

    .line 288
    .line 289
    iget-object v9, v0, Lh70/g;->f:Lay0/a;

    .line 290
    .line 291
    iget-object v10, v0, Lh70/g;->g:Lay0/a;

    .line 292
    .line 293
    iget-object v11, v0, Lh70/g;->h:Lay0/a;

    .line 294
    .line 295
    move-object/from16 v16, v12

    .line 296
    .line 297
    iget-object v12, v0, Lh70/g;->i:Lay0/a;

    .line 298
    .line 299
    iget-object v13, v0, Lh70/g;->j:Lay0/k;

    .line 300
    .line 301
    iget-object v14, v0, Lh70/g;->k:Lay0/a;

    .line 302
    .line 303
    iget-object v15, v0, Lh70/g;->l:Lay0/k;

    .line 304
    .line 305
    move v8, v1

    .line 306
    invoke-static/range {v7 .. v17}, Lh70/m;->h(Lvy0/b0;ZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/k;Ll2/o;I)V

    .line 307
    .line 308
    .line 309
    move-object/from16 v12, v16

    .line 310
    .line 311
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 312
    .line 313
    .line 314
    goto :goto_7

    .line 315
    :cond_8
    const v1, 0x42c5cc7b

    .line 316
    .line 317
    .line 318
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 319
    .line 320
    .line 321
    const/4 v13, 0x6

    .line 322
    iget-object v7, v0, Lh70/g;->m:Lg61/p;

    .line 323
    .line 324
    iget-object v8, v0, Lh70/g;->n:Lg61/q;

    .line 325
    .line 326
    iget-object v9, v0, Lh70/g;->o:Lay0/k;

    .line 327
    .line 328
    iget-object v10, v0, Lh70/g;->p:Lay0/a;

    .line 329
    .line 330
    iget-object v11, v0, Lh70/g;->q:Lay0/a;

    .line 331
    .line 332
    invoke-static/range {v7 .. v13}, Lh70/m;->b(Lg61/p;Lg61/q;Lay0/k;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 336
    .line 337
    .line 338
    :goto_7
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 339
    .line 340
    .line 341
    goto :goto_8

    .line 342
    :cond_9
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 343
    .line 344
    .line 345
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 346
    .line 347
    return-object v0
.end method

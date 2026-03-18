.class public final synthetic Lz20/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly20/h;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lh2/r8;

.field public final synthetic m:Lvy0/b0;


# direct methods
.method public synthetic constructor <init>(Ly20/h;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lh2/r8;Lvy0/b0;I)V
    .locals 0

    .line 1
    iput p10, p0, Lz20/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz20/i;->e:Ly20/h;

    .line 4
    .line 5
    iput-object p2, p0, Lz20/i;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Lz20/i;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Lz20/i;->h:Lay0/k;

    .line 10
    .line 11
    iput-object p5, p0, Lz20/i;->i:Lay0/k;

    .line 12
    .line 13
    iput-object p6, p0, Lz20/i;->j:Lay0/k;

    .line 14
    .line 15
    iput-object p7, p0, Lz20/i;->k:Lay0/a;

    .line 16
    .line 17
    iput-object p8, p0, Lz20/i;->l:Lh2/r8;

    .line 18
    .line 19
    iput-object p9, p0, Lz20/i;->m:Lvy0/b0;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lz20/i;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk1/q;

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
    const-string v4, "$this$PullToRefreshBox"

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
    const/4 v5, 0x0

    .line 34
    const/4 v6, 0x1

    .line 35
    if-eq v1, v4, :cond_0

    .line 36
    .line 37
    move v1, v6

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v1, v5

    .line 40
    :goto_0
    and-int/2addr v3, v6

    .line 41
    check-cast v2, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_4

    .line 48
    .line 49
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 50
    .line 51
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 52
    .line 53
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 54
    .line 55
    invoke-static {v3, v4, v2, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    iget-wide v7, v2, Ll2/t;->T:J

    .line 60
    .line 61
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 66
    .line 67
    .line 68
    move-result-object v7

    .line 69
    invoke-static {v2, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 74
    .line 75
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 79
    .line 80
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 81
    .line 82
    .line 83
    iget-boolean v9, v2, Ll2/t;->S:Z

    .line 84
    .line 85
    if-eqz v9, :cond_1

    .line 86
    .line 87
    invoke-virtual {v2, v8}, Ll2/t;->l(Lay0/a;)V

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_1
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 92
    .line 93
    .line 94
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 95
    .line 96
    invoke-static {v8, v3, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 97
    .line 98
    .line 99
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 100
    .line 101
    invoke-static {v3, v7, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 102
    .line 103
    .line 104
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 105
    .line 106
    iget-boolean v7, v2, Ll2/t;->S:Z

    .line 107
    .line 108
    if-nez v7, :cond_2

    .line 109
    .line 110
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v7

    .line 114
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v8

    .line 118
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v7

    .line 122
    if-nez v7, :cond_3

    .line 123
    .line 124
    :cond_2
    invoke-static {v4, v2, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 125
    .line 126
    .line 127
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 128
    .line 129
    invoke-static {v3, v1, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    const/16 v1, 0x30

    .line 133
    .line 134
    const/4 v3, 0x0

    .line 135
    invoke-static {v1, v2, v3, v5}, Ldt0/a;->c(ILl2/o;Lx2/s;Z)V

    .line 136
    .line 137
    .line 138
    const/16 v17, 0x0

    .line 139
    .line 140
    iget-object v7, v0, Lz20/i;->e:Ly20/h;

    .line 141
    .line 142
    iget-object v8, v0, Lz20/i;->f:Lay0/a;

    .line 143
    .line 144
    iget-object v9, v0, Lz20/i;->g:Lay0/a;

    .line 145
    .line 146
    iget-object v10, v0, Lz20/i;->h:Lay0/k;

    .line 147
    .line 148
    iget-object v11, v0, Lz20/i;->i:Lay0/k;

    .line 149
    .line 150
    iget-object v12, v0, Lz20/i;->j:Lay0/k;

    .line 151
    .line 152
    iget-object v13, v0, Lz20/i;->k:Lay0/a;

    .line 153
    .line 154
    iget-object v14, v0, Lz20/i;->l:Lh2/r8;

    .line 155
    .line 156
    iget-object v15, v0, Lz20/i;->m:Lvy0/b0;

    .line 157
    .line 158
    move-object/from16 v16, v2

    .line 159
    .line 160
    invoke-static/range {v7 .. v17}, Lz20/a;->k(Ly20/h;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lh2/r8;Lvy0/b0;Ll2/o;I)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v2, v6}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    goto :goto_2

    .line 167
    :cond_4
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 168
    .line 169
    .line 170
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    return-object v0

    .line 173
    :pswitch_0
    move-object/from16 v1, p1

    .line 174
    .line 175
    check-cast v1, Lk1/z0;

    .line 176
    .line 177
    move-object/from16 v2, p2

    .line 178
    .line 179
    check-cast v2, Ll2/o;

    .line 180
    .line 181
    move-object/from16 v3, p3

    .line 182
    .line 183
    check-cast v3, Ljava/lang/Integer;

    .line 184
    .line 185
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 186
    .line 187
    .line 188
    move-result v3

    .line 189
    const-string v4, "padding"

    .line 190
    .line 191
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    and-int/lit8 v4, v3, 0x6

    .line 195
    .line 196
    if-nez v4, :cond_6

    .line 197
    .line 198
    move-object v4, v2

    .line 199
    check-cast v4, Ll2/t;

    .line 200
    .line 201
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    if-eqz v4, :cond_5

    .line 206
    .line 207
    const/4 v4, 0x4

    .line 208
    goto :goto_3

    .line 209
    :cond_5
    const/4 v4, 0x2

    .line 210
    :goto_3
    or-int/2addr v3, v4

    .line 211
    :cond_6
    and-int/lit8 v4, v3, 0x13

    .line 212
    .line 213
    const/16 v5, 0x12

    .line 214
    .line 215
    const/4 v6, 0x1

    .line 216
    if-eq v4, v5, :cond_7

    .line 217
    .line 218
    move v4, v6

    .line 219
    goto :goto_4

    .line 220
    :cond_7
    const/4 v4, 0x0

    .line 221
    :goto_4
    and-int/2addr v3, v6

    .line 222
    move-object v12, v2

    .line 223
    check-cast v12, Ll2/t;

    .line 224
    .line 225
    invoke-virtual {v12, v3, v4}, Ll2/t;->O(IZ)Z

    .line 226
    .line 227
    .line 228
    move-result v2

    .line 229
    if-eqz v2, :cond_8

    .line 230
    .line 231
    invoke-static {v12}, Lj2/i;->d(Ll2/o;)Lj2/p;

    .line 232
    .line 233
    .line 234
    move-result-object v8

    .line 235
    iget-object v14, v0, Lz20/i;->e:Ly20/h;

    .line 236
    .line 237
    iget-boolean v5, v14, Ly20/h;->e:Z

    .line 238
    .line 239
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 240
    .line 241
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 246
    .line 247
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v2

    .line 251
    check-cast v2, Lj91/e;

    .line 252
    .line 253
    invoke-virtual {v2}, Lj91/e;->b()J

    .line 254
    .line 255
    .line 256
    move-result-wide v2

    .line 257
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 258
    .line 259
    invoke-static {v1, v2, v3, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 260
    .line 261
    .line 262
    move-result-object v7

    .line 263
    new-instance v1, Lz20/b;

    .line 264
    .line 265
    const/4 v2, 0x1

    .line 266
    invoke-direct {v1, v8, v14, v2}, Lz20/b;-><init>(Lj2/p;Ly20/h;I)V

    .line 267
    .line 268
    .line 269
    const v2, 0xb499fdf

    .line 270
    .line 271
    .line 272
    invoke-static {v2, v12, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 273
    .line 274
    .line 275
    move-result-object v10

    .line 276
    new-instance v13, Lz20/i;

    .line 277
    .line 278
    const/16 v23, 0x1

    .line 279
    .line 280
    iget-object v15, v0, Lz20/i;->f:Lay0/a;

    .line 281
    .line 282
    iget-object v1, v0, Lz20/i;->g:Lay0/a;

    .line 283
    .line 284
    iget-object v2, v0, Lz20/i;->h:Lay0/k;

    .line 285
    .line 286
    iget-object v3, v0, Lz20/i;->i:Lay0/k;

    .line 287
    .line 288
    iget-object v4, v0, Lz20/i;->j:Lay0/k;

    .line 289
    .line 290
    iget-object v6, v0, Lz20/i;->k:Lay0/a;

    .line 291
    .line 292
    iget-object v9, v0, Lz20/i;->l:Lh2/r8;

    .line 293
    .line 294
    iget-object v0, v0, Lz20/i;->m:Lvy0/b0;

    .line 295
    .line 296
    move-object/from16 v22, v0

    .line 297
    .line 298
    move-object/from16 v16, v1

    .line 299
    .line 300
    move-object/from16 v17, v2

    .line 301
    .line 302
    move-object/from16 v18, v3

    .line 303
    .line 304
    move-object/from16 v19, v4

    .line 305
    .line 306
    move-object/from16 v20, v6

    .line 307
    .line 308
    move-object/from16 v21, v9

    .line 309
    .line 310
    invoke-direct/range {v13 .. v23}, Lz20/i;-><init>(Ly20/h;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lh2/r8;Lvy0/b0;I)V

    .line 311
    .line 312
    .line 313
    const v0, 0x648ad6be

    .line 314
    .line 315
    .line 316
    invoke-static {v0, v12, v13}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 317
    .line 318
    .line 319
    move-result-object v11

    .line 320
    const/high16 v13, 0x1b0000

    .line 321
    .line 322
    const/16 v14, 0x10

    .line 323
    .line 324
    const/4 v9, 0x0

    .line 325
    move-object v6, v15

    .line 326
    invoke-static/range {v5 .. v14}, Lj2/i;->b(ZLay0/a;Lx2/s;Lj2/p;Lx2/e;Lay0/o;Lt2/b;Ll2/o;II)V

    .line 327
    .line 328
    .line 329
    goto :goto_5

    .line 330
    :cond_8
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 331
    .line 332
    .line 333
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 334
    .line 335
    return-object v0

    .line 336
    nop

    .line 337
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

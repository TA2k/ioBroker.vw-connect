.class public final synthetic Lx30/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lw30/s;

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Lay0/a;

.field public final synthetic p:Lay0/a;

.field public final synthetic q:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lw30/s;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx30/g;->d:Lw30/s;

    .line 5
    .line 6
    iput-object p2, p0, Lx30/g;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lx30/g;->f:Lay0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lx30/g;->g:Lay0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lx30/g;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lx30/g;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Lx30/g;->j:Lay0/a;

    .line 17
    .line 18
    iput-object p8, p0, Lx30/g;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, Lx30/g;->l:Lay0/a;

    .line 21
    .line 22
    iput-object p10, p0, Lx30/g;->m:Lay0/a;

    .line 23
    .line 24
    iput-object p11, p0, Lx30/g;->n:Lay0/a;

    .line 25
    .line 26
    iput-object p12, p0, Lx30/g;->o:Lay0/a;

    .line 27
    .line 28
    iput-object p13, p0, Lx30/g;->p:Lay0/a;

    .line 29
    .line 30
    iput-object p14, p0, Lx30/g;->q:Lay0/a;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/z0;

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
    const-string v4, "paddingValues"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v4, v3, 0x6

    .line 25
    .line 26
    if-nez v4, :cond_1

    .line 27
    .line 28
    move-object v4, v2

    .line 29
    check-cast v4, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_0

    .line 36
    .line 37
    const/4 v4, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v4, 0x2

    .line 40
    :goto_0
    or-int/2addr v3, v4

    .line 41
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 42
    .line 43
    const/16 v5, 0x12

    .line 44
    .line 45
    const/4 v6, 0x1

    .line 46
    const/4 v7, 0x0

    .line 47
    if-eq v4, v5, :cond_2

    .line 48
    .line 49
    move v4, v6

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    move v4, v7

    .line 52
    :goto_1
    and-int/2addr v3, v6

    .line 53
    move-object v13, v2

    .line 54
    check-cast v13, Ll2/t;

    .line 55
    .line 56
    invoke-virtual {v13, v3, v4}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_9

    .line 61
    .line 62
    iget-object v2, v0, Lx30/g;->d:Lw30/s;

    .line 63
    .line 64
    iget-object v8, v2, Lw30/s;->a:Lql0/g;

    .line 65
    .line 66
    if-nez v8, :cond_3

    .line 67
    .line 68
    const v3, -0xbdcd8d6

    .line 69
    .line 70
    .line 71
    invoke-virtual {v13, v3}, Ll2/t;->Y(I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v13, v7}, Ll2/t;->q(Z)V

    .line 75
    .line 76
    .line 77
    move-object v14, v13

    .line 78
    goto :goto_2

    .line 79
    :cond_3
    const v3, -0xbdcd8d5

    .line 80
    .line 81
    .line 82
    invoke-virtual {v13, v3}, Ll2/t;->Y(I)V

    .line 83
    .line 84
    .line 85
    iget-object v3, v0, Lx30/g;->e:Lay0/a;

    .line 86
    .line 87
    invoke-virtual {v13, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    if-nez v4, :cond_4

    .line 96
    .line 97
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-ne v5, v4, :cond_5

    .line 100
    .line 101
    :cond_4
    new-instance v5, Lvo0/g;

    .line 102
    .line 103
    const/16 v4, 0x9

    .line 104
    .line 105
    invoke-direct {v5, v3, v4}, Lvo0/g;-><init>(Lay0/a;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v13, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_5
    move-object v9, v5

    .line 112
    check-cast v9, Lay0/k;

    .line 113
    .line 114
    const/4 v12, 0x0

    .line 115
    move-object v14, v13

    .line 116
    const/4 v13, 0x4

    .line 117
    const/4 v10, 0x0

    .line 118
    move-object v11, v14

    .line 119
    invoke-static/range {v8 .. v13}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v14, v7}, Ll2/t;->q(Z)V

    .line 123
    .line 124
    .line 125
    :goto_2
    sget-object v3, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 126
    .line 127
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 128
    .line 129
    invoke-virtual {v14, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v4

    .line 133
    check-cast v4, Lj91/e;

    .line 134
    .line 135
    invoke-virtual {v4}, Lj91/e;->b()J

    .line 136
    .line 137
    .line 138
    move-result-wide v4

    .line 139
    sget-object v8, Le3/j0;->a:Le3/i0;

    .line 140
    .line 141
    invoke-static {v3, v4, v5, v8}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 142
    .line 143
    .line 144
    move-result-object v15

    .line 145
    invoke-interface {v1}, Lk1/z0;->d()F

    .line 146
    .line 147
    .line 148
    move-result v17

    .line 149
    const/16 v19, 0x0

    .line 150
    .line 151
    const/16 v20, 0xd

    .line 152
    .line 153
    const/16 v16, 0x0

    .line 154
    .line 155
    const/16 v18, 0x0

    .line 156
    .line 157
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-static {v7, v6, v14}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    const/16 v4, 0xe

    .line 166
    .line 167
    invoke-static {v1, v3, v4}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    sget-object v3, Lk1/j;->a:Lk1/c;

    .line 172
    .line 173
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 174
    .line 175
    invoke-virtual {v14, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    check-cast v3, Lj91/c;

    .line 180
    .line 181
    iget v3, v3, Lj91/c;->g:F

    .line 182
    .line 183
    invoke-static {v3}, Lk1/j;->g(F)Lk1/h;

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 188
    .line 189
    invoke-static {v3, v4, v14, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 190
    .line 191
    .line 192
    move-result-object v3

    .line 193
    iget-wide v4, v14, Ll2/t;->T:J

    .line 194
    .line 195
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 196
    .line 197
    .line 198
    move-result v4

    .line 199
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 200
    .line 201
    .line 202
    move-result-object v5

    .line 203
    invoke-static {v14, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 204
    .line 205
    .line 206
    move-result-object v1

    .line 207
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 208
    .line 209
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 210
    .line 211
    .line 212
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 213
    .line 214
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 215
    .line 216
    .line 217
    iget-boolean v9, v14, Ll2/t;->S:Z

    .line 218
    .line 219
    if-eqz v9, :cond_6

    .line 220
    .line 221
    invoke-virtual {v14, v8}, Ll2/t;->l(Lay0/a;)V

    .line 222
    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_6
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 226
    .line 227
    .line 228
    :goto_3
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 229
    .line 230
    invoke-static {v8, v3, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 231
    .line 232
    .line 233
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 234
    .line 235
    invoke-static {v3, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 236
    .line 237
    .line 238
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 239
    .line 240
    iget-boolean v5, v14, Ll2/t;->S:Z

    .line 241
    .line 242
    if-nez v5, :cond_7

    .line 243
    .line 244
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v5

    .line 248
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 249
    .line 250
    .line 251
    move-result-object v8

    .line 252
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    move-result v5

    .line 256
    if-nez v5, :cond_8

    .line 257
    .line 258
    :cond_7
    invoke-static {v4, v14, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 259
    .line 260
    .line 261
    :cond_8
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 262
    .line 263
    invoke-static {v3, v1, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 264
    .line 265
    .line 266
    iget-boolean v12, v2, Lw30/s;->b:Z

    .line 267
    .line 268
    move-object v13, v14

    .line 269
    const/4 v14, 0x0

    .line 270
    iget-object v8, v0, Lx30/g;->f:Lay0/a;

    .line 271
    .line 272
    iget-object v9, v0, Lx30/g;->g:Lay0/a;

    .line 273
    .line 274
    iget-object v10, v0, Lx30/g;->h:Lay0/a;

    .line 275
    .line 276
    iget-object v11, v0, Lx30/g;->i:Lay0/a;

    .line 277
    .line 278
    invoke-static/range {v8 .. v14}, Lx30/b;->m(Lay0/a;Lay0/a;Lay0/a;Lay0/a;ZLl2/o;I)V

    .line 279
    .line 280
    .line 281
    move-object v14, v13

    .line 282
    const/4 v15, 0x0

    .line 283
    iget-object v9, v0, Lx30/g;->j:Lay0/a;

    .line 284
    .line 285
    iget-object v10, v0, Lx30/g;->k:Lay0/a;

    .line 286
    .line 287
    iget-object v11, v0, Lx30/g;->l:Lay0/a;

    .line 288
    .line 289
    iget-object v12, v0, Lx30/g;->m:Lay0/a;

    .line 290
    .line 291
    iget-object v13, v0, Lx30/g;->n:Lay0/a;

    .line 292
    .line 293
    move-object v8, v2

    .line 294
    invoke-static/range {v8 .. v15}, Lx30/b;->w(Lw30/s;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 295
    .line 296
    .line 297
    iget-object v1, v0, Lx30/g;->o:Lay0/a;

    .line 298
    .line 299
    iget-object v2, v0, Lx30/g;->p:Lay0/a;

    .line 300
    .line 301
    invoke-static {v8, v1, v2, v14, v7}, Lx30/b;->N(Lw30/s;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 302
    .line 303
    .line 304
    iget-object v0, v0, Lx30/g;->q:Lay0/a;

    .line 305
    .line 306
    invoke-static {v0, v14, v7}, Lx30/b;->C(Lay0/a;Ll2/o;I)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v14, v6}, Ll2/t;->q(Z)V

    .line 310
    .line 311
    .line 312
    goto :goto_4

    .line 313
    :cond_9
    move-object v14, v13

    .line 314
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 315
    .line 316
    .line 317
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 318
    .line 319
    return-object v0
.end method

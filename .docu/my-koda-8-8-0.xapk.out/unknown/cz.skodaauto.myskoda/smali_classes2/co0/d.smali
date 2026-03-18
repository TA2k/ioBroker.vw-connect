.class public final synthetic Lco0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:J

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:J

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Z

.field public final synthetic k:Ljava/lang/Integer;

.field public final synthetic l:Ljava/lang/Boolean;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/o;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;JLjava/lang/String;ZLjava/lang/Integer;Ljava/lang/Boolean;Lay0/k;Lay0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lco0/d;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lco0/d;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-wide p3, p0, Lco0/d;->f:J

    .line 9
    .line 10
    iput-object p5, p0, Lco0/d;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-wide p6, p0, Lco0/d;->h:J

    .line 13
    .line 14
    iput-object p8, p0, Lco0/d;->i:Ljava/lang/String;

    .line 15
    .line 16
    iput-boolean p9, p0, Lco0/d;->j:Z

    .line 17
    .line 18
    iput-object p10, p0, Lco0/d;->k:Ljava/lang/Integer;

    .line 19
    .line 20
    iput-object p11, p0, Lco0/d;->l:Ljava/lang/Boolean;

    .line 21
    .line 22
    iput-object p12, p0, Lco0/d;->m:Lay0/k;

    .line 23
    .line 24
    iput-object p13, p0, Lco0/d;->n:Lay0/o;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 28

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
    check-cast v2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x1

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v6

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v5

    .line 25
    :goto_0
    and-int/2addr v2, v6

    .line 26
    check-cast v1, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    if-eqz v2, :cond_b

    .line 35
    .line 36
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 37
    .line 38
    const/high16 v4, 0x3f800000    # 1.0f

    .line 39
    .line 40
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 45
    .line 46
    invoke-virtual {v1, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    check-cast v4, Lj91/c;

    .line 51
    .line 52
    iget v4, v4, Lj91/c;->d:F

    .line 53
    .line 54
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    const v4, -0x3bced2e6

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, v4}, Ll2/t;->Y(I)V

    .line 62
    .line 63
    .line 64
    const v4, 0xca3d8b5

    .line 65
    .line 66
    .line 67
    invoke-virtual {v1, v4}, Ll2/t;->Y(I)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 71
    .line 72
    .line 73
    sget-object v4, Lw3/h1;->h:Ll2/u2;

    .line 74
    .line 75
    invoke-virtual {v1, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    check-cast v4, Lt4/c;

    .line 80
    .line 81
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 86
    .line 87
    if-ne v6, v7, :cond_1

    .line 88
    .line 89
    invoke-static {v4, v1}, Lvj/b;->t(Lt4/c;Ll2/t;)Lz4/p;

    .line 90
    .line 91
    .line 92
    move-result-object v6

    .line 93
    :cond_1
    move-object v10, v6

    .line 94
    check-cast v10, Lz4/p;

    .line 95
    .line 96
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    if-ne v4, v7, :cond_2

    .line 101
    .line 102
    invoke-static {v1}, Lvj/b;->r(Ll2/t;)Lz4/k;

    .line 103
    .line 104
    .line 105
    move-result-object v4

    .line 106
    :cond_2
    check-cast v4, Lz4/k;

    .line 107
    .line 108
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v6

    .line 112
    if-ne v6, v7, :cond_3

    .line 113
    .line 114
    sget-object v6, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 115
    .line 116
    invoke-static {v6}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    invoke-virtual {v1, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    :cond_3
    move-object v12, v6

    .line 124
    check-cast v12, Ll2/b1;

    .line 125
    .line 126
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    if-ne v6, v7, :cond_4

    .line 131
    .line 132
    invoke-static {v4, v1}, Lvj/b;->s(Lz4/k;Ll2/t;)Lz4/m;

    .line 133
    .line 134
    .line 135
    move-result-object v6

    .line 136
    :cond_4
    move-object v11, v6

    .line 137
    check-cast v11, Lz4/m;

    .line 138
    .line 139
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v6

    .line 143
    if-ne v6, v7, :cond_5

    .line 144
    .line 145
    sget-object v6, Ll2/x0;->f:Ll2/x0;

    .line 146
    .line 147
    invoke-static {v3, v6, v1}, Lf2/m0;->r(Llx0/b0;Ll2/x0;Ll2/t;)Ll2/j1;

    .line 148
    .line 149
    .line 150
    move-result-object v6

    .line 151
    :cond_5
    move-object v9, v6

    .line 152
    check-cast v9, Ll2/b1;

    .line 153
    .line 154
    invoke-virtual {v1, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v6

    .line 158
    const/16 v8, 0x101

    .line 159
    .line 160
    invoke-virtual {v1, v8}, Ll2/t;->e(I)Z

    .line 161
    .line 162
    .line 163
    move-result v8

    .line 164
    or-int/2addr v6, v8

    .line 165
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v8

    .line 169
    if-nez v6, :cond_6

    .line 170
    .line 171
    if-ne v8, v7, :cond_7

    .line 172
    .line 173
    :cond_6
    new-instance v8, Lc40/b;

    .line 174
    .line 175
    const/4 v13, 0x1

    .line 176
    invoke-direct/range {v8 .. v13}, Lc40/b;-><init>(Ll2/b1;Lz4/p;Lz4/m;Ll2/b1;I)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v1, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    :cond_7
    check-cast v8, Lt3/q0;

    .line 183
    .line 184
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v6

    .line 188
    if-ne v6, v7, :cond_8

    .line 189
    .line 190
    new-instance v6, Lc40/c;

    .line 191
    .line 192
    const/4 v13, 0x1

    .line 193
    invoke-direct {v6, v12, v11, v13}, Lc40/c;-><init>(Ll2/b1;Lz4/m;I)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {v1, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    :cond_8
    move-object v14, v6

    .line 200
    check-cast v14, Lay0/a;

    .line 201
    .line 202
    invoke-virtual {v1, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result v6

    .line 206
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v11

    .line 210
    if-nez v6, :cond_9

    .line 211
    .line 212
    if-ne v11, v7, :cond_a

    .line 213
    .line 214
    :cond_9
    new-instance v11, Lc40/d;

    .line 215
    .line 216
    const/4 v6, 0x1

    .line 217
    invoke-direct {v11, v10, v6}, Lc40/d;-><init>(Lz4/p;I)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v1, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    :cond_a
    check-cast v11, Lay0/k;

    .line 224
    .line 225
    invoke-static {v2, v5, v11}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 226
    .line 227
    .line 228
    move-result-object v2

    .line 229
    new-instance v11, Lco0/h;

    .line 230
    .line 231
    iget-object v15, v0, Lco0/d;->d:Ljava/lang/String;

    .line 232
    .line 233
    iget-object v6, v0, Lco0/d;->e:Ljava/lang/String;

    .line 234
    .line 235
    iget-wide v12, v0, Lco0/d;->f:J

    .line 236
    .line 237
    iget-object v7, v0, Lco0/d;->g:Ljava/lang/String;

    .line 238
    .line 239
    move-object/from16 v16, v6

    .line 240
    .line 241
    iget-wide v5, v0, Lco0/d;->h:J

    .line 242
    .line 243
    iget-object v10, v0, Lco0/d;->i:Ljava/lang/String;

    .line 244
    .line 245
    move-object/from16 p2, v3

    .line 246
    .line 247
    iget-boolean v3, v0, Lco0/d;->j:Z

    .line 248
    .line 249
    move/from16 v23, v3

    .line 250
    .line 251
    iget-object v3, v0, Lco0/d;->k:Ljava/lang/Integer;

    .line 252
    .line 253
    move-object/from16 v24, v3

    .line 254
    .line 255
    iget-object v3, v0, Lco0/d;->l:Ljava/lang/Boolean;

    .line 256
    .line 257
    move-object/from16 v25, v3

    .line 258
    .line 259
    iget-object v3, v0, Lco0/d;->m:Lay0/k;

    .line 260
    .line 261
    iget-object v0, v0, Lco0/d;->n:Lay0/o;

    .line 262
    .line 263
    move-object/from16 v27, v0

    .line 264
    .line 265
    move-object/from16 v26, v3

    .line 266
    .line 267
    move-wide/from16 v20, v5

    .line 268
    .line 269
    move-object/from16 v19, v7

    .line 270
    .line 271
    move-object/from16 v22, v10

    .line 272
    .line 273
    move-wide/from16 v17, v12

    .line 274
    .line 275
    move-object v13, v4

    .line 276
    move-object v12, v9

    .line 277
    invoke-direct/range {v11 .. v27}, Lco0/h;-><init>(Ll2/b1;Lz4/k;Lay0/a;Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;JLjava/lang/String;ZLjava/lang/Integer;Ljava/lang/Boolean;Lay0/k;Lay0/o;)V

    .line 278
    .line 279
    .line 280
    const v0, 0x478ef317

    .line 281
    .line 282
    .line 283
    invoke-static {v0, v1, v11}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    const/16 v3, 0x30

    .line 288
    .line 289
    invoke-static {v2, v0, v8, v1, v3}, Lt3/k1;->a(Lx2/s;Lt2/b;Lt3/q0;Ll2/o;I)V

    .line 290
    .line 291
    .line 292
    const/4 v0, 0x0

    .line 293
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 294
    .line 295
    .line 296
    return-object p2

    .line 297
    :cond_b
    move-object/from16 p2, v3

    .line 298
    .line 299
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 300
    .line 301
    .line 302
    return-object p2
.end method

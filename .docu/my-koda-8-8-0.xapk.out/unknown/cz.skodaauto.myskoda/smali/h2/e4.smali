.class public final Lh2/e4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/Long;

.field public final synthetic e:Ljava/lang/Long;

.field public final synthetic f:Lay0/n;

.field public final synthetic g:Lm1/t;

.field public final synthetic h:Lgy0/j;

.field public final synthetic i:Li2/z;

.field public final synthetic j:Li2/c0;

.field public final synthetic k:Lh2/g2;

.field public final synthetic l:Lh2/z1;

.field public final synthetic m:Li2/y;

.field public final synthetic n:Lh2/e8;


# direct methods
.method public constructor <init>(Ljava/lang/Long;Ljava/lang/Long;Lay0/n;Lm1/t;Lgy0/j;Li2/z;Li2/c0;Lh2/g2;Lh2/z1;Li2/y;Lh2/e8;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/e4;->d:Ljava/lang/Long;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/e4;->e:Ljava/lang/Long;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/e4;->f:Lay0/n;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/e4;->g:Lm1/t;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/e4;->h:Lgy0/j;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/e4;->i:Li2/z;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/e4;->j:Li2/c0;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/e4;->k:Lh2/g2;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/e4;->l:Lh2/z1;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/e4;->m:Li2/y;

    .line 23
    .line 24
    iput-object p11, p0, Lh2/e4;->n:Lh2/e8;

    .line 25
    .line 26
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
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x1

    .line 19
    const/4 v6, 0x0

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v5

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v6

    .line 25
    :goto_0
    and-int/2addr v2, v5

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
    if-eqz v2, :cond_7

    .line 33
    .line 34
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    invoke-static {v1}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    :cond_1
    check-cast v2, Lvy0/b0;

    .line 50
    .line 51
    const v4, 0x7f1205af

    .line 52
    .line 53
    .line 54
    invoke-static {v1, v4}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    const v5, 0x7f1205ae

    .line 59
    .line 60
    .line 61
    invoke-static {v1, v5}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    iget-object v7, v0, Lh2/e4;->d:Ljava/lang/Long;

    .line 66
    .line 67
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v8

    .line 71
    iget-object v9, v0, Lh2/e4;->e:Ljava/lang/Long;

    .line 72
    .line 73
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v10

    .line 77
    or-int/2addr v8, v10

    .line 78
    iget-object v10, v0, Lh2/e4;->f:Lay0/n;

    .line 79
    .line 80
    invoke-virtual {v1, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v11

    .line 84
    or-int/2addr v8, v11

    .line 85
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v11

    .line 89
    if-nez v8, :cond_2

    .line 90
    .line 91
    if-ne v11, v3, :cond_3

    .line 92
    .line 93
    :cond_2
    new-instance v11, Laa/o;

    .line 94
    .line 95
    const/16 v8, 0x15

    .line 96
    .line 97
    invoke-direct {v11, v7, v9, v10, v8}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v1, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    :cond_3
    check-cast v11, Lay0/k;

    .line 104
    .line 105
    new-instance v8, Lh2/n2;

    .line 106
    .line 107
    const/4 v10, 0x2

    .line 108
    iget-object v12, v0, Lh2/e4;->g:Lm1/t;

    .line 109
    .line 110
    invoke-direct {v8, v12, v2, v10}, Lh2/n2;-><init>(Lm1/t;Lvy0/b0;I)V

    .line 111
    .line 112
    .line 113
    new-instance v10, Lh2/n2;

    .line 114
    .line 115
    const/4 v13, 0x3

    .line 116
    invoke-direct {v10, v12, v2, v13}, Lh2/n2;-><init>(Lm1/t;Lvy0/b0;I)V

    .line 117
    .line 118
    .line 119
    new-instance v2, Ld4/d;

    .line 120
    .line 121
    invoke-direct {v2, v4, v8}, Ld4/d;-><init>(Ljava/lang/String;Lay0/a;)V

    .line 122
    .line 123
    .line 124
    new-instance v4, Ld4/d;

    .line 125
    .line 126
    invoke-direct {v4, v5, v10}, Ld4/d;-><init>(Ljava/lang/String;Lay0/a;)V

    .line 127
    .line 128
    .line 129
    filled-new-array {v2, v4}, [Ld4/d;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v4

    .line 141
    if-ne v4, v3, :cond_4

    .line 142
    .line 143
    new-instance v4, Lh10/d;

    .line 144
    .line 145
    const/16 v5, 0xb

    .line 146
    .line 147
    invoke-direct {v4, v5}, Lh10/d;-><init>(I)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    :cond_4
    check-cast v4, Lay0/k;

    .line 154
    .line 155
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 156
    .line 157
    invoke-static {v5, v6, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    iget-object v5, v0, Lh2/e4;->h:Lgy0/j;

    .line 162
    .line 163
    invoke-virtual {v1, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v5

    .line 167
    iget-object v6, v0, Lh2/e4;->i:Li2/z;

    .line 168
    .line 169
    invoke-virtual {v1, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v6

    .line 173
    or-int/2addr v5, v6

    .line 174
    iget-object v6, v0, Lh2/e4;->j:Li2/c0;

    .line 175
    .line 176
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v6

    .line 180
    or-int/2addr v5, v6

    .line 181
    iget-object v6, v0, Lh2/e4;->k:Lh2/g2;

    .line 182
    .line 183
    invoke-virtual {v1, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result v6

    .line 187
    or-int/2addr v5, v6

    .line 188
    invoke-virtual {v1, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v6

    .line 192
    or-int/2addr v5, v6

    .line 193
    iget-object v6, v0, Lh2/e4;->l:Lh2/z1;

    .line 194
    .line 195
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result v8

    .line 199
    or-int/2addr v5, v8

    .line 200
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v7

    .line 204
    or-int/2addr v5, v7

    .line 205
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v7

    .line 209
    or-int/2addr v5, v7

    .line 210
    invoke-virtual {v1, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v7

    .line 214
    or-int/2addr v5, v7

    .line 215
    iget-object v7, v0, Lh2/e4;->m:Li2/y;

    .line 216
    .line 217
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v8

    .line 221
    or-int/2addr v5, v8

    .line 222
    iget-object v8, v0, Lh2/e4;->n:Lh2/e8;

    .line 223
    .line 224
    invoke-virtual {v1, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    move-result v8

    .line 228
    or-int/2addr v5, v8

    .line 229
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v8

    .line 233
    if-nez v5, :cond_5

    .line 234
    .line 235
    if-ne v8, v3, :cond_6

    .line 236
    .line 237
    :cond_5
    new-instance v12, Lh2/c4;

    .line 238
    .line 239
    const/16 v24, 0x0

    .line 240
    .line 241
    iget-object v13, v0, Lh2/e4;->h:Lgy0/j;

    .line 242
    .line 243
    iget-object v14, v0, Lh2/e4;->i:Li2/z;

    .line 244
    .line 245
    iget-object v15, v0, Lh2/e4;->j:Li2/c0;

    .line 246
    .line 247
    iget-object v3, v0, Lh2/e4;->d:Ljava/lang/Long;

    .line 248
    .line 249
    iget-object v5, v0, Lh2/e4;->e:Ljava/lang/Long;

    .line 250
    .line 251
    iget-object v8, v0, Lh2/e4;->k:Lh2/g2;

    .line 252
    .line 253
    iget-object v9, v0, Lh2/e4;->n:Lh2/e8;

    .line 254
    .line 255
    move-object/from16 v23, v2

    .line 256
    .line 257
    move-object/from16 v16, v3

    .line 258
    .line 259
    move-object/from16 v17, v5

    .line 260
    .line 261
    move-object/from16 v22, v6

    .line 262
    .line 263
    move-object/from16 v19, v7

    .line 264
    .line 265
    move-object/from16 v20, v8

    .line 266
    .line 267
    move-object/from16 v21, v9

    .line 268
    .line 269
    move-object/from16 v18, v11

    .line 270
    .line 271
    invoke-direct/range {v12 .. v24}, Lh2/c4;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lay0/k;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v1, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 275
    .line 276
    .line 277
    move-object v8, v12

    .line 278
    :cond_6
    move-object v15, v8

    .line 279
    check-cast v15, Lay0/k;

    .line 280
    .line 281
    const/16 v17, 0x0

    .line 282
    .line 283
    const/16 v18, 0x1fc

    .line 284
    .line 285
    iget-object v8, v0, Lh2/e4;->g:Lm1/t;

    .line 286
    .line 287
    const/4 v9, 0x0

    .line 288
    const/4 v10, 0x0

    .line 289
    const/4 v11, 0x0

    .line 290
    const/4 v12, 0x0

    .line 291
    const/4 v13, 0x0

    .line 292
    const/4 v14, 0x0

    .line 293
    move-object/from16 v16, v1

    .line 294
    .line 295
    move-object v7, v4

    .line 296
    invoke-static/range {v7 .. v18}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 297
    .line 298
    .line 299
    goto :goto_1

    .line 300
    :cond_7
    move-object/from16 v16, v1

    .line 301
    .line 302
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 303
    .line 304
    .line 305
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 306
    .line 307
    return-object v0
.end method

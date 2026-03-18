.class public final synthetic Lsm0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(IILay0/a;Ljava/util/List;)V
    .locals 0

    .line 1
    iput p2, p0, Lsm0/b;->d:I

    iput-object p4, p0, Lsm0/b;->e:Ljava/util/List;

    iput-object p3, p0, Lsm0/b;->f:Lay0/a;

    iput p1, p0, Lsm0/b;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/util/List;Lay0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Lsm0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lsm0/b;->g:I

    iput-object p2, p0, Lsm0/b;->e:Ljava/util/List;

    iput-object p3, p0, Lsm0/b;->f:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lsm0/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    const/4 v5, 0x1

    .line 24
    const/4 v6, 0x2

    .line 25
    if-eq v3, v6, :cond_0

    .line 26
    .line 27
    move v3, v5

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v4

    .line 30
    :goto_0
    and-int/2addr v2, v5

    .line 31
    move-object v13, v1

    .line 32
    check-cast v13, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_6

    .line 39
    .line 40
    iget-object v1, v0, Lsm0/b;->e:Ljava/util/List;

    .line 41
    .line 42
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    if-nez v2, :cond_1

    .line 51
    .line 52
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 53
    .line 54
    if-ne v3, v2, :cond_2

    .line 55
    .line 56
    :cond_1
    new-instance v3, Ld01/v;

    .line 57
    .line 58
    const/16 v2, 0xf

    .line 59
    .line 60
    invoke-direct {v3, v1, v2}, Ld01/v;-><init>(Ljava/util/List;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v13, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_2
    check-cast v3, Lay0/a;

    .line 67
    .line 68
    iget v2, v0, Lsm0/b;->g:I

    .line 69
    .line 70
    invoke-static {v2, v3, v13, v4, v6}, Lp1/y;->b(ILay0/a;Ll2/o;II)Lp1/b;

    .line 71
    .line 72
    .line 73
    move-result-object v17

    .line 74
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 75
    .line 76
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 77
    .line 78
    invoke-virtual {v13, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    check-cast v3, Lj91/e;

    .line 83
    .line 84
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 85
    .line 86
    .line 87
    move-result-wide v6

    .line 88
    sget-object v3, Le3/j0;->a:Le3/i0;

    .line 89
    .line 90
    invoke-static {v2, v6, v7, v3}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 95
    .line 96
    invoke-static {v3, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    iget-wide v6, v13, Ll2/t;->T:J

    .line 101
    .line 102
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    invoke-static {v13, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 115
    .line 116
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 120
    .line 121
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 122
    .line 123
    .line 124
    iget-boolean v8, v13, Ll2/t;->S:Z

    .line 125
    .line 126
    if-eqz v8, :cond_3

    .line 127
    .line 128
    invoke-virtual {v13, v7}, Ll2/t;->l(Lay0/a;)V

    .line 129
    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_3
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 133
    .line 134
    .line 135
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 136
    .line 137
    invoke-static {v7, v3, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 141
    .line 142
    invoke-static {v3, v6, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    .line 144
    .line 145
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 146
    .line 147
    iget-boolean v6, v13, Ll2/t;->S:Z

    .line 148
    .line 149
    if-nez v6, :cond_4

    .line 150
    .line 151
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v7

    .line 159
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v6

    .line 163
    if-nez v6, :cond_5

    .line 164
    .line 165
    :cond_4
    invoke-static {v4, v13, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 166
    .line 167
    .line 168
    :cond_5
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 169
    .line 170
    invoke-static {v3, v2, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 174
    .line 175
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    check-cast v3, Lj91/c;

    .line 180
    .line 181
    iget v7, v3, Lj91/c;->d:F

    .line 182
    .line 183
    new-instance v3, Li40/x;

    .line 184
    .line 185
    const/4 v4, 0x2

    .line 186
    invoke-direct {v3, v1, v4}, Li40/x;-><init>(Ljava/util/List;I)V

    .line 187
    .line 188
    .line 189
    const v1, -0x5e20470f

    .line 190
    .line 191
    .line 192
    invoke-static {v1, v13, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 193
    .line 194
    .line 195
    move-result-object v18

    .line 196
    const/4 v8, 0x0

    .line 197
    const/16 v9, 0x3fde

    .line 198
    .line 199
    const/4 v10, 0x0

    .line 200
    const/4 v11, 0x0

    .line 201
    const/4 v12, 0x0

    .line 202
    move-object v14, v13

    .line 203
    const/4 v13, 0x0

    .line 204
    const/4 v15, 0x0

    .line 205
    const/16 v16, 0x0

    .line 206
    .line 207
    const/16 v19, 0x0

    .line 208
    .line 209
    const/16 v20, 0x0

    .line 210
    .line 211
    const/16 v21, 0x0

    .line 212
    .line 213
    const/16 v22, 0x0

    .line 214
    .line 215
    invoke-static/range {v7 .. v22}, Ljp/ad;->b(FIILe1/j;Lh1/g;Lh1/n;Lk1/z0;Ll2/o;Lo3/a;Lp1/f;Lp1/v;Lt2/b;Lx2/i;Lx2/s;ZZ)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v1

    .line 222
    check-cast v1, Lj91/c;

    .line 223
    .line 224
    iget v1, v1, Lj91/c;->c:F

    .line 225
    .line 226
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 227
    .line 228
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 229
    .line 230
    .line 231
    move-result-object v8

    .line 232
    sget-object v12, Lxk0/h;->e:Lt2/b;

    .line 233
    .line 234
    move-object v13, v14

    .line 235
    const/high16 v14, 0x180000

    .line 236
    .line 237
    const/16 v15, 0x3c

    .line 238
    .line 239
    iget-object v7, v0, Lsm0/b;->f:Lay0/a;

    .line 240
    .line 241
    const/4 v9, 0x0

    .line 242
    invoke-static/range {v7 .. v15}, Lh2/r;->l(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;Ll2/o;II)V

    .line 243
    .line 244
    .line 245
    move-object v14, v13

    .line 246
    invoke-virtual {v14, v5}, Ll2/t;->q(Z)V

    .line 247
    .line 248
    .line 249
    goto :goto_2

    .line 250
    :cond_6
    move-object v14, v13

    .line 251
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 252
    .line 253
    .line 254
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 255
    .line 256
    return-object v0

    .line 257
    :pswitch_0
    move-object/from16 v1, p1

    .line 258
    .line 259
    check-cast v1, Ll2/o;

    .line 260
    .line 261
    move-object/from16 v2, p2

    .line 262
    .line 263
    check-cast v2, Ljava/lang/Integer;

    .line 264
    .line 265
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 266
    .line 267
    .line 268
    iget v2, v0, Lsm0/b;->g:I

    .line 269
    .line 270
    or-int/lit8 v2, v2, 0x1

    .line 271
    .line 272
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 273
    .line 274
    .line 275
    move-result v2

    .line 276
    iget-object v3, v0, Lsm0/b;->e:Ljava/util/List;

    .line 277
    .line 278
    iget-object v0, v0, Lsm0/b;->f:Lay0/a;

    .line 279
    .line 280
    invoke-static {v3, v0, v1, v2}, Lsm0/a;->b(Ljava/util/List;Lay0/a;Ll2/o;I)V

    .line 281
    .line 282
    .line 283
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 284
    .line 285
    return-object v0

    .line 286
    :pswitch_1
    move-object/from16 v1, p1

    .line 287
    .line 288
    check-cast v1, Ll2/o;

    .line 289
    .line 290
    move-object/from16 v2, p2

    .line 291
    .line 292
    check-cast v2, Ljava/lang/Integer;

    .line 293
    .line 294
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 295
    .line 296
    .line 297
    iget v2, v0, Lsm0/b;->g:I

    .line 298
    .line 299
    or-int/lit8 v2, v2, 0x1

    .line 300
    .line 301
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 302
    .line 303
    .line 304
    move-result v2

    .line 305
    iget-object v3, v0, Lsm0/b;->e:Ljava/util/List;

    .line 306
    .line 307
    iget-object v0, v0, Lsm0/b;->f:Lay0/a;

    .line 308
    .line 309
    invoke-static {v3, v0, v1, v2}, Lsm0/a;->b(Ljava/util/List;Lay0/a;Ll2/o;I)V

    .line 310
    .line 311
    .line 312
    goto :goto_3

    .line 313
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

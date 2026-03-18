.class public final Lh2/z2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Lh2/z1;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Lh2/z1;ZZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/z2;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/z2;->e:Lh2/z1;

    .line 7
    .line 8
    iput-boolean p3, p0, Lh2/z2;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lh2/z2;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lh2/z2;->h:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lh2/z2;->i:Z

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

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
    move-object v11, v1

    .line 27
    check-cast v11, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v11, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_c

    .line 34
    .line 35
    sget v1, Lk2/m;->g:F

    .line 36
    .line 37
    sget v2, Lk2/m;->e:F

    .line 38
    .line 39
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 40
    .line 41
    invoke-static {v3, v1, v2}, Landroidx/compose/foundation/layout/d;->k(Lx2/s;FF)Lx2/s;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    sget-object v2, Lx2/c;->h:Lx2/j;

    .line 46
    .line 47
    invoke-static {v2, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    iget-wide v7, v11, Ll2/t;->T:J

    .line 52
    .line 53
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 58
    .line 59
    .line 60
    move-result-object v7

    .line 61
    invoke-static {v11, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 66
    .line 67
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 71
    .line 72
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 73
    .line 74
    .line 75
    iget-boolean v9, v11, Ll2/t;->S:Z

    .line 76
    .line 77
    if-eqz v9, :cond_1

    .line 78
    .line 79
    invoke-virtual {v11, v8}, Ll2/t;->l(Lay0/a;)V

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_1
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 84
    .line 85
    .line 86
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 87
    .line 88
    invoke-static {v8, v2, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 89
    .line 90
    .line 91
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 92
    .line 93
    invoke-static {v2, v7, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 94
    .line 95
    .line 96
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 97
    .line 98
    iget-boolean v7, v11, Ll2/t;->S:Z

    .line 99
    .line 100
    if-nez v7, :cond_2

    .line 101
    .line 102
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v7

    .line 106
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 107
    .line 108
    .line 109
    move-result-object v8

    .line 110
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v7

    .line 114
    if-nez v7, :cond_3

    .line 115
    .line 116
    :cond_2
    invoke-static {v4, v11, v4, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 117
    .line 118
    .line 119
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 120
    .line 121
    invoke-static {v2, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 129
    .line 130
    if-ne v1, v2, :cond_4

    .line 131
    .line 132
    new-instance v1, Lh10/d;

    .line 133
    .line 134
    const/4 v2, 0x5

    .line 135
    invoke-direct {v1, v2}, Lh10/d;-><init>(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v11, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_4
    check-cast v1, Lay0/k;

    .line 142
    .line 143
    invoke-static {v3, v1}, Ld4/n;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    iget-object v2, v0, Lh2/z2;->e:Lh2/z1;

    .line 148
    .line 149
    iget-wide v3, v2, Lh2/z1;->o:J

    .line 150
    .line 151
    iget-boolean v7, v0, Lh2/z2;->g:Z

    .line 152
    .line 153
    iget-boolean v8, v0, Lh2/z2;->h:Z

    .line 154
    .line 155
    iget-boolean v9, v0, Lh2/z2;->i:Z

    .line 156
    .line 157
    if-eqz v7, :cond_5

    .line 158
    .line 159
    if-eqz v9, :cond_5

    .line 160
    .line 161
    iget-wide v3, v2, Lh2/z1;->p:J

    .line 162
    .line 163
    goto :goto_2

    .line 164
    :cond_5
    if-eqz v7, :cond_6

    .line 165
    .line 166
    if-nez v9, :cond_6

    .line 167
    .line 168
    iget-wide v3, v2, Lh2/z1;->q:J

    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_6
    if-eqz v8, :cond_7

    .line 172
    .line 173
    if-eqz v9, :cond_7

    .line 174
    .line 175
    iget-wide v3, v2, Lh2/z1;->w:J

    .line 176
    .line 177
    goto :goto_2

    .line 178
    :cond_7
    if-eqz v8, :cond_8

    .line 179
    .line 180
    if-nez v9, :cond_8

    .line 181
    .line 182
    goto :goto_2

    .line 183
    :cond_8
    iget-boolean v7, v0, Lh2/z2;->f:Z

    .line 184
    .line 185
    if-eqz v7, :cond_9

    .line 186
    .line 187
    if-eqz v9, :cond_9

    .line 188
    .line 189
    iget-wide v3, v2, Lh2/z1;->t:J

    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_9
    if-eqz v9, :cond_a

    .line 193
    .line 194
    iget-wide v3, v2, Lh2/z1;->n:J

    .line 195
    .line 196
    :cond_a
    :goto_2
    if-eqz v8, :cond_b

    .line 197
    .line 198
    const v2, -0x39c9230c

    .line 199
    .line 200
    .line 201
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 202
    .line 203
    .line 204
    new-instance v2, Le3/s;

    .line 205
    .line 206
    invoke-direct {v2, v3, v4}, Le3/s;-><init>(J)V

    .line 207
    .line 208
    .line 209
    invoke-static {v2, v11}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 210
    .line 211
    .line 212
    move-result-object v2

    .line 213
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 214
    .line 215
    .line 216
    goto :goto_3

    .line 217
    :cond_b
    const v2, -0x39c8238a

    .line 218
    .line 219
    .line 220
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 221
    .line 222
    .line 223
    sget-object v2, Lk2/w;->f:Lk2/w;

    .line 224
    .line 225
    invoke-static {v2, v11}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 226
    .line 227
    .line 228
    move-result-object v9

    .line 229
    const/4 v12, 0x0

    .line 230
    const/16 v13, 0xc

    .line 231
    .line 232
    const/4 v10, 0x0

    .line 233
    move-wide v7, v3

    .line 234
    invoke-static/range {v7 .. v13}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 235
    .line 236
    .line 237
    move-result-object v2

    .line 238
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 239
    .line 240
    .line 241
    :goto_3
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v2

    .line 245
    check-cast v2, Le3/s;

    .line 246
    .line 247
    iget-wide v9, v2, Le3/s;->a:J

    .line 248
    .line 249
    new-instance v2, Lr4/k;

    .line 250
    .line 251
    const/4 v3, 0x3

    .line 252
    invoke-direct {v2, v3}, Lr4/k;-><init>(I)V

    .line 253
    .line 254
    .line 255
    const/16 v28, 0x0

    .line 256
    .line 257
    const v29, 0x3fbf8

    .line 258
    .line 259
    .line 260
    iget-object v7, v0, Lh2/z2;->d:Ljava/lang/String;

    .line 261
    .line 262
    move-object/from16 v26, v11

    .line 263
    .line 264
    const-wide/16 v11, 0x0

    .line 265
    .line 266
    const/4 v13, 0x0

    .line 267
    const-wide/16 v14, 0x0

    .line 268
    .line 269
    const/16 v16, 0x0

    .line 270
    .line 271
    const-wide/16 v18, 0x0

    .line 272
    .line 273
    const/16 v20, 0x0

    .line 274
    .line 275
    const/16 v21, 0x0

    .line 276
    .line 277
    const/16 v22, 0x0

    .line 278
    .line 279
    const/16 v23, 0x0

    .line 280
    .line 281
    const/16 v24, 0x0

    .line 282
    .line 283
    const/16 v25, 0x0

    .line 284
    .line 285
    const/16 v27, 0x0

    .line 286
    .line 287
    move-object v8, v1

    .line 288
    move-object/from16 v17, v2

    .line 289
    .line 290
    invoke-static/range {v7 .. v29}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 291
    .line 292
    .line 293
    move-object/from16 v11, v26

    .line 294
    .line 295
    invoke-virtual {v11, v5}, Ll2/t;->q(Z)V

    .line 296
    .line 297
    .line 298
    goto :goto_4

    .line 299
    :cond_c
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 300
    .line 301
    .line 302
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 303
    .line 304
    return-object v0
.end method

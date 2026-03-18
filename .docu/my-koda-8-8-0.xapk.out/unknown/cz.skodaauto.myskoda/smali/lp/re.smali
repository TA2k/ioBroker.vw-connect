.class public abstract Llp/re;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v8, p0

    .line 2
    .line 3
    check-cast v8, Ll2/t;

    .line 4
    .line 5
    const v1, 0xf68df43

    .line 6
    .line 7
    .line 8
    invoke-virtual {v8, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    const/4 v11, 0x1

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v1, v11

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v1, 0x0

    .line 17
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v8, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_4

    .line 24
    .line 25
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 26
    .line 27
    const/high16 v2, 0x3f800000    # 1.0f

    .line 28
    .line 29
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    const-string v2, "wallbox_change_auth_mode_response_text"

    .line 34
    .line 35
    invoke-static {v1, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    sget-object v2, Lx2/c;->n:Lx2/i;

    .line 40
    .line 41
    sget-object v3, Lk1/j;->a:Lk1/c;

    .line 42
    .line 43
    const/16 v4, 0x30

    .line 44
    .line 45
    invoke-static {v3, v2, v8, v4}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    iget-wide v4, v8, Ll2/t;->T:J

    .line 50
    .line 51
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    invoke-static {v8, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 64
    .line 65
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 69
    .line 70
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 71
    .line 72
    .line 73
    iget-boolean v7, v8, Ll2/t;->S:Z

    .line 74
    .line 75
    if-eqz v7, :cond_1

    .line 76
    .line 77
    invoke-virtual {v8, v6}, Ll2/t;->l(Lay0/a;)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 82
    .line 83
    .line 84
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 85
    .line 86
    invoke-static {v6, v3, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 87
    .line 88
    .line 89
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 90
    .line 91
    invoke-static {v3, v5, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 92
    .line 93
    .line 94
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 95
    .line 96
    iget-boolean v5, v8, Ll2/t;->S:Z

    .line 97
    .line 98
    if-nez v5, :cond_2

    .line 99
    .line 100
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v5

    .line 104
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v5

    .line 112
    if-nez v5, :cond_3

    .line 113
    .line 114
    :cond_2
    invoke-static {v4, v8, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 115
    .line 116
    .line 117
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 118
    .line 119
    invoke-static {v3, v1, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    const v1, 0x7f080348

    .line 123
    .line 124
    .line 125
    const/4 v3, 0x6

    .line 126
    invoke-static {v1, v3, v8}, Ljp/ha;->c(IILl2/o;)Lj3/f;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    invoke-static {v1, v8}, Lj3/b;->c(Lj3/f;Ll2/o;)Lj3/j0;

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    new-instance v12, Landroidx/compose/foundation/layout/VerticalAlignElement;

    .line 135
    .line 136
    invoke-direct {v12, v2}, Landroidx/compose/foundation/layout/VerticalAlignElement;-><init>(Lx2/i;)V

    .line 137
    .line 138
    .line 139
    int-to-float v15, v3

    .line 140
    const/16 v16, 0x0

    .line 141
    .line 142
    const/16 v17, 0xb

    .line 143
    .line 144
    const/4 v13, 0x0

    .line 145
    const/4 v14, 0x0

    .line 146
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    sget-object v12, Lj91/h;->a:Ll2/u2;

    .line 151
    .line 152
    invoke-virtual {v8, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v2

    .line 156
    check-cast v2, Lj91/e;

    .line 157
    .line 158
    invoke-virtual {v2}, Lj91/e;->u()J

    .line 159
    .line 160
    .line 161
    move-result-wide v4

    .line 162
    new-instance v7, Le3/m;

    .line 163
    .line 164
    const/4 v2, 0x5

    .line 165
    invoke-direct {v7, v4, v5, v2}, Le3/m;-><init>(JI)V

    .line 166
    .line 167
    .line 168
    const/16 v9, 0x38

    .line 169
    .line 170
    const/16 v10, 0x38

    .line 171
    .line 172
    const-string v2, "error success icon"

    .line 173
    .line 174
    const/4 v4, 0x0

    .line 175
    const/4 v5, 0x0

    .line 176
    const/4 v6, 0x0

    .line 177
    invoke-static/range {v1 .. v10}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 178
    .line 179
    .line 180
    const v1, 0x7f120bd9

    .line 181
    .line 182
    .line 183
    invoke-static {v8, v1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 188
    .line 189
    invoke-virtual {v8, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    check-cast v2, Lj91/f;

    .line 194
    .line 195
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 196
    .line 197
    .line 198
    move-result-object v2

    .line 199
    invoke-virtual {v8, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v3

    .line 203
    check-cast v3, Lj91/e;

    .line 204
    .line 205
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 206
    .line 207
    .line 208
    move-result-wide v4

    .line 209
    const/16 v21, 0x0

    .line 210
    .line 211
    const v22, 0xfff4

    .line 212
    .line 213
    .line 214
    const/4 v3, 0x0

    .line 215
    const-wide/16 v6, 0x0

    .line 216
    .line 217
    move-object/from16 v19, v8

    .line 218
    .line 219
    const/4 v8, 0x0

    .line 220
    const-wide/16 v9, 0x0

    .line 221
    .line 222
    move v12, v11

    .line 223
    const/4 v11, 0x0

    .line 224
    move v13, v12

    .line 225
    const/4 v12, 0x0

    .line 226
    move v15, v13

    .line 227
    const-wide/16 v13, 0x0

    .line 228
    .line 229
    move/from16 v16, v15

    .line 230
    .line 231
    const/4 v15, 0x0

    .line 232
    move/from16 v17, v16

    .line 233
    .line 234
    const/16 v16, 0x0

    .line 235
    .line 236
    move/from16 v18, v17

    .line 237
    .line 238
    const/16 v17, 0x0

    .line 239
    .line 240
    move/from16 v20, v18

    .line 241
    .line 242
    const/16 v18, 0x0

    .line 243
    .line 244
    move/from16 v23, v20

    .line 245
    .line 246
    const/16 v20, 0x0

    .line 247
    .line 248
    move/from16 v0, v23

    .line 249
    .line 250
    invoke-static/range {v1 .. v22}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 251
    .line 252
    .line 253
    move-object/from16 v8, v19

    .line 254
    .line 255
    invoke-virtual {v8, v0}, Ll2/t;->q(Z)V

    .line 256
    .line 257
    .line 258
    goto :goto_2

    .line 259
    :cond_4
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 260
    .line 261
    .line 262
    :goto_2
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    if-eqz v0, :cond_5

    .line 267
    .line 268
    new-instance v1, Lxj/h;

    .line 269
    .line 270
    const/4 v2, 0x7

    .line 271
    move/from16 v3, p1

    .line 272
    .line 273
    invoke-direct {v1, v3, v2}, Lxj/h;-><init>(II)V

    .line 274
    .line 275
    .line 276
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 277
    .line 278
    :cond_5
    return-void
.end method

.method public static final b(Ll4/v;)Lg4/g;
    .locals 3

    .line 1
    iget-object v0, p0, Ll4/v;->a:Lg4/g;

    .line 2
    .line 3
    iget-wide v1, p0, Ll4/v;->b:J

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    invoke-static {v1, v2}, Lg4/o0;->f(J)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    invoke-static {v1, v2}, Lg4/o0;->e(J)I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    invoke-virtual {v0, p0, v1}, Lg4/g;->d(II)Lg4/g;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static final c(Ll4/v;I)Lg4/g;
    .locals 4

    .line 1
    iget-object v0, p0, Ll4/v;->a:Lg4/g;

    .line 2
    .line 3
    iget-wide v1, p0, Ll4/v;->b:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lg4/o0;->e(J)I

    .line 6
    .line 7
    .line 8
    move-result v3

    .line 9
    invoke-static {v1, v2}, Lg4/o0;->e(J)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    add-int/2addr v1, p1

    .line 14
    iget-object p0, p0, Ll4/v;->a:Lg4/g;

    .line 15
    .line 16
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    invoke-static {v1, p0}, Ljava/lang/Math;->min(II)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-virtual {v0, v3, p0}, Lg4/g;->d(II)Lg4/g;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public static final d(Ll4/v;I)Lg4/g;
    .locals 3

    .line 1
    iget-object v0, p0, Ll4/v;->a:Lg4/g;

    .line 2
    .line 3
    iget-wide v1, p0, Ll4/v;->b:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lg4/o0;->f(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    sub-int/2addr p0, p1

    .line 10
    const/4 p1, 0x0

    .line 11
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-static {v1, v2}, Lg4/o0;->f(J)I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    invoke-virtual {v0, p0, p1}, Lg4/g;->d(II)Lg4/g;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

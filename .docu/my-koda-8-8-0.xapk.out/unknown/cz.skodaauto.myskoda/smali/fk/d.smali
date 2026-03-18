.class public abstract Lfk/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lzb/u;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lzb/k;->a:Lzb/u;

    .line 2
    .line 3
    sput-object v0, Lfk/d;->a:Lzb/u;

    .line 4
    .line 5
    return-void
.end method

.method public static final a(Lhc/a;Lay0/k;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "event"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v13, p2

    .line 13
    .line 14
    check-cast v13, Ll2/t;

    .line 15
    .line 16
    const v3, -0x37e0bcc9

    .line 17
    .line 18
    .line 19
    invoke-virtual {v13, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    and-int/lit8 v3, v2, 0x6

    .line 23
    .line 24
    const/4 v11, 0x2

    .line 25
    const/4 v12, 0x4

    .line 26
    if-nez v3, :cond_2

    .line 27
    .line 28
    and-int/lit8 v3, v2, 0x8

    .line 29
    .line 30
    if-nez v3, :cond_0

    .line 31
    .line 32
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    :goto_0
    if-eqz v3, :cond_1

    .line 42
    .line 43
    move v3, v12

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    move v3, v11

    .line 46
    :goto_1
    or-int/2addr v3, v2

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    move v3, v2

    .line 49
    :goto_2
    and-int/lit8 v4, v2, 0x30

    .line 50
    .line 51
    const/16 v14, 0x20

    .line 52
    .line 53
    if-nez v4, :cond_4

    .line 54
    .line 55
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    if-eqz v4, :cond_3

    .line 60
    .line 61
    move v4, v14

    .line 62
    goto :goto_3

    .line 63
    :cond_3
    const/16 v4, 0x10

    .line 64
    .line 65
    :goto_3
    or-int/2addr v3, v4

    .line 66
    :cond_4
    and-int/lit8 v4, v3, 0x13

    .line 67
    .line 68
    const/16 v5, 0x12

    .line 69
    .line 70
    const/4 v15, 0x0

    .line 71
    const/4 v6, 0x1

    .line 72
    if-eq v4, v5, :cond_5

    .line 73
    .line 74
    move v4, v6

    .line 75
    goto :goto_4

    .line 76
    :cond_5
    move v4, v15

    .line 77
    :goto_4
    and-int/lit8 v5, v3, 0x1

    .line 78
    .line 79
    invoke-virtual {v13, v5, v4}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    if-eqz v4, :cond_e

    .line 84
    .line 85
    sget-object v4, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 86
    .line 87
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 88
    .line 89
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 90
    .line 91
    invoke-static {v5, v7, v13, v15}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    iget-wide v7, v13, Ll2/t;->T:J

    .line 96
    .line 97
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 98
    .line 99
    .line 100
    move-result v7

    .line 101
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    invoke-static {v13, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 110
    .line 111
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 112
    .line 113
    .line 114
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 115
    .line 116
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 117
    .line 118
    .line 119
    iget-boolean v10, v13, Ll2/t;->S:Z

    .line 120
    .line 121
    if-eqz v10, :cond_6

    .line 122
    .line 123
    invoke-virtual {v13, v9}, Ll2/t;->l(Lay0/a;)V

    .line 124
    .line 125
    .line 126
    goto :goto_5

    .line 127
    :cond_6
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 128
    .line 129
    .line 130
    :goto_5
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 131
    .line 132
    invoke-static {v9, v5, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 133
    .line 134
    .line 135
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 136
    .line 137
    invoke-static {v5, v8, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 141
    .line 142
    iget-boolean v8, v13, Ll2/t;->S:Z

    .line 143
    .line 144
    if-nez v8, :cond_7

    .line 145
    .line 146
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v8

    .line 150
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 151
    .line 152
    .line 153
    move-result-object v9

    .line 154
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v8

    .line 158
    if-nez v8, :cond_8

    .line 159
    .line 160
    :cond_7
    invoke-static {v7, v13, v7, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 161
    .line 162
    .line 163
    :cond_8
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 164
    .line 165
    invoke-static {v5, v4, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    const/4 v9, 0x6

    .line 169
    const/16 v10, 0xe

    .line 170
    .line 171
    const-string v4, ""

    .line 172
    .line 173
    const/4 v5, 0x0

    .line 174
    move v7, v6

    .line 175
    const/4 v6, 0x0

    .line 176
    move v8, v7

    .line 177
    const/4 v7, 0x0

    .line 178
    move-object/from16 v16, v13

    .line 179
    .line 180
    move v13, v8

    .line 181
    move-object/from16 v8, v16

    .line 182
    .line 183
    invoke-static/range {v4 .. v10}, Ldk/l;->a(Ljava/lang/String;Lx2/s;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;Ll2/o;II)V

    .line 184
    .line 185
    .line 186
    const/16 v4, 0x18

    .line 187
    .line 188
    int-to-float v4, v4

    .line 189
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 190
    .line 191
    const/4 v6, 0x0

    .line 192
    invoke-static {v5, v4, v6, v11}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    and-int/lit8 v5, v3, 0xe

    .line 197
    .line 198
    if-eq v5, v12, :cond_a

    .line 199
    .line 200
    and-int/lit8 v5, v3, 0x8

    .line 201
    .line 202
    if-eqz v5, :cond_9

    .line 203
    .line 204
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v5

    .line 208
    if-eqz v5, :cond_9

    .line 209
    .line 210
    goto :goto_6

    .line 211
    :cond_9
    move v6, v15

    .line 212
    goto :goto_7

    .line 213
    :cond_a
    :goto_6
    move v6, v13

    .line 214
    :goto_7
    and-int/lit8 v3, v3, 0x70

    .line 215
    .line 216
    if-ne v3, v14, :cond_b

    .line 217
    .line 218
    move v15, v13

    .line 219
    :cond_b
    or-int v3, v6, v15

    .line 220
    .line 221
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    if-nez v3, :cond_c

    .line 226
    .line 227
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 228
    .line 229
    if-ne v5, v3, :cond_d

    .line 230
    .line 231
    :cond_c
    new-instance v5, Let/g;

    .line 232
    .line 233
    const/4 v3, 0x4

    .line 234
    invoke-direct {v5, v3, v0, v1}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v8, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    :cond_d
    move-object v12, v5

    .line 241
    check-cast v12, Lay0/k;

    .line 242
    .line 243
    const/4 v14, 0x6

    .line 244
    const/16 v15, 0x1fe

    .line 245
    .line 246
    const/4 v5, 0x0

    .line 247
    const/4 v6, 0x0

    .line 248
    const/4 v7, 0x0

    .line 249
    move v3, v13

    .line 250
    move-object v13, v8

    .line 251
    const/4 v8, 0x0

    .line 252
    const/4 v9, 0x0

    .line 253
    const/4 v10, 0x0

    .line 254
    const/4 v11, 0x0

    .line 255
    invoke-static/range {v4 .. v15}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v13, v3}, Ll2/t;->q(Z)V

    .line 259
    .line 260
    .line 261
    goto :goto_8

    .line 262
    :cond_e
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 263
    .line 264
    .line 265
    :goto_8
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 266
    .line 267
    .line 268
    move-result-object v3

    .line 269
    if-eqz v3, :cond_f

    .line 270
    .line 271
    new-instance v4, La71/n0;

    .line 272
    .line 273
    const/16 v5, 0xc

    .line 274
    .line 275
    invoke-direct {v4, v2, v5, v0, v1}, La71/n0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 276
    .line 277
    .line 278
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 279
    .line 280
    :cond_f
    return-void
.end method

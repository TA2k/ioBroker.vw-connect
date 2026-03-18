.class public abstract Lkp/ca;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lug/b;Lay0/k;Ll2/o;I)V
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
    const-string v3, "uiState"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "event"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v13, p2

    .line 18
    .line 19
    check-cast v13, Ll2/t;

    .line 20
    .line 21
    const v3, -0x2d72fbf

    .line 22
    .line 23
    .line 24
    invoke-virtual {v13, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    const/4 v11, 0x4

    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    move v3, v11

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v3, 0x2

    .line 37
    :goto_0
    or-int/2addr v3, v2

    .line 38
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    const/16 v12, 0x20

    .line 43
    .line 44
    if-eqz v4, :cond_1

    .line 45
    .line 46
    move v4, v12

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    const/16 v4, 0x10

    .line 49
    .line 50
    :goto_1
    or-int/2addr v3, v4

    .line 51
    and-int/lit8 v4, v3, 0x13

    .line 52
    .line 53
    const/16 v5, 0x12

    .line 54
    .line 55
    const/4 v14, 0x0

    .line 56
    const/4 v15, 0x1

    .line 57
    if-eq v4, v5, :cond_2

    .line 58
    .line 59
    move v4, v15

    .line 60
    goto :goto_2

    .line 61
    :cond_2
    move v4, v14

    .line 62
    :goto_2
    and-int/lit8 v5, v3, 0x1

    .line 63
    .line 64
    invoke-virtual {v13, v5, v4}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    if-eqz v4, :cond_b

    .line 69
    .line 70
    sget-object v4, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 71
    .line 72
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 73
    .line 74
    sget-object v6, Lx2/c;->p:Lx2/h;

    .line 75
    .line 76
    invoke-static {v5, v6, v13, v14}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 77
    .line 78
    .line 79
    move-result-object v5

    .line 80
    iget-wide v6, v13, Ll2/t;->T:J

    .line 81
    .line 82
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 83
    .line 84
    .line 85
    move-result v6

    .line 86
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 87
    .line 88
    .line 89
    move-result-object v7

    .line 90
    invoke-static {v13, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object v8

    .line 94
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 95
    .line 96
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 100
    .line 101
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 102
    .line 103
    .line 104
    iget-boolean v10, v13, Ll2/t;->S:Z

    .line 105
    .line 106
    if-eqz v10, :cond_3

    .line 107
    .line 108
    invoke-virtual {v13, v9}, Ll2/t;->l(Lay0/a;)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_3
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 113
    .line 114
    .line 115
    :goto_3
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 116
    .line 117
    invoke-static {v9, v5, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 118
    .line 119
    .line 120
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 121
    .line 122
    invoke-static {v5, v7, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 123
    .line 124
    .line 125
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 126
    .line 127
    iget-boolean v7, v13, Ll2/t;->S:Z

    .line 128
    .line 129
    if-nez v7, :cond_4

    .line 130
    .line 131
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v7

    .line 135
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 136
    .line 137
    .line 138
    move-result-object v9

    .line 139
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v7

    .line 143
    if-nez v7, :cond_5

    .line 144
    .line 145
    :cond_4
    invoke-static {v6, v13, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 146
    .line 147
    .line 148
    :cond_5
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 149
    .line 150
    invoke-static {v5, v8, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 151
    .line 152
    .line 153
    const v5, 0x7f120a64

    .line 154
    .line 155
    .line 156
    invoke-static {v13, v5}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v5

    .line 160
    const/4 v9, 0x0

    .line 161
    const/16 v10, 0xe

    .line 162
    .line 163
    move-object v6, v4

    .line 164
    move-object v4, v5

    .line 165
    const/4 v5, 0x0

    .line 166
    move-object v7, v6

    .line 167
    const/4 v6, 0x0

    .line 168
    move-object v8, v7

    .line 169
    const/4 v7, 0x0

    .line 170
    move-object/from16 v16, v13

    .line 171
    .line 172
    move-object v13, v8

    .line 173
    move-object/from16 v8, v16

    .line 174
    .line 175
    invoke-static/range {v4 .. v10}, Ldk/l;->a(Ljava/lang/String;Lx2/s;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;Ll2/o;II)V

    .line 176
    .line 177
    .line 178
    and-int/lit8 v4, v3, 0xe

    .line 179
    .line 180
    if-eq v4, v11, :cond_7

    .line 181
    .line 182
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v4

    .line 186
    if-eqz v4, :cond_6

    .line 187
    .line 188
    goto :goto_4

    .line 189
    :cond_6
    move v4, v14

    .line 190
    goto :goto_5

    .line 191
    :cond_7
    :goto_4
    move v4, v15

    .line 192
    :goto_5
    and-int/lit8 v3, v3, 0x70

    .line 193
    .line 194
    if-ne v3, v12, :cond_8

    .line 195
    .line 196
    move v14, v15

    .line 197
    :cond_8
    or-int v3, v4, v14

    .line 198
    .line 199
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v4

    .line 203
    if-nez v3, :cond_9

    .line 204
    .line 205
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 206
    .line 207
    if-ne v4, v3, :cond_a

    .line 208
    .line 209
    :cond_9
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 210
    .line 211
    const/16 v3, 0x8

    .line 212
    .line 213
    invoke-direct {v4, v3, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v8, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    :cond_a
    move-object v12, v4

    .line 220
    check-cast v12, Lay0/k;

    .line 221
    .line 222
    const/4 v14, 0x6

    .line 223
    move v3, v15

    .line 224
    const/16 v15, 0x1fe

    .line 225
    .line 226
    const/4 v5, 0x0

    .line 227
    const/4 v6, 0x0

    .line 228
    const/4 v7, 0x0

    .line 229
    move-object v4, v13

    .line 230
    move-object v13, v8

    .line 231
    const/4 v8, 0x0

    .line 232
    const/4 v9, 0x0

    .line 233
    const/4 v10, 0x0

    .line 234
    const/4 v11, 0x0

    .line 235
    invoke-static/range {v4 .. v15}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v13, v3}, Ll2/t;->q(Z)V

    .line 239
    .line 240
    .line 241
    goto :goto_6

    .line 242
    :cond_b
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 243
    .line 244
    .line 245
    :goto_6
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 246
    .line 247
    .line 248
    move-result-object v3

    .line 249
    if-eqz v3, :cond_c

    .line 250
    .line 251
    new-instance v4, Lo50/b;

    .line 252
    .line 253
    const/16 v5, 0x1a

    .line 254
    .line 255
    invoke-direct {v4, v2, v5, v0, v1}, Lo50/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 256
    .line 257
    .line 258
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 259
    .line 260
    :cond_c
    return-void
.end method

.method public static final b(Ln1/o;Lg1/w1;)I
    .locals 2

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    iget-wide p0, p0, Ln1/o;->t:J

    .line 6
    .line 7
    const-wide v0, 0xffffffffL

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    and-long/2addr p0, v0

    .line 13
    :goto_0
    long-to-int p0, p0

    .line 14
    return p0

    .line 15
    :cond_0
    iget-wide p0, p0, Ln1/o;->t:J

    .line 16
    .line 17
    const/16 v0, 0x20

    .line 18
    .line 19
    shr-long/2addr p0, v0

    .line 20
    goto :goto_0
.end method

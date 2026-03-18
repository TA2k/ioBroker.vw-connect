.class public abstract Llp/cg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 12

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x512ada9e

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v1

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_6

    .line 23
    .line 24
    const v2, -0x6040e0aa

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-eqz v2, :cond_5

    .line 35
    .line 36
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    const-class v3, Lx60/f;

    .line 45
    .line 46
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    check-cast v2, Lql0/j;

    .line 67
    .line 68
    invoke-static {v2, p0, v1, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    move-object v5, v2

    .line 72
    check-cast v5, Lx60/f;

    .line 73
    .line 74
    iget-object v2, v5, Lql0/j;->g:Lyy0/l1;

    .line 75
    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-static {v2, v3, p0, v0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    check-cast v0, Lx60/d;

    .line 86
    .line 87
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 96
    .line 97
    if-nez v2, :cond_1

    .line 98
    .line 99
    if-ne v3, v11, :cond_2

    .line 100
    .line 101
    :cond_1
    new-instance v3, Lxk0/u;

    .line 102
    .line 103
    const/4 v9, 0x0

    .line 104
    const/16 v10, 0x18

    .line 105
    .line 106
    const/4 v4, 0x0

    .line 107
    const-class v6, Lx60/f;

    .line 108
    .line 109
    const-string v7, "onUnderstood"

    .line 110
    .line 111
    const-string v8, "onUnderstood()V"

    .line 112
    .line 113
    invoke-direct/range {v3 .. v10}, Lxk0/u;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    :cond_2
    check-cast v3, Lhy0/g;

    .line 120
    .line 121
    move-object v2, v3

    .line 122
    check-cast v2, Lay0/a;

    .line 123
    .line 124
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    if-nez v3, :cond_3

    .line 133
    .line 134
    if-ne v4, v11, :cond_4

    .line 135
    .line 136
    :cond_3
    new-instance v3, Lxk0/u;

    .line 137
    .line 138
    const/4 v9, 0x0

    .line 139
    const/16 v10, 0x19

    .line 140
    .line 141
    const/4 v4, 0x0

    .line 142
    const-class v6, Lx60/f;

    .line 143
    .line 144
    const-string v7, "onCancel"

    .line 145
    .line 146
    const-string v8, "onCancel()V"

    .line 147
    .line 148
    invoke-direct/range {v3 .. v10}, Lxk0/u;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    move-object v4, v3

    .line 155
    :cond_4
    check-cast v4, Lhy0/g;

    .line 156
    .line 157
    check-cast v4, Lay0/a;

    .line 158
    .line 159
    invoke-static {v0, v2, v4, p0, v1}, Llp/cg;->b(Lx60/d;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 160
    .line 161
    .line 162
    goto :goto_1

    .line 163
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 164
    .line 165
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 166
    .line 167
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw p0

    .line 171
    :cond_6
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 172
    .line 173
    .line 174
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    if-eqz p0, :cond_7

    .line 179
    .line 180
    new-instance v0, Lxk0/z;

    .line 181
    .line 182
    const/16 v1, 0xa

    .line 183
    .line 184
    invoke-direct {v0, p1, v1}, Lxk0/z;-><init>(II)V

    .line 185
    .line 186
    .line 187
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 188
    .line 189
    :cond_7
    return-void
.end method

.method public static final b(Lx60/d;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 8

    .line 1
    move-object v3, p3

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p3, 0x4c8ed953    # 7.4893976E7f

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p3}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p3

    .line 14
    if-eqz p3, :cond_0

    .line 15
    .line 16
    const/4 p3, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p3, 0x2

    .line 19
    :goto_0
    or-int/2addr p3, p4

    .line 20
    invoke-virtual {v3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/16 v1, 0x20

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    move v0, v1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v0, 0x10

    .line 31
    .line 32
    :goto_1
    or-int/2addr p3, v0

    .line 33
    invoke-virtual {v3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    const/16 v2, 0x100

    .line 38
    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    move v0, v2

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/16 v0, 0x80

    .line 44
    .line 45
    :goto_2
    or-int/2addr p3, v0

    .line 46
    and-int/lit16 v0, p3, 0x93

    .line 47
    .line 48
    const/16 v4, 0x92

    .line 49
    .line 50
    const/4 v5, 0x1

    .line 51
    const/4 v6, 0x0

    .line 52
    if-eq v0, v4, :cond_3

    .line 53
    .line 54
    move v0, v5

    .line 55
    goto :goto_3

    .line 56
    :cond_3
    move v0, v6

    .line 57
    :goto_3
    and-int/lit8 v4, p3, 0x1

    .line 58
    .line 59
    invoke-virtual {v3, v4, v0}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_f

    .line 64
    .line 65
    iget-object v0, p0, Lx60/d;->b:Lql0/g;

    .line 66
    .line 67
    if-nez v0, :cond_8

    .line 68
    .line 69
    const p3, 0x237f1b27

    .line 70
    .line 71
    .line 72
    invoke-virtual {v3, p3}, Ll2/t;->Y(I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 76
    .line 77
    .line 78
    sget-object p3, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 79
    .line 80
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 81
    .line 82
    invoke-static {v0, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    iget-wide v1, v3, Ll2/t;->T:J

    .line 87
    .line 88
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    invoke-static {v3, p3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 97
    .line 98
    .line 99
    move-result-object p3

    .line 100
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 101
    .line 102
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 106
    .line 107
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 108
    .line 109
    .line 110
    iget-boolean v7, v3, Ll2/t;->S:Z

    .line 111
    .line 112
    if-eqz v7, :cond_4

    .line 113
    .line 114
    invoke-virtual {v3, v4}, Ll2/t;->l(Lay0/a;)V

    .line 115
    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_4
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 119
    .line 120
    .line 121
    :goto_4
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 122
    .line 123
    invoke-static {v4, v0, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 124
    .line 125
    .line 126
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 127
    .line 128
    invoke-static {v0, v2, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 129
    .line 130
    .line 131
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 132
    .line 133
    iget-boolean v2, v3, Ll2/t;->S:Z

    .line 134
    .line 135
    if-nez v2, :cond_5

    .line 136
    .line 137
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    if-nez v2, :cond_6

    .line 150
    .line 151
    :cond_5
    invoke-static {v1, v3, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 152
    .line 153
    .line 154
    :cond_6
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 155
    .line 156
    invoke-static {v0, p3, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 157
    .line 158
    .line 159
    const/4 p3, 0x3

    .line 160
    const/4 v0, 0x0

    .line 161
    invoke-static {v0, v0, v3, v6, p3}, Lxf0/y1;->c(Lx2/s;Ljava/lang/String;Ll2/o;II)V

    .line 162
    .line 163
    .line 164
    iget-object p3, p0, Lx60/d;->a:Lae0/a;

    .line 165
    .line 166
    if-nez p3, :cond_7

    .line 167
    .line 168
    const p3, -0x1adae914

    .line 169
    .line 170
    .line 171
    invoke-virtual {v3, p3}, Ll2/t;->Y(I)V

    .line 172
    .line 173
    .line 174
    :goto_5
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 175
    .line 176
    .line 177
    goto :goto_6

    .line 178
    :cond_7
    const v0, 0x51b6dfb5

    .line 179
    .line 180
    .line 181
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 182
    .line 183
    .line 184
    invoke-static {p3, v3, v6}, Llp/cg;->c(Lae0/a;Ll2/o;I)V

    .line 185
    .line 186
    .line 187
    goto :goto_5

    .line 188
    :goto_6
    invoke-virtual {v3, v5}, Ll2/t;->q(Z)V

    .line 189
    .line 190
    .line 191
    move-object v1, p0

    .line 192
    move-object v2, p1

    .line 193
    move-object v4, p2

    .line 194
    move v5, p4

    .line 195
    goto/16 :goto_9

    .line 196
    .line 197
    :cond_8
    const v4, 0x237f1b28

    .line 198
    .line 199
    .line 200
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 201
    .line 202
    .line 203
    and-int/lit8 v4, p3, 0x70

    .line 204
    .line 205
    if-ne v4, v1, :cond_9

    .line 206
    .line 207
    move v1, v5

    .line 208
    goto :goto_7

    .line 209
    :cond_9
    move v1, v6

    .line 210
    :goto_7
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 215
    .line 216
    if-nez v1, :cond_a

    .line 217
    .line 218
    if-ne v4, v7, :cond_b

    .line 219
    .line 220
    :cond_a
    new-instance v4, Lvo0/g;

    .line 221
    .line 222
    const/16 v1, 0xf

    .line 223
    .line 224
    invoke-direct {v4, p1, v1}, Lvo0/g;-><init>(Lay0/a;I)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v3, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    :cond_b
    move-object v1, v4

    .line 231
    check-cast v1, Lay0/k;

    .line 232
    .line 233
    and-int/lit16 p3, p3, 0x380

    .line 234
    .line 235
    if-ne p3, v2, :cond_c

    .line 236
    .line 237
    goto :goto_8

    .line 238
    :cond_c
    move v5, v6

    .line 239
    :goto_8
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object p3

    .line 243
    if-nez v5, :cond_d

    .line 244
    .line 245
    if-ne p3, v7, :cond_e

    .line 246
    .line 247
    :cond_d
    new-instance p3, Lvo0/g;

    .line 248
    .line 249
    const/16 v2, 0x10

    .line 250
    .line 251
    invoke-direct {p3, p2, v2}, Lvo0/g;-><init>(Lay0/a;I)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {v3, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    :cond_e
    move-object v2, p3

    .line 258
    check-cast v2, Lay0/k;

    .line 259
    .line 260
    const/4 v4, 0x0

    .line 261
    const/4 v5, 0x0

    .line 262
    invoke-static/range {v0 .. v5}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 269
    .line 270
    .line 271
    move-result-object p3

    .line 272
    if-eqz p3, :cond_10

    .line 273
    .line 274
    new-instance v0, Ly60/b;

    .line 275
    .line 276
    const/4 v5, 0x0

    .line 277
    move-object v1, p0

    .line 278
    move-object v2, p1

    .line 279
    move-object v3, p2

    .line 280
    move v4, p4

    .line 281
    invoke-direct/range {v0 .. v5}, Ly60/b;-><init>(Lx60/d;Lay0/a;Lay0/a;II)V

    .line 282
    .line 283
    .line 284
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 285
    .line 286
    return-void

    .line 287
    :cond_f
    move-object v1, p0

    .line 288
    move-object v2, p1

    .line 289
    move-object v4, p2

    .line 290
    move v5, p4

    .line 291
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 292
    .line 293
    .line 294
    :goto_9
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 295
    .line 296
    .line 297
    move-result-object p0

    .line 298
    if-eqz p0, :cond_10

    .line 299
    .line 300
    move-object v3, v2

    .line 301
    move-object v2, v1

    .line 302
    new-instance v1, Ly60/b;

    .line 303
    .line 304
    const/4 v6, 0x1

    .line 305
    invoke-direct/range {v1 .. v6}, Ly60/b;-><init>(Lx60/d;Lay0/a;Lay0/a;II)V

    .line 306
    .line 307
    .line 308
    iput-object v1, p0, Ll2/u1;->d:Lay0/n;

    .line 309
    .line 310
    :cond_10
    return-void
.end method

.method public static final c(Lae0/a;Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x7a92d599

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    const/4 v3, 0x1

    .line 23
    const/4 v4, 0x0

    .line 24
    if-eq v2, v1, :cond_1

    .line 25
    .line 26
    move v1, v3

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v1, v4

    .line 29
    :goto_1
    and-int/2addr v0, v3

    .line 30
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_7

    .line 35
    .line 36
    sget-object v0, Llc0/c;->a:Llc0/c;

    .line 37
    .line 38
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_2

    .line 43
    .line 44
    const v0, -0x2133c97c

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 48
    .line 49
    .line 50
    invoke-static {p1, v4}, Lnc0/e;->d(Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 54
    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    sget-object v0, Lw60/a;->a:Lw60/a;

    .line 58
    .line 59
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_3

    .line 64
    .line 65
    const v0, -0x2133c1e0

    .line 66
    .line 67
    .line 68
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 69
    .line 70
    .line 71
    invoke-static {p1, v4}, Llp/bg;->a(Ll2/o;I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 75
    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_3
    sget-object v0, Lw60/a;->b:Lw60/a;

    .line 79
    .line 80
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-eqz v0, :cond_4

    .line 85
    .line 86
    const v0, -0x2133b9d9

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 90
    .line 91
    .line 92
    invoke-static {p1, v4}, Llp/dg;->a(Ll2/o;I)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_4
    const v0, -0x2133b37a

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    if-nez v0, :cond_5

    .line 114
    .line 115
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 116
    .line 117
    if-ne v1, v0, :cond_6

    .line 118
    .line 119
    :cond_5
    new-instance v1, Lc40/i;

    .line 120
    .line 121
    const/4 v0, 0x2

    .line 122
    invoke-direct {v1, p0, v0}, Lc40/i;-><init>(Lae0/a;I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_6
    check-cast v1, Lay0/a;

    .line 129
    .line 130
    const/4 v0, 0x0

    .line 131
    invoke-static {v0, p0, v1}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 132
    .line 133
    .line 134
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_7
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 139
    .line 140
    .line 141
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    if-eqz p1, :cond_8

    .line 146
    .line 147
    new-instance v0, Lc40/j;

    .line 148
    .line 149
    const/4 v1, 0x2

    .line 150
    invoke-direct {v0, p0, p2, v1}, Lc40/j;-><init>(Lae0/a;II)V

    .line 151
    .line 152
    .line 153
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 154
    .line 155
    :cond_8
    return-void
.end method

.method public static d(Ljava/util/List;Llp/jg;)Ljava/util/AbstractList;
    .locals 1

    .line 1
    instance-of v0, p0, Ljava/util/RandomAccess;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/p0;

    .line 6
    .line 7
    invoke-direct {v0, p0, p1}, Lhr/p0;-><init>(Ljava/util/List;Llp/jg;)V

    .line 8
    .line 9
    .line 10
    return-object v0

    .line 11
    :cond_0
    new-instance v0, Lhr/q0;

    .line 12
    .line 13
    invoke-direct {v0, p0, p1}, Lhr/q0;-><init>(Ljava/util/List;Llp/jg;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

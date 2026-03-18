.class public final synthetic Li50/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh50/c;


# direct methods
.method public synthetic constructor <init>(Lh50/c;I)V
    .locals 0

    .line 1
    iput p2, p0, Li50/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li50/a;->e:Lh50/c;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li50/a;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/compose/foundation/lazy/a;

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
    const-string v4, "$this$item"

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
    if-eqz v1, :cond_1

    .line 48
    .line 49
    iget-object v0, v0, Li50/a;->e:Lh50/c;

    .line 50
    .line 51
    invoke-static {v0, v2, v5}, Li50/c;->h(Lh50/c;Ll2/o;I)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_1
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 56
    .line 57
    .line 58
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_0
    move-object/from16 v1, p1

    .line 62
    .line 63
    check-cast v1, Lk1/z0;

    .line 64
    .line 65
    move-object/from16 v2, p2

    .line 66
    .line 67
    check-cast v2, Ll2/o;

    .line 68
    .line 69
    move-object/from16 v3, p3

    .line 70
    .line 71
    check-cast v3, Ljava/lang/Integer;

    .line 72
    .line 73
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    const-string v4, "paddingValues"

    .line 78
    .line 79
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    and-int/lit8 v4, v3, 0x6

    .line 83
    .line 84
    if-nez v4, :cond_3

    .line 85
    .line 86
    move-object v4, v2

    .line 87
    check-cast v4, Ll2/t;

    .line 88
    .line 89
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-eqz v4, :cond_2

    .line 94
    .line 95
    const/4 v4, 0x4

    .line 96
    goto :goto_2

    .line 97
    :cond_2
    const/4 v4, 0x2

    .line 98
    :goto_2
    or-int/2addr v3, v4

    .line 99
    :cond_3
    and-int/lit8 v4, v3, 0x13

    .line 100
    .line 101
    const/16 v5, 0x12

    .line 102
    .line 103
    const/4 v6, 0x0

    .line 104
    const/4 v7, 0x1

    .line 105
    if-eq v4, v5, :cond_4

    .line 106
    .line 107
    move v4, v7

    .line 108
    goto :goto_3

    .line 109
    :cond_4
    move v4, v6

    .line 110
    :goto_3
    and-int/2addr v3, v7

    .line 111
    check-cast v2, Ll2/t;

    .line 112
    .line 113
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    if-eqz v3, :cond_a

    .line 118
    .line 119
    sget-object v8, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 120
    .line 121
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 122
    .line 123
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    check-cast v3, Lj91/e;

    .line 128
    .line 129
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 130
    .line 131
    .line 132
    move-result-wide v3

    .line 133
    sget-object v5, Le3/j0;->a:Le3/i0;

    .line 134
    .line 135
    invoke-static {v8, v3, v4, v5}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 136
    .line 137
    .line 138
    move-result-object v9

    .line 139
    invoke-interface {v1}, Lk1/z0;->d()F

    .line 140
    .line 141
    .line 142
    move-result v11

    .line 143
    invoke-interface {v1}, Lk1/z0;->c()F

    .line 144
    .line 145
    .line 146
    move-result v13

    .line 147
    const/4 v14, 0x5

    .line 148
    const/4 v10, 0x0

    .line 149
    const/4 v12, 0x0

    .line 150
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 155
    .line 156
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 157
    .line 158
    invoke-static {v3, v4, v2, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    iget-wide v4, v2, Ll2/t;->T:J

    .line 163
    .line 164
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 165
    .line 166
    .line 167
    move-result v4

    .line 168
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    invoke-static {v2, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 177
    .line 178
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 179
    .line 180
    .line 181
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 182
    .line 183
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 184
    .line 185
    .line 186
    iget-boolean v9, v2, Ll2/t;->S:Z

    .line 187
    .line 188
    if-eqz v9, :cond_5

    .line 189
    .line 190
    invoke-virtual {v2, v6}, Ll2/t;->l(Lay0/a;)V

    .line 191
    .line 192
    .line 193
    goto :goto_4

    .line 194
    :cond_5
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 195
    .line 196
    .line 197
    :goto_4
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 198
    .line 199
    invoke-static {v6, v3, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 200
    .line 201
    .line 202
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 203
    .line 204
    invoke-static {v3, v5, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 205
    .line 206
    .line 207
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 208
    .line 209
    iget-boolean v5, v2, Ll2/t;->S:Z

    .line 210
    .line 211
    if-nez v5, :cond_6

    .line 212
    .line 213
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v5

    .line 217
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 218
    .line 219
    .line 220
    move-result-object v6

    .line 221
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v5

    .line 225
    if-nez v5, :cond_7

    .line 226
    .line 227
    :cond_6
    invoke-static {v4, v2, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 228
    .line 229
    .line 230
    :cond_7
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 231
    .line 232
    invoke-static {v3, v1, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 233
    .line 234
    .line 235
    iget-object v0, v0, Li50/a;->e:Lh50/c;

    .line 236
    .line 237
    invoke-virtual {v2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result v1

    .line 241
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    if-nez v1, :cond_8

    .line 246
    .line 247
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 248
    .line 249
    if-ne v3, v1, :cond_9

    .line 250
    .line 251
    :cond_8
    new-instance v3, Li40/e1;

    .line 252
    .line 253
    const/4 v1, 0x1

    .line 254
    invoke-direct {v3, v0, v1}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    :cond_9
    move-object/from16 v16, v3

    .line 261
    .line 262
    check-cast v16, Lay0/k;

    .line 263
    .line 264
    const/16 v18, 0x6

    .line 265
    .line 266
    const/16 v19, 0x1fe

    .line 267
    .line 268
    const/4 v9, 0x0

    .line 269
    const/4 v10, 0x0

    .line 270
    const/4 v11, 0x0

    .line 271
    const/4 v12, 0x0

    .line 272
    const/4 v13, 0x0

    .line 273
    const/4 v14, 0x0

    .line 274
    const/4 v15, 0x0

    .line 275
    move-object/from16 v17, v2

    .line 276
    .line 277
    invoke-static/range {v8 .. v19}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 281
    .line 282
    .line 283
    goto :goto_5

    .line 284
    :cond_a
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 285
    .line 286
    .line 287
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 288
    .line 289
    return-object v0

    .line 290
    nop

    .line 291
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

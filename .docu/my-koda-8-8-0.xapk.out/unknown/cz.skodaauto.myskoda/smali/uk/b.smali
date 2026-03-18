.class public final synthetic Luk/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lsg/f;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lsg/f;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Luk/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Luk/b;->e:Lsg/f;

    iput-object p2, p0, Luk/b;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lsg/f;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p3, 0x1

    iput p3, p0, Luk/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Luk/b;->e:Lsg/f;

    iput-object p2, p0, Luk/b;->f:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Luk/b;->d:I

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
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/16 v2, 0x9

    .line 20
    .line 21
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    iget-object v3, v0, Luk/b;->e:Lsg/f;

    .line 26
    .line 27
    iget-object v0, v0, Luk/b;->f:Lay0/k;

    .line 28
    .line 29
    invoke-static {v3, v0, v1, v2}, Luk/a;->b(Lsg/f;Lay0/k;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object v0

    .line 35
    :pswitch_0
    move-object/from16 v1, p1

    .line 36
    .line 37
    check-cast v1, Ll2/o;

    .line 38
    .line 39
    move-object/from16 v2, p2

    .line 40
    .line 41
    check-cast v2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    and-int/lit8 v3, v2, 0x3

    .line 48
    .line 49
    const/4 v4, 0x2

    .line 50
    const/4 v5, 0x1

    .line 51
    const/4 v6, 0x0

    .line 52
    if-eq v3, v4, :cond_0

    .line 53
    .line 54
    move v3, v5

    .line 55
    goto :goto_0

    .line 56
    :cond_0
    move v3, v6

    .line 57
    :goto_0
    and-int/2addr v2, v5

    .line 58
    move-object v11, v1

    .line 59
    check-cast v11, Ll2/t;

    .line 60
    .line 61
    invoke-virtual {v11, v2, v3}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_6

    .line 66
    .line 67
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 68
    .line 69
    sget-object v2, Lx2/c;->p:Lx2/h;

    .line 70
    .line 71
    invoke-static {v1, v2, v11, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    iget-wide v2, v11, Ll2/t;->T:J

    .line 76
    .line 77
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    sget-object v12, Lx2/p;->b:Lx2/p;

    .line 86
    .line 87
    invoke-static {v11, v12}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 92
    .line 93
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 97
    .line 98
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 99
    .line 100
    .line 101
    iget-boolean v8, v11, Ll2/t;->S:Z

    .line 102
    .line 103
    if-eqz v8, :cond_1

    .line 104
    .line 105
    invoke-virtual {v11, v7}, Ll2/t;->l(Lay0/a;)V

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_1
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 110
    .line 111
    .line 112
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 113
    .line 114
    invoke-static {v7, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 115
    .line 116
    .line 117
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 118
    .line 119
    invoke-static {v1, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 123
    .line 124
    iget-boolean v3, v11, Ll2/t;->S:Z

    .line 125
    .line 126
    if-nez v3, :cond_2

    .line 127
    .line 128
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 133
    .line 134
    .line 135
    move-result-object v7

    .line 136
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    if-nez v3, :cond_3

    .line 141
    .line 142
    :cond_2
    invoke-static {v2, v11, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 143
    .line 144
    .line 145
    :cond_3
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 146
    .line 147
    invoke-static {v1, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 148
    .line 149
    .line 150
    const/16 v1, 0x10

    .line 151
    .line 152
    invoke-static {v11, v1}, Luk/a;->i(Ll2/o;I)F

    .line 153
    .line 154
    .line 155
    move-result v14

    .line 156
    int-to-float v13, v1

    .line 157
    const/16 v16, 0x0

    .line 158
    .line 159
    const/16 v17, 0x8

    .line 160
    .line 161
    move v15, v13

    .line 162
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v7

    .line 166
    move-object v10, v11

    .line 167
    const/4 v11, 0x0

    .line 168
    const/4 v12, 0x6

    .line 169
    const/4 v8, 0x0

    .line 170
    const/4 v9, 0x0

    .line 171
    invoke-static/range {v7 .. v12}, Ldk/c;->b(Lx2/s;Lg4/p0;Ljava/lang/String;Ll2/o;II)V

    .line 172
    .line 173
    .line 174
    iget-object v1, v0, Luk/b;->e:Lsg/f;

    .line 175
    .line 176
    iget-object v2, v1, Lsg/f;->c:Lsg/c;

    .line 177
    .line 178
    iget-object v7, v2, Lsg/c;->b:Ljava/lang/String;

    .line 179
    .line 180
    iget-object v8, v2, Lsg/c;->a:Ljava/lang/String;

    .line 181
    .line 182
    const/16 v2, 0x8

    .line 183
    .line 184
    int-to-float v9, v2

    .line 185
    const/16 v12, 0x180

    .line 186
    .line 187
    const/16 v13, 0x8

    .line 188
    .line 189
    move-object v11, v10

    .line 190
    const/4 v10, 0x0

    .line 191
    invoke-static/range {v7 .. v13}, Lkp/c8;->a(Ljava/lang/String;Ljava/lang/String;FLjava/lang/String;Ll2/o;II)V

    .line 192
    .line 193
    .line 194
    move-object v10, v11

    .line 195
    iget-object v7, v1, Lsg/f;->a:Ljava/lang/String;

    .line 196
    .line 197
    int-to-float v8, v6

    .line 198
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 199
    .line 200
    invoke-virtual {v10, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    check-cast v2, Lj91/f;

    .line 205
    .line 206
    invoke-virtual {v2}, Lj91/f;->k()Lg4/p0;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    const/16 v12, 0x30

    .line 211
    .line 212
    const/4 v13, 0x4

    .line 213
    const/4 v9, 0x0

    .line 214
    move-object v10, v2

    .line 215
    invoke-static/range {v7 .. v13}, Lkp/c8;->c(Ljava/lang/String;FLjava/lang/String;Lg4/p0;Ll2/o;II)V

    .line 216
    .line 217
    .line 218
    move-object v10, v11

    .line 219
    iget-object v2, v1, Lsg/f;->d:Ljava/util/ArrayList;

    .line 220
    .line 221
    invoke-static {v2, v10, v6}, Luk/a;->g(Ljava/util/ArrayList;Ll2/o;I)V

    .line 222
    .line 223
    .line 224
    iget-object v2, v1, Lsg/f;->e:Ljava/lang/String;

    .line 225
    .line 226
    invoke-static {v2, v10, v6}, Luk/a;->f(Ljava/lang/String;Ll2/o;I)V

    .line 227
    .line 228
    .line 229
    iget-object v0, v0, Luk/b;->f:Lay0/k;

    .line 230
    .line 231
    invoke-virtual {v10, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 232
    .line 233
    .line 234
    move-result v2

    .line 235
    invoke-virtual {v10, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    move-result v3

    .line 239
    or-int/2addr v2, v3

    .line 240
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v3

    .line 244
    if-nez v2, :cond_4

    .line 245
    .line 246
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 247
    .line 248
    if-ne v3, v2, :cond_5

    .line 249
    .line 250
    :cond_4
    new-instance v3, Lt61/g;

    .line 251
    .line 252
    const/16 v2, 0x14

    .line 253
    .line 254
    invoke-direct {v3, v2, v0, v1}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v10, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    :cond_5
    check-cast v3, Lay0/a;

    .line 261
    .line 262
    invoke-static {v3, v10, v6}, Luk/a;->e(Lay0/a;Ll2/o;I)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v10, v5}, Ll2/t;->q(Z)V

    .line 266
    .line 267
    .line 268
    goto :goto_2

    .line 269
    :cond_6
    move-object v10, v11

    .line 270
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 271
    .line 272
    .line 273
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 274
    .line 275
    return-object v0

    .line 276
    nop

    .line 277
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

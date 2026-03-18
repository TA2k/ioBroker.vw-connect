.class public final synthetic Lxf0/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(JZLjava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p3, p0, Lxf0/s0;->d:Z

    .line 5
    .line 6
    iput-wide p1, p0, Lxf0/s0;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lxf0/s0;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p5, p0, Lxf0/s0;->g:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/h1;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const-string v4, "$this$FeatureSwitchCard"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v4, v3, 0x6

    .line 25
    .line 26
    if-nez v4, :cond_1

    .line 27
    .line 28
    move-object v4, v2

    .line 29
    check-cast v4, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_0

    .line 36
    .line 37
    const/4 v4, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v4, 0x2

    .line 40
    :goto_0
    or-int/2addr v3, v4

    .line 41
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 42
    .line 43
    const/16 v5, 0x12

    .line 44
    .line 45
    const/4 v6, 0x1

    .line 46
    const/4 v7, 0x0

    .line 47
    if-eq v4, v5, :cond_2

    .line 48
    .line 49
    move v4, v6

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    move v4, v7

    .line 52
    :goto_1
    and-int/2addr v3, v6

    .line 53
    check-cast v2, Ll2/t;

    .line 54
    .line 55
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_7

    .line 60
    .line 61
    const/high16 v3, 0x3f800000    # 1.0f

    .line 62
    .line 63
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 64
    .line 65
    invoke-interface {v1, v4, v3}, Lk1/h1;->a(Lx2/s;F)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 70
    .line 71
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 72
    .line 73
    invoke-static {v3, v5, v2, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    iget-wide v8, v2, Ll2/t;->T:J

    .line 78
    .line 79
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 84
    .line 85
    .line 86
    move-result-object v8

    .line 87
    invoke-static {v2, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 92
    .line 93
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 97
    .line 98
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 99
    .line 100
    .line 101
    iget-boolean v10, v2, Ll2/t;->S:Z

    .line 102
    .line 103
    if-eqz v10, :cond_3

    .line 104
    .line 105
    invoke-virtual {v2, v9}, Ll2/t;->l(Lay0/a;)V

    .line 106
    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_3
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 110
    .line 111
    .line 112
    :goto_2
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 113
    .line 114
    invoke-static {v9, v3, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 115
    .line 116
    .line 117
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 118
    .line 119
    invoke-static {v3, v8, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 123
    .line 124
    iget-boolean v8, v2, Ll2/t;->S:Z

    .line 125
    .line 126
    if-nez v8, :cond_4

    .line 127
    .line 128
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v8

    .line 132
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 133
    .line 134
    .line 135
    move-result-object v9

    .line 136
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v8

    .line 140
    if-nez v8, :cond_5

    .line 141
    .line 142
    :cond_4
    invoke-static {v5, v2, v5, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 143
    .line 144
    .line 145
    :cond_5
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 146
    .line 147
    invoke-static {v3, v1, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 148
    .line 149
    .line 150
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 151
    .line 152
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    check-cast v1, Lj91/f;

    .line 157
    .line 158
    invoke-virtual {v1}, Lj91/f;->k()Lg4/p0;

    .line 159
    .line 160
    .line 161
    move-result-object v9

    .line 162
    iget-boolean v1, v0, Lxf0/s0;->d:Z

    .line 163
    .line 164
    if-eqz v1, :cond_6

    .line 165
    .line 166
    const v1, -0x66987d38

    .line 167
    .line 168
    .line 169
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 170
    .line 171
    .line 172
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 173
    .line 174
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v1

    .line 178
    check-cast v1, Lj91/e;

    .line 179
    .line 180
    invoke-virtual {v1}, Lj91/e;->r()J

    .line 181
    .line 182
    .line 183
    move-result-wide v10

    .line 184
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    :goto_3
    move-wide v11, v10

    .line 188
    goto :goto_4

    .line 189
    :cond_6
    const v1, -0x66987ab9

    .line 190
    .line 191
    .line 192
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 196
    .line 197
    .line 198
    iget-wide v10, v0, Lxf0/s0;->e:J

    .line 199
    .line 200
    goto :goto_3

    .line 201
    :goto_4
    new-instance v1, Ljava/lang/StringBuilder;

    .line 202
    .line 203
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 204
    .line 205
    .line 206
    iget-object v3, v0, Lxf0/s0;->f:Ljava/lang/String;

    .line 207
    .line 208
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    const-string v3, "card_description"

    .line 212
    .line 213
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    invoke-static {v4, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v10

    .line 224
    const/16 v28, 0x6180

    .line 225
    .line 226
    const v29, 0xaff0

    .line 227
    .line 228
    .line 229
    iget-object v8, v0, Lxf0/s0;->g:Ljava/lang/String;

    .line 230
    .line 231
    const-wide/16 v13, 0x0

    .line 232
    .line 233
    const/4 v15, 0x0

    .line 234
    const-wide/16 v16, 0x0

    .line 235
    .line 236
    const/16 v18, 0x0

    .line 237
    .line 238
    const/16 v19, 0x0

    .line 239
    .line 240
    const-wide/16 v20, 0x0

    .line 241
    .line 242
    const/16 v22, 0x2

    .line 243
    .line 244
    const/16 v23, 0x0

    .line 245
    .line 246
    const/16 v24, 0x2

    .line 247
    .line 248
    const/16 v25, 0x0

    .line 249
    .line 250
    const/16 v27, 0x0

    .line 251
    .line 252
    move-object/from16 v26, v2

    .line 253
    .line 254
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v2, v6}, Ll2/t;->q(Z)V

    .line 258
    .line 259
    .line 260
    goto :goto_5

    .line 261
    :cond_7
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 262
    .line 263
    .line 264
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 265
    .line 266
    return-object v0
.end method

.class public final Lh2/i3;
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


# direct methods
.method public constructor <init>(Ljava/lang/String;Lh2/z1;ZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/i3;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/i3;->e:Lh2/z1;

    .line 7
    .line 8
    iput-boolean p3, p0, Lh2/i3;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lh2/i3;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lh2/i3;->h:Z

    .line 13
    .line 14
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
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x1

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v6

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v5

    .line 25
    :goto_0
    and-int/2addr v2, v6

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
    if-eqz v1, :cond_9

    .line 34
    .line 35
    const/high16 v1, 0x3f800000    # 1.0f

    .line 36
    .line 37
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 38
    .line 39
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    sget-object v3, Lx2/c;->h:Lx2/j;

    .line 44
    .line 45
    invoke-static {v3, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    iget-wide v4, v11, Ll2/t;->T:J

    .line 50
    .line 51
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    invoke-static {v11, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 64
    .line 65
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 69
    .line 70
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 71
    .line 72
    .line 73
    iget-boolean v8, v11, Ll2/t;->S:Z

    .line 74
    .line 75
    if-eqz v8, :cond_1

    .line 76
    .line 77
    invoke-virtual {v11, v7}, Ll2/t;->l(Lay0/a;)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 82
    .line 83
    .line 84
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 85
    .line 86
    invoke-static {v7, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 87
    .line 88
    .line 89
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 90
    .line 91
    invoke-static {v3, v5, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 92
    .line 93
    .line 94
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 95
    .line 96
    iget-boolean v5, v11, Ll2/t;->S:Z

    .line 97
    .line 98
    if-nez v5, :cond_2

    .line 99
    .line 100
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v5

    .line 104
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v5

    .line 112
    if-nez v5, :cond_3

    .line 113
    .line 114
    :cond_2
    invoke-static {v4, v11, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 115
    .line 116
    .line 117
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 118
    .line 119
    invoke-static {v3, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 127
    .line 128
    if-ne v1, v3, :cond_4

    .line 129
    .line 130
    new-instance v1, Lh10/d;

    .line 131
    .line 132
    const/4 v3, 0x5

    .line 133
    invoke-direct {v1, v3}, Lh10/d;-><init>(I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v11, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    :cond_4
    check-cast v1, Lay0/k;

    .line 140
    .line 141
    invoke-static {v2, v1}, Ld4/n;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    iget-object v2, v0, Lh2/i3;->e:Lh2/z1;

    .line 146
    .line 147
    iget-boolean v3, v0, Lh2/i3;->g:Z

    .line 148
    .line 149
    iget-boolean v4, v0, Lh2/i3;->h:Z

    .line 150
    .line 151
    if-eqz v3, :cond_5

    .line 152
    .line 153
    if-eqz v4, :cond_5

    .line 154
    .line 155
    iget-wide v2, v2, Lh2/z1;->j:J

    .line 156
    .line 157
    :goto_2
    move-wide v7, v2

    .line 158
    goto :goto_3

    .line 159
    :cond_5
    if-eqz v3, :cond_6

    .line 160
    .line 161
    if-nez v4, :cond_6

    .line 162
    .line 163
    iget-wide v2, v2, Lh2/z1;->k:J

    .line 164
    .line 165
    goto :goto_2

    .line 166
    :cond_6
    iget-boolean v3, v0, Lh2/i3;->f:Z

    .line 167
    .line 168
    if-eqz v3, :cond_7

    .line 169
    .line 170
    if-eqz v4, :cond_7

    .line 171
    .line 172
    iget-wide v2, v2, Lh2/z1;->i:J

    .line 173
    .line 174
    goto :goto_2

    .line 175
    :cond_7
    if-eqz v4, :cond_8

    .line 176
    .line 177
    iget-wide v2, v2, Lh2/z1;->g:J

    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_8
    iget-wide v2, v2, Lh2/z1;->h:J

    .line 181
    .line 182
    goto :goto_2

    .line 183
    :goto_3
    sget-object v2, Lk2/w;->f:Lk2/w;

    .line 184
    .line 185
    invoke-static {v2, v11}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 186
    .line 187
    .line 188
    move-result-object v9

    .line 189
    const/4 v12, 0x0

    .line 190
    const/16 v13, 0xc

    .line 191
    .line 192
    const/4 v10, 0x0

    .line 193
    invoke-static/range {v7 .. v13}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    move-object/from16 v26, v11

    .line 198
    .line 199
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    check-cast v2, Le3/s;

    .line 204
    .line 205
    iget-wide v9, v2, Le3/s;->a:J

    .line 206
    .line 207
    new-instance v2, Lr4/k;

    .line 208
    .line 209
    const/4 v3, 0x3

    .line 210
    invoke-direct {v2, v3}, Lr4/k;-><init>(I)V

    .line 211
    .line 212
    .line 213
    const/16 v28, 0x0

    .line 214
    .line 215
    const v29, 0x3fbf8

    .line 216
    .line 217
    .line 218
    iget-object v7, v0, Lh2/i3;->d:Ljava/lang/String;

    .line 219
    .line 220
    const-wide/16 v11, 0x0

    .line 221
    .line 222
    const/4 v13, 0x0

    .line 223
    const-wide/16 v14, 0x0

    .line 224
    .line 225
    const/16 v16, 0x0

    .line 226
    .line 227
    const-wide/16 v18, 0x0

    .line 228
    .line 229
    const/16 v20, 0x0

    .line 230
    .line 231
    const/16 v21, 0x0

    .line 232
    .line 233
    const/16 v22, 0x0

    .line 234
    .line 235
    const/16 v23, 0x0

    .line 236
    .line 237
    const/16 v24, 0x0

    .line 238
    .line 239
    const/16 v25, 0x0

    .line 240
    .line 241
    const/16 v27, 0x0

    .line 242
    .line 243
    move-object v8, v1

    .line 244
    move-object/from16 v17, v2

    .line 245
    .line 246
    invoke-static/range {v7 .. v29}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 247
    .line 248
    .line 249
    move-object/from16 v11, v26

    .line 250
    .line 251
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 252
    .line 253
    .line 254
    goto :goto_4

    .line 255
    :cond_9
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 256
    .line 257
    .line 258
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 259
    .line 260
    return-object v0
.end method

.class public final Lg4/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lk4/m;

.field public final b:Lt4/c;

.field public final c:Lt4/m;

.field public final d:Lgw0/c;


# direct methods
.method public constructor <init>(Lk4/m;Lt4/c;Lt4/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg4/n0;->a:Lk4/m;

    .line 5
    .line 6
    iput-object p2, p0, Lg4/n0;->b:Lt4/c;

    .line 7
    .line 8
    iput-object p3, p0, Lg4/n0;->c:Lt4/m;

    .line 9
    .line 10
    new-instance p1, Lgw0/c;

    .line 11
    .line 12
    const/16 p2, 0x12

    .line 13
    .line 14
    invoke-direct {p1, p2}, Lgw0/c;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lg4/n0;->d:Lgw0/c;

    .line 18
    .line 19
    return-void
.end method

.method public static a(Lg4/n0;Lg4/g;Lg4/p0;)Lg4/l0;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {v2, v2, v1}, Lt4/b;->b(III)J

    .line 7
    .line 8
    .line 9
    move-result-wide v13

    .line 10
    iget-object v11, v0, Lg4/n0;->c:Lt4/m;

    .line 11
    .line 12
    iget-object v7, v0, Lg4/n0;->b:Lt4/c;

    .line 13
    .line 14
    iget-object v8, v0, Lg4/n0;->a:Lk4/m;

    .line 15
    .line 16
    iget-object v0, v0, Lg4/n0;->d:Lgw0/c;

    .line 17
    .line 18
    new-instance v3, Lg4/k0;

    .line 19
    .line 20
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 21
    .line 22
    move-object v10, v7

    .line 23
    const v7, 0x7fffffff

    .line 24
    .line 25
    .line 26
    move-object v12, v8

    .line 27
    const/4 v8, 0x1

    .line 28
    const/16 v20, 0x1

    .line 29
    .line 30
    move-object/from16 v4, p1

    .line 31
    .line 32
    move-object/from16 v5, p2

    .line 33
    .line 34
    move/from16 v9, v20

    .line 35
    .line 36
    invoke-direct/range {v3 .. v14}, Lg4/k0;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;IZILt4/c;Lt4/m;Lk4/m;J)V

    .line 37
    .line 38
    .line 39
    move-object v1, v3

    .line 40
    const/4 v3, 0x0

    .line 41
    if-eqz v0, :cond_3

    .line 42
    .line 43
    new-instance v4, Lg4/j;

    .line 44
    .line 45
    invoke-direct {v4, v1}, Lg4/j;-><init>(Lg4/k0;)V

    .line 46
    .line 47
    .line 48
    iget-object v5, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v5, Landroidx/collection/w;

    .line 51
    .line 52
    if-eqz v5, :cond_0

    .line 53
    .line 54
    invoke-virtual {v5, v4}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    check-cast v4, Lg4/l0;

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    iget-object v5, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v5, Lg4/j;

    .line 64
    .line 65
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    if-eqz v4, :cond_3

    .line 70
    .line 71
    iget-object v4, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v4, Lg4/l0;

    .line 74
    .line 75
    :goto_0
    if-nez v4, :cond_1

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    iget-object v5, v4, Lg4/l0;->b:Lg4/o;

    .line 79
    .line 80
    iget-object v5, v5, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 81
    .line 82
    invoke-virtual {v5}, Landroidx/lifecycle/c1;->a()Z

    .line 83
    .line 84
    .line 85
    move-result v5

    .line 86
    if-eqz v5, :cond_2

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_2
    move-object v3, v4

    .line 90
    :cond_3
    :goto_1
    const/16 v9, 0x20

    .line 91
    .line 92
    const-wide v21, 0xffffffffL

    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    if-eqz v3, :cond_4

    .line 98
    .line 99
    iget-object v0, v3, Lg4/l0;->b:Lg4/o;

    .line 100
    .line 101
    iget v2, v0, Lg4/o;->d:F

    .line 102
    .line 103
    float-to-double v2, v2

    .line 104
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 105
    .line 106
    .line 107
    move-result-wide v2

    .line 108
    double-to-float v2, v2

    .line 109
    float-to-int v2, v2

    .line 110
    iget v3, v0, Lg4/o;->e:F

    .line 111
    .line 112
    float-to-double v3, v3

    .line 113
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 114
    .line 115
    .line 116
    move-result-wide v3

    .line 117
    double-to-float v3, v3

    .line 118
    float-to-int v3, v3

    .line 119
    int-to-long v4, v2

    .line 120
    shl-long/2addr v4, v9

    .line 121
    int-to-long v2, v3

    .line 122
    and-long v2, v2, v21

    .line 123
    .line 124
    or-long/2addr v2, v4

    .line 125
    invoke-static {v13, v14, v2, v3}, Lt4/b;->d(JJ)J

    .line 126
    .line 127
    .line 128
    move-result-wide v2

    .line 129
    new-instance v4, Lg4/l0;

    .line 130
    .line 131
    invoke-direct {v4, v1, v0, v2, v3}, Lg4/l0;-><init>(Lg4/k0;Lg4/o;J)V

    .line 132
    .line 133
    .line 134
    return-object v4

    .line 135
    :cond_4
    move-object/from16 v5, p2

    .line 136
    .line 137
    invoke-static {v5, v11}, Lg4/f0;->h(Lg4/p0;Lt4/m;)Lg4/p0;

    .line 138
    .line 139
    .line 140
    move-result-object v5

    .line 141
    new-instance v16, Landroidx/lifecycle/c1;

    .line 142
    .line 143
    move-object/from16 v4, p1

    .line 144
    .line 145
    move-object v7, v10

    .line 146
    move-object v8, v12

    .line 147
    move-object/from16 v3, v16

    .line 148
    .line 149
    invoke-direct/range {v3 .. v8}, Landroidx/lifecycle/c1;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;Lt4/c;Lk4/m;)V

    .line 150
    .line 151
    .line 152
    invoke-static {v13, v14}, Lt4/a;->j(J)I

    .line 153
    .line 154
    .line 155
    move-result v3

    .line 156
    invoke-static {v13, v14}, Lt4/a;->d(J)Z

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    if-eqz v4, :cond_5

    .line 161
    .line 162
    invoke-static {v13, v14}, Lt4/a;->h(J)I

    .line 163
    .line 164
    .line 165
    move-result v4

    .line 166
    goto :goto_2

    .line 167
    :cond_5
    const v4, 0x7fffffff

    .line 168
    .line 169
    .line 170
    :goto_2
    if-ne v3, v4, :cond_6

    .line 171
    .line 172
    goto :goto_3

    .line 173
    :cond_6
    invoke-virtual/range {v16 .. v16}, Landroidx/lifecycle/c1;->b()F

    .line 174
    .line 175
    .line 176
    move-result v5

    .line 177
    float-to-double v5, v5

    .line 178
    invoke-static {v5, v6}, Ljava/lang/Math;->ceil(D)D

    .line 179
    .line 180
    .line 181
    move-result-wide v5

    .line 182
    double-to-float v5, v5

    .line 183
    float-to-int v5, v5

    .line 184
    invoke-static {v5, v3, v4}, Lkp/r9;->e(III)I

    .line 185
    .line 186
    .line 187
    move-result v4

    .line 188
    :goto_3
    new-instance v15, Lg4/o;

    .line 189
    .line 190
    invoke-static {v13, v14}, Lt4/a;->g(J)I

    .line 191
    .line 192
    .line 193
    move-result v3

    .line 194
    invoke-static {v2, v4, v2, v3}, Lkp/a9;->b(IIII)J

    .line 195
    .line 196
    .line 197
    move-result-wide v17

    .line 198
    const v19, 0x7fffffff

    .line 199
    .line 200
    .line 201
    invoke-direct/range {v15 .. v20}, Lg4/o;-><init>(Landroidx/lifecycle/c1;JII)V

    .line 202
    .line 203
    .line 204
    new-instance v2, Lg4/l0;

    .line 205
    .line 206
    iget v3, v15, Lg4/o;->d:F

    .line 207
    .line 208
    float-to-double v3, v3

    .line 209
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 210
    .line 211
    .line 212
    move-result-wide v3

    .line 213
    double-to-float v3, v3

    .line 214
    float-to-int v3, v3

    .line 215
    iget v4, v15, Lg4/o;->e:F

    .line 216
    .line 217
    float-to-double v4, v4

    .line 218
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 219
    .line 220
    .line 221
    move-result-wide v4

    .line 222
    double-to-float v4, v4

    .line 223
    float-to-int v4, v4

    .line 224
    int-to-long v5, v3

    .line 225
    shl-long/2addr v5, v9

    .line 226
    int-to-long v3, v4

    .line 227
    and-long v3, v3, v21

    .line 228
    .line 229
    or-long/2addr v3, v5

    .line 230
    invoke-static {v13, v14, v3, v4}, Lt4/b;->d(JJ)J

    .line 231
    .line 232
    .line 233
    move-result-wide v3

    .line 234
    invoke-direct {v2, v1, v15, v3, v4}, Lg4/l0;-><init>(Lg4/k0;Lg4/o;J)V

    .line 235
    .line 236
    .line 237
    if-eqz v0, :cond_8

    .line 238
    .line 239
    iget-object v3, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast v3, Landroidx/collection/w;

    .line 242
    .line 243
    if-eqz v3, :cond_7

    .line 244
    .line 245
    new-instance v0, Lg4/j;

    .line 246
    .line 247
    invoke-direct {v0, v1}, Lg4/j;-><init>(Lg4/k0;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v3, v0, v2}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    return-object v2

    .line 254
    :cond_7
    new-instance v3, Lg4/j;

    .line 255
    .line 256
    invoke-direct {v3, v1}, Lg4/j;-><init>(Lg4/k0;)V

    .line 257
    .line 258
    .line 259
    iput-object v3, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 260
    .line 261
    iput-object v2, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 262
    .line 263
    :cond_8
    return-object v2
.end method

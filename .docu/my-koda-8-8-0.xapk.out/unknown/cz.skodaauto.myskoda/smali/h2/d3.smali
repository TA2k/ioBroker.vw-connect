.class public final Lh2/d3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lm1/t;

.field public final synthetic e:Lgy0/j;

.field public final synthetic f:Li2/z;

.field public final synthetic g:Li2/c0;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Li2/y;

.field public final synthetic j:Ljava/lang/Long;

.field public final synthetic k:Lh2/g2;

.field public final synthetic l:Lh2/e8;

.field public final synthetic m:Lh2/z1;


# direct methods
.method public constructor <init>(Lm1/t;Lgy0/j;Li2/z;Li2/c0;Lay0/k;Li2/y;Ljava/lang/Long;Lh2/g2;Lh2/e8;Lh2/z1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/d3;->d:Lm1/t;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/d3;->e:Lgy0/j;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/d3;->f:Li2/z;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/d3;->g:Li2/c0;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/d3;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/d3;->i:Li2/y;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/d3;->j:Ljava/lang/Long;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/d3;->k:Lh2/g2;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/d3;->l:Lh2/e8;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/d3;->m:Lh2/z1;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

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
    move-object v15, v1

    .line 27
    check-cast v15, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v15, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_6

    .line 34
    .line 35
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 40
    .line 41
    if-ne v1, v2, :cond_1

    .line 42
    .line 43
    new-instance v1, Lh10/d;

    .line 44
    .line 45
    const/16 v3, 0x9

    .line 46
    .line 47
    invoke-direct {v1, v3}, Lh10/d;-><init>(I)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v15, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_1
    check-cast v1, Lay0/k;

    .line 54
    .line 55
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 56
    .line 57
    invoke-static {v3, v5, v1}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    sget-object v1, Lh2/c2;->a:Lh2/c2;

    .line 62
    .line 63
    const/4 v1, 0x3

    .line 64
    invoke-static {v1}, Lc1/d;->o(I)Lc1/u;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    sget-object v3, Lk2/w;->f:Lk2/w;

    .line 69
    .line 70
    invoke-static {v3, v15}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-virtual {v15, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    iget-object v7, v0, Lh2/d3;->d:Lm1/t;

    .line 79
    .line 80
    invoke-virtual {v15, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    or-int/2addr v4, v5

    .line 85
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    if-nez v4, :cond_2

    .line 90
    .line 91
    if-ne v5, v2, :cond_3

    .line 92
    .line 93
    :cond_2
    sget-object v4, Lh1/m;->b:Lh1/m;

    .line 94
    .line 95
    new-instance v5, Lb81/d;

    .line 96
    .line 97
    const/4 v8, 0x6

    .line 98
    invoke-direct {v5, v8, v7, v4}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    new-instance v4, Laq/a;

    .line 102
    .line 103
    const/16 v8, 0x1d

    .line 104
    .line 105
    invoke-direct {v4, v5, v8}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 106
    .line 107
    .line 108
    sget v5, Lh1/k;->a:F

    .line 109
    .line 110
    new-instance v5, Lh1/g;

    .line 111
    .line 112
    invoke-direct {v5, v4, v1, v3}, Lh1/g;-><init>(Lh1/l;Lc1/u;Lc1/j;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v15, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_3
    move-object v11, v5

    .line 119
    check-cast v11, Lh1/g;

    .line 120
    .line 121
    iget-object v1, v0, Lh2/d3;->e:Lgy0/j;

    .line 122
    .line 123
    invoke-virtual {v15, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    iget-object v3, v0, Lh2/d3;->f:Li2/z;

    .line 128
    .line 129
    invoke-virtual {v15, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    or-int/2addr v1, v3

    .line 134
    iget-object v3, v0, Lh2/d3;->g:Li2/c0;

    .line 135
    .line 136
    invoke-virtual {v15, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    or-int/2addr v1, v3

    .line 141
    iget-object v3, v0, Lh2/d3;->h:Lay0/k;

    .line 142
    .line 143
    invoke-virtual {v15, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v3

    .line 147
    or-int/2addr v1, v3

    .line 148
    iget-object v3, v0, Lh2/d3;->i:Li2/y;

    .line 149
    .line 150
    invoke-virtual {v15, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v4

    .line 154
    or-int/2addr v1, v4

    .line 155
    iget-object v4, v0, Lh2/d3;->j:Ljava/lang/Long;

    .line 156
    .line 157
    invoke-virtual {v15, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v4

    .line 161
    or-int/2addr v1, v4

    .line 162
    iget-object v4, v0, Lh2/d3;->k:Lh2/g2;

    .line 163
    .line 164
    invoke-virtual {v15, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result v4

    .line 168
    or-int/2addr v1, v4

    .line 169
    iget-object v4, v0, Lh2/d3;->l:Lh2/e8;

    .line 170
    .line 171
    invoke-virtual {v15, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v4

    .line 175
    or-int/2addr v1, v4

    .line 176
    iget-object v4, v0, Lh2/d3;->m:Lh2/z1;

    .line 177
    .line 178
    invoke-virtual {v15, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v5

    .line 182
    or-int/2addr v1, v5

    .line 183
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v5

    .line 187
    if-nez v1, :cond_4

    .line 188
    .line 189
    if-ne v5, v2, :cond_5

    .line 190
    .line 191
    :cond_4
    new-instance v16, Lh2/b3;

    .line 192
    .line 193
    const/16 v26, 0x0

    .line 194
    .line 195
    iget-object v1, v0, Lh2/d3;->e:Lgy0/j;

    .line 196
    .line 197
    iget-object v2, v0, Lh2/d3;->f:Li2/z;

    .line 198
    .line 199
    iget-object v5, v0, Lh2/d3;->g:Li2/c0;

    .line 200
    .line 201
    iget-object v8, v0, Lh2/d3;->h:Lay0/k;

    .line 202
    .line 203
    iget-object v9, v0, Lh2/d3;->j:Ljava/lang/Long;

    .line 204
    .line 205
    iget-object v10, v0, Lh2/d3;->k:Lh2/g2;

    .line 206
    .line 207
    iget-object v0, v0, Lh2/d3;->l:Lh2/e8;

    .line 208
    .line 209
    move-object/from16 v24, v0

    .line 210
    .line 211
    move-object/from16 v17, v1

    .line 212
    .line 213
    move-object/from16 v18, v2

    .line 214
    .line 215
    move-object/from16 v21, v3

    .line 216
    .line 217
    move-object/from16 v25, v4

    .line 218
    .line 219
    move-object/from16 v19, v5

    .line 220
    .line 221
    move-object/from16 v20, v8

    .line 222
    .line 223
    move-object/from16 v22, v9

    .line 224
    .line 225
    move-object/from16 v23, v10

    .line 226
    .line 227
    invoke-direct/range {v16 .. v26}, Lh2/b3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 228
    .line 229
    .line 230
    move-object/from16 v5, v16

    .line 231
    .line 232
    invoke-virtual {v15, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    :cond_5
    move-object v14, v5

    .line 236
    check-cast v14, Lay0/k;

    .line 237
    .line 238
    const/16 v16, 0x0

    .line 239
    .line 240
    const/16 v17, 0x1bc

    .line 241
    .line 242
    const/4 v8, 0x0

    .line 243
    const/4 v9, 0x0

    .line 244
    const/4 v10, 0x0

    .line 245
    const/4 v12, 0x0

    .line 246
    const/4 v13, 0x0

    .line 247
    invoke-static/range {v6 .. v17}, La/a;->b(Lx2/s;Lm1/t;Lk1/z0;Lk1/g;Lx2/i;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 248
    .line 249
    .line 250
    goto :goto_1

    .line 251
    :cond_6
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 252
    .line 253
    .line 254
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 255
    .line 256
    return-object v0
.end method

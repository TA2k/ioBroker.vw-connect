.class public final synthetic Lz61/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z


# direct methods
.method public synthetic constructor <init>(ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lz61/e;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lz61/e;->e:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/q;

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
    const-string v4, "$this$FuSiScaffold"

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
    const/4 v6, 0x0

    .line 46
    const/4 v7, 0x1

    .line 47
    if-eq v4, v5, :cond_2

    .line 48
    .line 49
    move v4, v7

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    move v4, v6

    .line 52
    :goto_1
    and-int/2addr v3, v7

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
    sget-object v3, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 62
    .line 63
    sget-object v4, Lx2/c;->e:Lx2/j;

    .line 64
    .line 65
    invoke-interface {v1, v3, v4}, Lk1/q;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    sget-object v3, Lx2/c;->q:Lx2/h;

    .line 70
    .line 71
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 72
    .line 73
    const/16 v5, 0x36

    .line 74
    .line 75
    invoke-static {v4, v3, v2, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    iget-wide v4, v2, Ll2/t;->T:J

    .line 80
    .line 81
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 82
    .line 83
    .line 84
    move-result v4

    .line 85
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    invoke-static {v2, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 94
    .line 95
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 99
    .line 100
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 101
    .line 102
    .line 103
    iget-boolean v9, v2, Ll2/t;->S:Z

    .line 104
    .line 105
    if-eqz v9, :cond_3

    .line 106
    .line 107
    invoke-virtual {v2, v8}, Ll2/t;->l(Lay0/a;)V

    .line 108
    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_3
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 112
    .line 113
    .line 114
    :goto_2
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 115
    .line 116
    invoke-static {v8, v3, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    .line 118
    .line 119
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 120
    .line 121
    invoke-static {v3, v5, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 125
    .line 126
    iget-boolean v5, v2, Ll2/t;->S:Z

    .line 127
    .line 128
    if-nez v5, :cond_4

    .line 129
    .line 130
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object v8

    .line 138
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v5

    .line 142
    if-nez v5, :cond_5

    .line 143
    .line 144
    :cond_4
    invoke-static {v4, v2, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 145
    .line 146
    .line 147
    :cond_5
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 148
    .line 149
    invoke-static {v3, v1, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 150
    .line 151
    .line 152
    iget-boolean v1, v0, Lz61/e;->d:Z

    .line 153
    .line 154
    if-nez v1, :cond_6

    .line 155
    .line 156
    iget-boolean v0, v0, Lz61/e;->e:Z

    .line 157
    .line 158
    if-nez v0, :cond_6

    .line 159
    .line 160
    const v0, -0x6ecfd8a3

    .line 161
    .line 162
    .line 163
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 164
    .line 165
    .line 166
    const-string v0, "drive_activation_park_in_loading_indicator_description"

    .line 167
    .line 168
    invoke-static {v0, v2}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v8

    .line 172
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 173
    .line 174
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    check-cast v0, Lj91/f;

    .line 179
    .line 180
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 181
    .line 182
    .line 183
    move-result-object v9

    .line 184
    sget-object v0, Lh71/m;->a:Ll2/u2;

    .line 185
    .line 186
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    check-cast v0, Lh71/l;

    .line 191
    .line 192
    iget-object v0, v0, Lh71/l;->e:Lh71/k;

    .line 193
    .line 194
    iget-wide v0, v0, Lh71/k;->c:J

    .line 195
    .line 196
    new-instance v3, Lr4/k;

    .line 197
    .line 198
    const/4 v4, 0x3

    .line 199
    invoke-direct {v3, v4}, Lr4/k;-><init>(I)V

    .line 200
    .line 201
    .line 202
    const/16 v19, 0x0

    .line 203
    .line 204
    const/16 v20, 0x7c

    .line 205
    .line 206
    const/4 v10, 0x0

    .line 207
    const/4 v11, 0x0

    .line 208
    const/4 v12, 0x0

    .line 209
    const/4 v13, 0x0

    .line 210
    const/4 v14, 0x0

    .line 211
    move-wide v15, v0

    .line 212
    move-object/from16 v18, v2

    .line 213
    .line 214
    move-object/from16 v17, v3

    .line 215
    .line 216
    invoke-static/range {v8 .. v20}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    .line 217
    .line 218
    .line 219
    :goto_3
    invoke-virtual {v2, v6}, Ll2/t;->q(Z)V

    .line 220
    .line 221
    .line 222
    goto :goto_4

    .line 223
    :cond_6
    const v0, -0x6f4550f0

    .line 224
    .line 225
    .line 226
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 227
    .line 228
    .line 229
    goto :goto_3

    .line 230
    :goto_4
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 231
    .line 232
    .line 233
    goto :goto_5

    .line 234
    :cond_7
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 235
    .line 236
    .line 237
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 238
    .line 239
    return-object v0
.end method

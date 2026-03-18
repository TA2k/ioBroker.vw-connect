.class public final synthetic Lmc/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Lmc/t;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(FLmc/t;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lmc/a;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Lmc/a;->e:Lmc/t;

    .line 7
    .line 8
    iput-object p3, p0, Lmc/a;->f:Lay0/k;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/t;

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
    const-string v4, "$this$PreviewMode"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v1, v3, 0x11

    .line 25
    .line 26
    const/16 v4, 0x10

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    const/4 v6, 0x1

    .line 30
    if-eq v1, v4, :cond_0

    .line 31
    .line 32
    move v1, v6

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v1, v5

    .line 35
    :goto_0
    and-int/2addr v3, v6

    .line 36
    move-object v11, v2

    .line 37
    check-cast v11, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {v11, v3, v1}, Ll2/t;->O(IZ)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_8

    .line 44
    .line 45
    sget-object v12, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 46
    .line 47
    const/4 v14, 0x0

    .line 48
    const/16 v17, 0x2

    .line 49
    .line 50
    iget v13, v0, Lmc/a;->d:F

    .line 51
    .line 52
    move v15, v13

    .line 53
    move/from16 v16, v13

    .line 54
    .line 55
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    sget-wide v2, Le3/s;->e:J

    .line 60
    .line 61
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 62
    .line 63
    invoke-static {v1, v2, v3, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 68
    .line 69
    invoke-static {v2, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    iget-wide v3, v11, Ll2/t;->T:J

    .line 74
    .line 75
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    invoke-static {v11, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 88
    .line 89
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 93
    .line 94
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 95
    .line 96
    .line 97
    iget-boolean v7, v11, Ll2/t;->S:Z

    .line 98
    .line 99
    if-eqz v7, :cond_1

    .line 100
    .line 101
    invoke-virtual {v11, v5}, Ll2/t;->l(Lay0/a;)V

    .line 102
    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_1
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 106
    .line 107
    .line 108
    :goto_1
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 109
    .line 110
    invoke-static {v5, v2, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 111
    .line 112
    .line 113
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 114
    .line 115
    invoke-static {v2, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 116
    .line 117
    .line 118
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 119
    .line 120
    iget-boolean v4, v11, Ll2/t;->S:Z

    .line 121
    .line 122
    if-nez v4, :cond_2

    .line 123
    .line 124
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v4

    .line 128
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v4

    .line 136
    if-nez v4, :cond_3

    .line 137
    .line 138
    :cond_2
    invoke-static {v3, v11, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 139
    .line 140
    .line 141
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 142
    .line 143
    invoke-static {v2, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    const/4 v1, 0x3

    .line 147
    const/4 v2, 0x0

    .line 148
    invoke-static {v12, v2, v1}, Landroidx/compose/animation/c;->a(Lx2/s;Lc1/a0;I)Lx2/s;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    const-string v2, "payment_form"

    .line 153
    .line 154
    invoke-static {v1, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 155
    .line 156
    .line 157
    move-result-object v12

    .line 158
    iget-object v1, v0, Lmc/a;->e:Lmc/t;

    .line 159
    .line 160
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v2

    .line 164
    iget-object v0, v0, Lmc/a;->f:Lay0/k;

    .line 165
    .line 166
    invoke-virtual {v11, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    or-int/2addr v2, v3

    .line 171
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v3

    .line 175
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 176
    .line 177
    if-nez v2, :cond_4

    .line 178
    .line 179
    if-ne v3, v4, :cond_5

    .line 180
    .line 181
    :cond_4
    new-instance v3, Lmc/b;

    .line 182
    .line 183
    const/4 v2, 0x0

    .line 184
    invoke-direct {v3, v1, v0, v2}, Lmc/b;-><init>(Lmc/t;Lay0/k;I)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {v11, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    :cond_5
    move-object v9, v3

    .line 191
    check-cast v9, Lay0/k;

    .line 192
    .line 193
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v2

    .line 197
    invoke-virtual {v11, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v3

    .line 201
    or-int/2addr v2, v3

    .line 202
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v3

    .line 206
    if-nez v2, :cond_6

    .line 207
    .line 208
    if-ne v3, v4, :cond_7

    .line 209
    .line 210
    :cond_6
    new-instance v3, Lmc/b;

    .line 211
    .line 212
    const/4 v2, 0x1

    .line 213
    invoke-direct {v3, v1, v0, v2}, Lmc/b;-><init>(Lmc/t;Lay0/k;I)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v11, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    :cond_7
    move-object v10, v3

    .line 220
    check-cast v10, Lay0/k;

    .line 221
    .line 222
    const/4 v7, 0x0

    .line 223
    const/4 v8, 0x0

    .line 224
    invoke-static/range {v7 .. v12}, Landroidx/compose/ui/viewinterop/a;->a(IILay0/k;Lay0/k;Ll2/o;Lx2/s;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 228
    .line 229
    .line 230
    goto :goto_2

    .line 231
    :cond_8
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 232
    .line 233
    .line 234
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    return-object v0
.end method

.class public final synthetic Lt90/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ls90/f;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Ls90/f;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lt90/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt90/f;->e:Ls90/f;

    .line 4
    .line 5
    iput-object p2, p0, Lt90/f;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lt90/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk1/q;

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
    const-string v4, "$this$GradientBox"

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
    const/4 v5, 0x1

    .line 34
    if-eq v1, v4, :cond_0

    .line 35
    .line 36
    move v1, v5

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v1, 0x0

    .line 39
    :goto_0
    and-int/2addr v3, v5

    .line 40
    move-object v11, v2

    .line 41
    check-cast v11, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {v11, v3, v1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_1

    .line 48
    .line 49
    iget-object v1, v0, Lt90/f;->e:Ls90/f;

    .line 50
    .line 51
    iget-object v10, v1, Ls90/f;->h:Ljava/lang/String;

    .line 52
    .line 53
    iget-boolean v1, v1, Ls90/f;->d:Z

    .line 54
    .line 55
    xor-int/lit8 v13, v1, 0x1

    .line 56
    .line 57
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 58
    .line 59
    const v2, 0x7f12159c

    .line 60
    .line 61
    .line 62
    invoke-static {v1, v2}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 63
    .line 64
    .line 65
    move-result-object v12

    .line 66
    const/4 v6, 0x0

    .line 67
    const/16 v7, 0x28

    .line 68
    .line 69
    iget-object v8, v0, Lt90/f;->f:Lay0/a;

    .line 70
    .line 71
    const/4 v9, 0x0

    .line 72
    const/4 v14, 0x0

    .line 73
    invoke-static/range {v6 .. v14}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_1
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 78
    .line 79
    .line 80
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    return-object v0

    .line 83
    :pswitch_0
    move-object/from16 v1, p1

    .line 84
    .line 85
    check-cast v1, Lk1/z0;

    .line 86
    .line 87
    move-object/from16 v2, p2

    .line 88
    .line 89
    check-cast v2, Ll2/o;

    .line 90
    .line 91
    move-object/from16 v3, p3

    .line 92
    .line 93
    check-cast v3, Ljava/lang/Integer;

    .line 94
    .line 95
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    const-string v4, "paddingValues"

    .line 100
    .line 101
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    and-int/lit8 v4, v3, 0x6

    .line 105
    .line 106
    if-nez v4, :cond_3

    .line 107
    .line 108
    move-object v4, v2

    .line 109
    check-cast v4, Ll2/t;

    .line 110
    .line 111
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    if-eqz v4, :cond_2

    .line 116
    .line 117
    const/4 v4, 0x4

    .line 118
    goto :goto_2

    .line 119
    :cond_2
    const/4 v4, 0x2

    .line 120
    :goto_2
    or-int/2addr v3, v4

    .line 121
    :cond_3
    and-int/lit8 v4, v3, 0x13

    .line 122
    .line 123
    const/16 v5, 0x12

    .line 124
    .line 125
    const/4 v6, 0x1

    .line 126
    if-eq v4, v5, :cond_4

    .line 127
    .line 128
    move v4, v6

    .line 129
    goto :goto_3

    .line 130
    :cond_4
    const/4 v4, 0x0

    .line 131
    :goto_3
    and-int/2addr v3, v6

    .line 132
    move-object v12, v2

    .line 133
    check-cast v12, Ll2/t;

    .line 134
    .line 135
    invoke-virtual {v12, v3, v4}, Ll2/t;->O(IZ)Z

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    if-eqz v2, :cond_5

    .line 140
    .line 141
    invoke-static {v12}, Lj2/i;->d(Ll2/o;)Lj2/p;

    .line 142
    .line 143
    .line 144
    move-result-object v8

    .line 145
    iget-object v2, v0, Lt90/f;->e:Ls90/f;

    .line 146
    .line 147
    iget-boolean v5, v2, Ls90/f;->e:Z

    .line 148
    .line 149
    sget-object v13, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 150
    .line 151
    invoke-interface {v1}, Lk1/z0;->d()F

    .line 152
    .line 153
    .line 154
    move-result v15

    .line 155
    iget-boolean v3, v2, Ls90/f;->g:Z

    .line 156
    .line 157
    invoke-static {v1, v3}, Lxf0/y1;->y(Lk1/z0;Z)F

    .line 158
    .line 159
    .line 160
    move-result v17

    .line 161
    const/16 v18, 0x5

    .line 162
    .line 163
    const/4 v14, 0x0

    .line 164
    const/16 v16, 0x0

    .line 165
    .line 166
    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 171
    .line 172
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v3

    .line 176
    check-cast v3, Lj91/e;

    .line 177
    .line 178
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 179
    .line 180
    .line 181
    move-result-wide v3

    .line 182
    sget-object v6, Le3/j0;->a:Le3/i0;

    .line 183
    .line 184
    invoke-static {v1, v3, v4, v6}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 185
    .line 186
    .line 187
    move-result-object v7

    .line 188
    new-instance v1, Lp4/a;

    .line 189
    .line 190
    const/16 v3, 0x8

    .line 191
    .line 192
    invoke-direct {v1, v3, v8, v2}, Lp4/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    const v3, 0x476d69c4

    .line 196
    .line 197
    .line 198
    invoke-static {v3, v12, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 199
    .line 200
    .line 201
    move-result-object v10

    .line 202
    new-instance v1, Lkv0/d;

    .line 203
    .line 204
    const/16 v3, 0xa

    .line 205
    .line 206
    invoke-direct {v1, v2, v3}, Lkv0/d;-><init>(Ljava/lang/Object;I)V

    .line 207
    .line 208
    .line 209
    const v2, -0x685c01dd

    .line 210
    .line 211
    .line 212
    invoke-static {v2, v12, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 213
    .line 214
    .line 215
    move-result-object v11

    .line 216
    const/high16 v13, 0x1b0000

    .line 217
    .line 218
    const/16 v14, 0x10

    .line 219
    .line 220
    iget-object v6, v0, Lt90/f;->f:Lay0/a;

    .line 221
    .line 222
    const/4 v9, 0x0

    .line 223
    invoke-static/range {v5 .. v14}, Lj2/i;->b(ZLay0/a;Lx2/s;Lj2/p;Lx2/e;Lay0/o;Lt2/b;Ll2/o;II)V

    .line 224
    .line 225
    .line 226
    goto :goto_4

    .line 227
    :cond_5
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 228
    .line 229
    .line 230
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 231
    .line 232
    return-object v0

    .line 233
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

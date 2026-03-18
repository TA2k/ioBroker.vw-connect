.class public final synthetic Lz10/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lz10/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz10/b;->e:Ll2/b1;

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
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lz10/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/media3/exoplayer/ExoPlayer;

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
    const-string v4, "it"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v3, v3, 0xe

    .line 30
    .line 31
    or-int/lit8 v3, v3, 0x30

    .line 32
    .line 33
    iget-object v0, v0, Lz10/b;->e:Ll2/b1;

    .line 34
    .line 35
    invoke-static {v1, v0, v2, v3}, Lz10/a;->p(Landroidx/media3/exoplayer/ExoPlayer;Ll2/b1;Ll2/o;I)V

    .line 36
    .line 37
    .line 38
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object v0

    .line 41
    :pswitch_0
    move-object/from16 v1, p1

    .line 42
    .line 43
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 44
    .line 45
    move-object/from16 v2, p2

    .line 46
    .line 47
    check-cast v2, Ll2/o;

    .line 48
    .line 49
    move-object/from16 v3, p3

    .line 50
    .line 51
    check-cast v3, Ljava/lang/Integer;

    .line 52
    .line 53
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    const-string v4, "$this$item"

    .line 58
    .line 59
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    and-int/lit8 v1, v3, 0x11

    .line 63
    .line 64
    const/16 v4, 0x10

    .line 65
    .line 66
    const/4 v5, 0x1

    .line 67
    if-eq v1, v4, :cond_0

    .line 68
    .line 69
    move v1, v5

    .line 70
    goto :goto_0

    .line 71
    :cond_0
    const/4 v1, 0x0

    .line 72
    :goto_0
    and-int/2addr v3, v5

    .line 73
    check-cast v2, Ll2/t;

    .line 74
    .line 75
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-eqz v1, :cond_2

    .line 80
    .line 81
    const v1, 0x7f12021d

    .line 82
    .line 83
    .line 84
    invoke-static {v2, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 89
    .line 90
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    check-cast v1, Lj91/f;

    .line 95
    .line 96
    invoke-virtual {v1}, Lj91/f;->i()Lg4/p0;

    .line 97
    .line 98
    .line 99
    move-result-object v5

    .line 100
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 101
    .line 102
    const/high16 v3, 0x3f800000    # 1.0f

    .line 103
    .line 104
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 109
    .line 110
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    check-cast v6, Lj91/c;

    .line 115
    .line 116
    iget v6, v6, Lj91/c;->d:F

    .line 117
    .line 118
    const/4 v7, 0x2

    .line 119
    const/4 v8, 0x0

    .line 120
    invoke-static {v1, v6, v8, v7}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 121
    .line 122
    .line 123
    move-result-object v9

    .line 124
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    check-cast v1, Lj91/c;

    .line 129
    .line 130
    iget v11, v1, Lj91/c;->e:F

    .line 131
    .line 132
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    check-cast v1, Lj91/c;

    .line 137
    .line 138
    iget v13, v1, Lj91/c;->d:F

    .line 139
    .line 140
    const/4 v14, 0x5

    .line 141
    const/4 v10, 0x0

    .line 142
    const/4 v12, 0x0

    .line 143
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 152
    .line 153
    if-ne v3, v6, :cond_1

    .line 154
    .line 155
    new-instance v3, Lle/b;

    .line 156
    .line 157
    const/16 v6, 0x1c

    .line 158
    .line 159
    iget-object v0, v0, Lz10/b;->e:Ll2/b1;

    .line 160
    .line 161
    invoke-direct {v3, v0, v6}, Lle/b;-><init>(Ll2/b1;I)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    :cond_1
    check-cast v3, Lay0/k;

    .line 168
    .line 169
    invoke-static {v1, v3}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 170
    .line 171
    .line 172
    move-result-object v6

    .line 173
    const/16 v24, 0x0

    .line 174
    .line 175
    const v25, 0xfff8

    .line 176
    .line 177
    .line 178
    const-wide/16 v7, 0x0

    .line 179
    .line 180
    const-wide/16 v9, 0x0

    .line 181
    .line 182
    const/4 v11, 0x0

    .line 183
    const-wide/16 v12, 0x0

    .line 184
    .line 185
    const/4 v14, 0x0

    .line 186
    const/4 v15, 0x0

    .line 187
    const-wide/16 v16, 0x0

    .line 188
    .line 189
    const/16 v18, 0x0

    .line 190
    .line 191
    const/16 v19, 0x0

    .line 192
    .line 193
    const/16 v20, 0x0

    .line 194
    .line 195
    const/16 v21, 0x0

    .line 196
    .line 197
    const/16 v23, 0x0

    .line 198
    .line 199
    move-object/from16 v22, v2

    .line 200
    .line 201
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 202
    .line 203
    .line 204
    goto :goto_1

    .line 205
    :cond_2
    move-object/from16 v22, v2

    .line 206
    .line 207
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 208
    .line 209
    .line 210
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 211
    .line 212
    return-object v0

    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

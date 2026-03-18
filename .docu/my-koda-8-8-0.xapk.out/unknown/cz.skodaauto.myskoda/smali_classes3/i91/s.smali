.class public final synthetic Li91/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li91/h1;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Z

.field public final synthetic i:Le1/t;

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(Li91/h1;Lx2/s;Lay0/a;ZLe1/t;II)V
    .locals 0

    .line 1
    iput p7, p0, Li91/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li91/s;->e:Li91/h1;

    .line 4
    .line 5
    iput-object p2, p0, Li91/s;->f:Lx2/s;

    .line 6
    .line 7
    iput-object p3, p0, Li91/s;->g:Lay0/a;

    .line 8
    .line 9
    iput-boolean p4, p0, Li91/s;->h:Z

    .line 10
    .line 11
    iput-object p5, p0, Li91/s;->i:Le1/t;

    .line 12
    .line 13
    iput p6, p0, Li91/s;->j:I

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/s;->d:I

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
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x1

    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v6

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v5

    .line 30
    :goto_0
    and-int/2addr v2, v6

    .line 31
    move-object v15, v1

    .line 32
    check-cast v15, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v15, v2, v3}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    sget-object v9, Ls1/f;->a:Ls1/e;

    .line 41
    .line 42
    const/4 v1, 0x3

    .line 43
    int-to-float v1, v1

    .line 44
    const/16 v21, 0x0

    .line 45
    .line 46
    move/from16 v17, v1

    .line 47
    .line 48
    move/from16 v18, v1

    .line 49
    .line 50
    move/from16 v19, v1

    .line 51
    .line 52
    move/from16 v20, v1

    .line 53
    .line 54
    move/from16 v16, v1

    .line 55
    .line 56
    invoke-static/range {v16 .. v21}, Lh2/o0;->b(FFFFFI)Lh2/q0;

    .line 57
    .line 58
    .line 59
    move-result-object v11

    .line 60
    iget-object v1, v0, Li91/s;->e:Li91/h1;

    .line 61
    .line 62
    invoke-virtual {v1, v15}, Li91/h1;->a(Ll2/o;)Lh2/n0;

    .line 63
    .line 64
    .line 65
    move-result-object v10

    .line 66
    int-to-float v1, v5

    .line 67
    new-instance v13, Lk1/a1;

    .line 68
    .line 69
    invoke-direct {v13, v1, v1, v1, v1}, Lk1/a1;-><init>(FFFF)V

    .line 70
    .line 71
    .line 72
    const/16 v1, 0x2c

    .line 73
    .line 74
    int-to-float v1, v1

    .line 75
    iget-object v2, v0, Li91/s;->f:Lx2/s;

    .line 76
    .line 77
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    new-instance v1, Ldl0/a;

    .line 82
    .line 83
    const/4 v2, 0x4

    .line 84
    iget v3, v0, Li91/s;->j:I

    .line 85
    .line 86
    invoke-direct {v1, v3, v2}, Ldl0/a;-><init>(II)V

    .line 87
    .line 88
    .line 89
    const v2, 0x754c737a

    .line 90
    .line 91
    .line 92
    invoke-static {v2, v15, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 93
    .line 94
    .line 95
    move-result-object v14

    .line 96
    const/high16 v16, 0x30c00000

    .line 97
    .line 98
    iget-object v6, v0, Li91/s;->g:Lay0/a;

    .line 99
    .line 100
    iget-boolean v8, v0, Li91/s;->h:Z

    .line 101
    .line 102
    iget-object v12, v0, Li91/s;->i:Le1/t;

    .line 103
    .line 104
    invoke-static/range {v6 .. v16}, Lh2/r;->h(Lay0/a;Lx2/s;ZLe3/n0;Lh2/n0;Lh2/q0;Le1/t;Lk1/z0;Lt2/b;Ll2/o;I)V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_1
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 109
    .line 110
    .line 111
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object v0

    .line 114
    :pswitch_0
    move-object/from16 v1, p1

    .line 115
    .line 116
    check-cast v1, Ll2/o;

    .line 117
    .line 118
    move-object/from16 v2, p2

    .line 119
    .line 120
    check-cast v2, Ljava/lang/Integer;

    .line 121
    .line 122
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    and-int/lit8 v3, v2, 0x3

    .line 127
    .line 128
    const/4 v4, 0x2

    .line 129
    const/4 v5, 0x0

    .line 130
    const/4 v6, 0x1

    .line 131
    if-eq v3, v4, :cond_2

    .line 132
    .line 133
    move v3, v6

    .line 134
    goto :goto_2

    .line 135
    :cond_2
    move v3, v5

    .line 136
    :goto_2
    and-int/2addr v2, v6

    .line 137
    move-object v15, v1

    .line 138
    check-cast v15, Ll2/t;

    .line 139
    .line 140
    invoke-virtual {v15, v2, v3}, Ll2/t;->O(IZ)Z

    .line 141
    .line 142
    .line 143
    move-result v1

    .line 144
    if-eqz v1, :cond_3

    .line 145
    .line 146
    sget-object v9, Ls1/f;->a:Ls1/e;

    .line 147
    .line 148
    int-to-float v1, v5

    .line 149
    const/16 v21, 0x0

    .line 150
    .line 151
    move/from16 v17, v1

    .line 152
    .line 153
    move/from16 v18, v1

    .line 154
    .line 155
    move/from16 v19, v1

    .line 156
    .line 157
    move/from16 v20, v1

    .line 158
    .line 159
    move/from16 v16, v1

    .line 160
    .line 161
    invoke-static/range {v16 .. v21}, Lh2/o0;->b(FFFFFI)Lh2/q0;

    .line 162
    .line 163
    .line 164
    move-result-object v11

    .line 165
    const/4 v1, 0x6

    .line 166
    int-to-float v1, v1

    .line 167
    new-instance v13, Lk1/a1;

    .line 168
    .line 169
    invoke-direct {v13, v1, v1, v1, v1}, Lk1/a1;-><init>(FFFF)V

    .line 170
    .line 171
    .line 172
    iget-object v1, v0, Li91/s;->e:Li91/h1;

    .line 173
    .line 174
    invoke-virtual {v1, v15}, Li91/h1;->a(Ll2/o;)Lh2/n0;

    .line 175
    .line 176
    .line 177
    move-result-object v10

    .line 178
    const/16 v2, 0x20

    .line 179
    .line 180
    int-to-float v2, v2

    .line 181
    iget-object v3, v0, Li91/s;->f:Lx2/s;

    .line 182
    .line 183
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 184
    .line 185
    .line 186
    move-result-object v7

    .line 187
    new-instance v2, Li91/u;

    .line 188
    .line 189
    iget v3, v0, Li91/s;->j:I

    .line 190
    .line 191
    iget-boolean v8, v0, Li91/s;->h:Z

    .line 192
    .line 193
    invoke-direct {v2, v3, v1, v8}, Li91/u;-><init>(ILi91/h1;Z)V

    .line 194
    .line 195
    .line 196
    const v1, -0x578fae58

    .line 197
    .line 198
    .line 199
    invoke-static {v1, v15, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 200
    .line 201
    .line 202
    move-result-object v14

    .line 203
    const/high16 v16, 0x30c00000

    .line 204
    .line 205
    const/16 v17, 0x100

    .line 206
    .line 207
    iget-object v6, v0, Li91/s;->g:Lay0/a;

    .line 208
    .line 209
    iget-object v12, v0, Li91/s;->i:Le1/t;

    .line 210
    .line 211
    invoke-static/range {v6 .. v17}, Lh2/r;->d(Lay0/a;Lx2/s;ZLe3/n0;Lh2/n0;Lh2/q0;Le1/t;Lk1/z0;Lt2/b;Ll2/o;II)V

    .line 212
    .line 213
    .line 214
    goto :goto_3

    .line 215
    :cond_3
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 216
    .line 217
    .line 218
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 219
    .line 220
    return-object v0

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.class public abstract Ld90/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x6c

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Ld90/x;->a:F

    .line 5
    .line 6
    const/16 v0, 0xc6

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Ld90/x;->b:F

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lc90/a;Lx2/s;Lay0/k;Ll2/o;II)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v0, "model"

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v6, p3

    .line 9
    .line 10
    check-cast v6, Ll2/t;

    .line 11
    .line 12
    const v0, 0x359f9821

    .line 13
    .line 14
    .line 15
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p4, v0

    .line 28
    .line 29
    and-int/lit8 v2, p5, 0x4

    .line 30
    .line 31
    const/16 v3, 0x100

    .line 32
    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    or-int/lit16 v0, v0, 0x180

    .line 36
    .line 37
    move-object/from16 v4, p2

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_1
    move-object/from16 v4, p2

    .line 41
    .line 42
    invoke-virtual {v6, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-eqz v5, :cond_2

    .line 47
    .line 48
    move v5, v3

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    const/16 v5, 0x80

    .line 51
    .line 52
    :goto_1
    or-int/2addr v0, v5

    .line 53
    :goto_2
    and-int/lit16 v5, v0, 0x93

    .line 54
    .line 55
    const/16 v7, 0x92

    .line 56
    .line 57
    const/4 v8, 0x1

    .line 58
    const/4 v9, 0x0

    .line 59
    if-eq v5, v7, :cond_3

    .line 60
    .line 61
    move v5, v8

    .line 62
    goto :goto_3

    .line 63
    :cond_3
    move v5, v9

    .line 64
    :goto_3
    and-int/lit8 v7, v0, 0x1

    .line 65
    .line 66
    invoke-virtual {v6, v7, v5}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result v5

    .line 70
    if-eqz v5, :cond_9

    .line 71
    .line 72
    if-eqz v2, :cond_4

    .line 73
    .line 74
    const/4 v2, 0x0

    .line 75
    move-object v10, v2

    .line 76
    goto :goto_4

    .line 77
    :cond_4
    move-object v10, v4

    .line 78
    :goto_4
    const v2, 0x4c1a29b9    # 4.04129E7f

    .line 79
    .line 80
    .line 81
    invoke-virtual {v6, v2}, Ll2/t;->Y(I)V

    .line 82
    .line 83
    .line 84
    if-eqz v10, :cond_8

    .line 85
    .line 86
    const v2, -0x7480ef85

    .line 87
    .line 88
    .line 89
    invoke-virtual {v6, v2}, Ll2/t;->Y(I)V

    .line 90
    .line 91
    .line 92
    and-int/lit16 v0, v0, 0x380

    .line 93
    .line 94
    if-ne v0, v3, :cond_5

    .line 95
    .line 96
    goto :goto_5

    .line 97
    :cond_5
    move v8, v9

    .line 98
    :goto_5
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    or-int/2addr v0, v8

    .line 103
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    if-nez v0, :cond_6

    .line 108
    .line 109
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 110
    .line 111
    if-ne v2, v0, :cond_7

    .line 112
    .line 113
    :cond_6
    new-instance v2, Ld90/w;

    .line 114
    .line 115
    const/4 v0, 0x0

    .line 116
    invoke-direct {v2, v0, v10, v1}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v6, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :cond_7
    move-object v15, v2

    .line 123
    check-cast v15, Lay0/a;

    .line 124
    .line 125
    const/16 v16, 0xf

    .line 126
    .line 127
    const/4 v12, 0x0

    .line 128
    const/4 v13, 0x0

    .line 129
    const/4 v14, 0x0

    .line 130
    move-object/from16 v11, p1

    .line 131
    .line 132
    invoke-static/range {v11 .. v16}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    invoke-virtual {v6, v9}, Ll2/t;->q(Z)V

    .line 137
    .line 138
    .line 139
    move-object v2, v0

    .line 140
    goto :goto_6

    .line 141
    :cond_8
    const v0, -0x747fe7a8

    .line 142
    .line 143
    .line 144
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v6, v9}, Ll2/t;->q(Z)V

    .line 148
    .line 149
    .line 150
    move-object/from16 v2, p1

    .line 151
    .line 152
    :goto_6
    invoke-virtual {v6, v9}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    new-instance v0, Ld90/m;

    .line 156
    .line 157
    const/4 v3, 0x2

    .line 158
    move-object/from16 v11, p1

    .line 159
    .line 160
    invoke-direct {v0, v3, v11, v1}, Ld90/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    const v3, -0x4f41aeea

    .line 164
    .line 165
    .line 166
    invoke-static {v3, v6, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    const/16 v7, 0xc00

    .line 171
    .line 172
    const/4 v8, 0x6

    .line 173
    const/4 v3, 0x0

    .line 174
    const/4 v4, 0x0

    .line 175
    invoke-static/range {v2 .. v8}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 176
    .line 177
    .line 178
    move-object v3, v10

    .line 179
    goto :goto_7

    .line 180
    :cond_9
    move-object/from16 v11, p1

    .line 181
    .line 182
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    move-object v3, v4

    .line 186
    :goto_7
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 187
    .line 188
    .line 189
    move-result-object v7

    .line 190
    if-eqz v7, :cond_a

    .line 191
    .line 192
    new-instance v0, La2/f;

    .line 193
    .line 194
    const/16 v6, 0x9

    .line 195
    .line 196
    move/from16 v4, p4

    .line 197
    .line 198
    move/from16 v5, p5

    .line 199
    .line 200
    move-object v2, v11

    .line 201
    invoke-direct/range {v0 .. v6}, La2/f;-><init>(Ljava/lang/Object;Lx2/s;Lay0/k;III)V

    .line 202
    .line 203
    .line 204
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 205
    .line 206
    :cond_a
    return-void
.end method

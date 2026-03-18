.class public final Lh2/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh2/v;

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F

.field public static final f:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lh2/v;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/v;->a:Lh2/v;

    .line 7
    .line 8
    sget-object v0, Lk2/h0;->a:Lk2/f0;

    .line 9
    .line 10
    sget v0, Lk2/h0;->e:F

    .line 11
    .line 12
    sput v0, Lh2/v;->b:F

    .line 13
    .line 14
    const/16 v0, 0x38

    .line 15
    .line 16
    int-to-float v0, v0

    .line 17
    sput v0, Lh2/v;->c:F

    .line 18
    .line 19
    const/16 v1, 0x280

    .line 20
    .line 21
    int-to-float v1, v1

    .line 22
    sput v1, Lh2/v;->d:F

    .line 23
    .line 24
    sput v0, Lh2/v;->e:F

    .line 25
    .line 26
    const/16 v0, 0x7d

    .line 27
    .line 28
    int-to-float v0, v0

    .line 29
    sput v0, Lh2/v;->f:F

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final a(Lx2/s;FFLe3/n0;JLl2/o;I)V
    .locals 22

    .line 1
    move/from16 v8, p8

    .line 2
    .line 3
    move-object/from16 v0, p7

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, -0x515137eb

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    or-int/lit16 v1, v8, 0x25b6

    .line 14
    .line 15
    and-int/lit16 v2, v1, 0x2493

    .line 16
    .line 17
    const/16 v3, 0x2492

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    const/4 v5, 0x1

    .line 21
    if-eq v2, v3, :cond_0

    .line 22
    .line 23
    move v2, v5

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move v2, v4

    .line 26
    :goto_0
    and-int/2addr v1, v5

    .line 27
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_5

    .line 32
    .line 33
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 34
    .line 35
    .line 36
    and-int/lit8 v1, v8, 0x1

    .line 37
    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 48
    .line 49
    .line 50
    move-object/from16 v1, p1

    .line 51
    .line 52
    move/from16 v2, p2

    .line 53
    .line 54
    move/from16 v3, p3

    .line 55
    .line 56
    move-object/from16 v10, p4

    .line 57
    .line 58
    move-wide/from16 v11, p5

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_2
    :goto_1
    sget v1, Lk2/h0;->d:F

    .line 62
    .line 63
    sget v2, Lk2/h0;->c:F

    .line 64
    .line 65
    sget-object v3, Lh2/i8;->a:Ll2/u2;

    .line 66
    .line 67
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    check-cast v3, Lh2/h8;

    .line 72
    .line 73
    iget-object v3, v3, Lh2/h8;->e:Ls1/e;

    .line 74
    .line 75
    sget-object v6, Lk2/h0;->b:Lk2/l;

    .line 76
    .line 77
    invoke-static {v6, v0}, Lh2/g1;->d(Lk2/l;Ll2/o;)J

    .line 78
    .line 79
    .line 80
    move-result-wide v6

    .line 81
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 82
    .line 83
    move-object v10, v3

    .line 84
    move-wide v11, v6

    .line 85
    move v3, v2

    .line 86
    move v2, v1

    .line 87
    move-object v1, v9

    .line 88
    :goto_2
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 89
    .line 90
    .line 91
    const v6, 0x7f120590

    .line 92
    .line 93
    .line 94
    invoke-static {v0, v6}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v6

    .line 98
    const/4 v7, 0x0

    .line 99
    sget v9, Lh2/m8;->a:F

    .line 100
    .line 101
    invoke-static {v1, v7, v9, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v7

    .line 109
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v9

    .line 113
    if-nez v7, :cond_3

    .line 114
    .line 115
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 116
    .line 117
    if-ne v9, v7, :cond_4

    .line 118
    .line 119
    :cond_3
    new-instance v9, Lac0/r;

    .line 120
    .line 121
    const/16 v7, 0xc

    .line 122
    .line 123
    invoke-direct {v9, v6, v7}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v0, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    :cond_4
    check-cast v9, Lay0/k;

    .line 130
    .line 131
    invoke-static {v5, v4, v9}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 132
    .line 133
    .line 134
    move-result-object v9

    .line 135
    new-instance v4, Lh2/u;

    .line 136
    .line 137
    invoke-direct {v4, v2, v3}, Lh2/u;-><init>(FF)V

    .line 138
    .line 139
    .line 140
    const v5, -0x3df6a050

    .line 141
    .line 142
    .line 143
    invoke-static {v5, v0, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 144
    .line 145
    .line 146
    move-result-object v18

    .line 147
    const/high16 v20, 0xc00000

    .line 148
    .line 149
    const/16 v21, 0x78

    .line 150
    .line 151
    const-wide/16 v13, 0x0

    .line 152
    .line 153
    const/4 v15, 0x0

    .line 154
    const/16 v16, 0x0

    .line 155
    .line 156
    const/16 v17, 0x0

    .line 157
    .line 158
    move-object/from16 v19, v0

    .line 159
    .line 160
    invoke-static/range {v9 .. v21}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    .line 161
    .line 162
    .line 163
    move v4, v3

    .line 164
    move-object v5, v10

    .line 165
    move-wide v6, v11

    .line 166
    move v3, v2

    .line 167
    move-object v2, v1

    .line 168
    goto :goto_3

    .line 169
    :cond_5
    move-object/from16 v19, v0

    .line 170
    .line 171
    invoke-virtual/range {v19 .. v19}, Ll2/t;->R()V

    .line 172
    .line 173
    .line 174
    move-object/from16 v2, p1

    .line 175
    .line 176
    move/from16 v3, p2

    .line 177
    .line 178
    move/from16 v4, p3

    .line 179
    .line 180
    move-object/from16 v5, p4

    .line 181
    .line 182
    move-wide/from16 v6, p5

    .line 183
    .line 184
    :goto_3
    invoke-virtual/range {v19 .. v19}, Ll2/t;->s()Ll2/u1;

    .line 185
    .line 186
    .line 187
    move-result-object v9

    .line 188
    if-eqz v9, :cond_6

    .line 189
    .line 190
    new-instance v0, Lh2/t;

    .line 191
    .line 192
    move-object/from16 v1, p0

    .line 193
    .line 194
    invoke-direct/range {v0 .. v8}, Lh2/t;-><init>(Lh2/v;Lx2/s;FFLe3/n0;JI)V

    .line 195
    .line 196
    .line 197
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 198
    .line 199
    :cond_6
    return-void
.end method

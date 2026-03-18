.class public abstract Lh2/f2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk1/a1;

.field public static final b:F

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    const/4 v1, 0x6

    .line 5
    int-to-float v1, v1

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x3

    .line 8
    invoke-static {v2, v2, v1, v0, v3}, Landroidx/compose/foundation/layout/a;->c(FFFFI)Lk1/a1;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    sput-object v1, Lh2/f2;->a:Lk1/a1;

    .line 13
    .line 14
    sput v0, Lh2/f2;->b:F

    .line 15
    .line 16
    const/16 v0, 0xc

    .line 17
    .line 18
    int-to-float v0, v0

    .line 19
    sput v0, Lh2/f2;->c:F

    .line 20
    .line 21
    return-void
.end method

.method public static final a(Lay0/a;Lt2/b;Lx2/s;Le3/n0;FLh2/z1;Lx4/p;Lt2/b;Ll2/o;I)V
    .locals 15

    .line 1
    move-object/from16 v4, p8

    .line 2
    .line 3
    check-cast v4, Ll2/t;

    .line 4
    .line 5
    const v0, 0xd18a3f1

    .line 6
    .line 7
    .line 8
    invoke-virtual {v4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v4, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x4

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v0, 0x2

    .line 20
    :goto_0
    or-int v0, p9, v0

    .line 21
    .line 22
    const v1, 0x32d80

    .line 23
    .line 24
    .line 25
    or-int/2addr v0, v1

    .line 26
    move-object/from16 v7, p5

    .line 27
    .line 28
    invoke-virtual {v4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    const/high16 v1, 0x100000

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/high16 v1, 0x80000

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v1

    .line 40
    const/high16 v1, 0xc00000

    .line 41
    .line 42
    or-int/2addr v0, v1

    .line 43
    const v1, 0x2492493

    .line 44
    .line 45
    .line 46
    and-int/2addr v1, v0

    .line 47
    const v2, 0x2492492

    .line 48
    .line 49
    .line 50
    if-eq v1, v2, :cond_2

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    const/4 v1, 0x0

    .line 55
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 56
    .line 57
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-eqz v1, :cond_5

    .line 62
    .line 63
    invoke-virtual {v4}, Ll2/t;->T()V

    .line 64
    .line 65
    .line 66
    and-int/lit8 v1, p9, 0x1

    .line 67
    .line 68
    const/4 v2, 0x3

    .line 69
    const v3, -0xe001

    .line 70
    .line 71
    .line 72
    if-eqz v1, :cond_4

    .line 73
    .line 74
    invoke-virtual {v4}, Ll2/t;->y()Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-eqz v1, :cond_3

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_3
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 82
    .line 83
    .line 84
    and-int/2addr v0, v3

    .line 85
    move-object/from16 v11, p2

    .line 86
    .line 87
    move-object/from16 v6, p3

    .line 88
    .line 89
    move/from16 v8, p4

    .line 90
    .line 91
    move v1, v0

    .line 92
    move-object/from16 v0, p6

    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_4
    :goto_3
    sget-object v1, Lh2/c2;->a:Lh2/c2;

    .line 96
    .line 97
    sget-object v1, Lk2/m;->c:Lk2/f0;

    .line 98
    .line 99
    invoke-static {v1, v4}, Lh2/i8;->b(Lk2/f0;Ll2/o;)Le3/n0;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    and-int/2addr v0, v3

    .line 104
    sget v3, Lh2/c2;->c:F

    .line 105
    .line 106
    new-instance v5, Lx4/p;

    .line 107
    .line 108
    invoke-direct {v5, v2}, Lx4/p;-><init>(I)V

    .line 109
    .line 110
    .line 111
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 112
    .line 113
    move v8, v3

    .line 114
    move-object v11, v6

    .line 115
    move-object v6, v1

    .line 116
    move v1, v0

    .line 117
    move-object v0, v5

    .line 118
    :goto_4
    invoke-virtual {v4}, Ll2/t;->r()V

    .line 119
    .line 120
    .line 121
    invoke-static {v11, v2}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    new-instance v5, Lh2/e2;

    .line 126
    .line 127
    move-object/from16 v10, p1

    .line 128
    .line 129
    move-object/from16 v9, p7

    .line 130
    .line 131
    invoke-direct/range {v5 .. v10}, Lh2/e2;-><init>(Le3/n0;Lh2/z1;FLt2/b;Lt2/b;)V

    .line 132
    .line 133
    .line 134
    const v3, 0x421948f7

    .line 135
    .line 136
    .line 137
    invoke-static {v3, v4, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    and-int/lit8 v1, v1, 0xe

    .line 142
    .line 143
    or-int/lit16 v5, v1, 0xd80

    .line 144
    .line 145
    move-object v1, v2

    .line 146
    move-object v2, v0

    .line 147
    move-object v0, p0

    .line 148
    invoke-static/range {v0 .. v5}, Lh2/j;->d(Lay0/a;Lx2/s;Lx4/p;Lt2/b;Ll2/o;I)V

    .line 149
    .line 150
    .line 151
    move-object v12, v2

    .line 152
    move-object v9, v6

    .line 153
    move v10, v8

    .line 154
    move-object v8, v11

    .line 155
    goto :goto_5

    .line 156
    :cond_5
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 157
    .line 158
    .line 159
    move-object/from16 v8, p2

    .line 160
    .line 161
    move-object/from16 v9, p3

    .line 162
    .line 163
    move/from16 v10, p4

    .line 164
    .line 165
    move-object/from16 v12, p6

    .line 166
    .line 167
    :goto_5
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    if-eqz v0, :cond_6

    .line 172
    .line 173
    new-instance v5, Lh2/d2;

    .line 174
    .line 175
    move-object v6, p0

    .line 176
    move-object/from16 v7, p1

    .line 177
    .line 178
    move-object/from16 v11, p5

    .line 179
    .line 180
    move-object/from16 v13, p7

    .line 181
    .line 182
    move/from16 v14, p9

    .line 183
    .line 184
    invoke-direct/range {v5 .. v14}, Lh2/d2;-><init>(Lay0/a;Lt2/b;Lx2/s;Le3/n0;FLh2/z1;Lx4/p;Lt2/b;I)V

    .line 185
    .line 186
    .line 187
    iput-object v5, v0, Ll2/u1;->d:Lay0/n;

    .line 188
    .line 189
    :cond_6
    return-void
.end method

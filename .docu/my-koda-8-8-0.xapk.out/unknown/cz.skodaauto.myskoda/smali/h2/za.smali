.class public final Lh2/za;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh2/za;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lh2/za;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/za;->a:Lh2/za;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lx2/s;FJLl2/o;II)V
    .locals 11

    .line 1
    move-object/from16 v0, p5

    .line 2
    .line 3
    check-cast v0, Ll2/t;

    .line 4
    .line 5
    const v1, -0x594d9a64

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    const/4 v1, 0x4

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v1, 0x2

    .line 20
    :goto_0
    or-int v1, p6, v1

    .line 21
    .line 22
    and-int/lit8 v3, p7, 0x2

    .line 23
    .line 24
    if-eqz v3, :cond_1

    .line 25
    .line 26
    or-int/lit8 v1, v1, 0x30

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_1
    and-int/lit8 v4, p6, 0x30

    .line 30
    .line 31
    if-nez v4, :cond_3

    .line 32
    .line 33
    invoke-virtual {v0, p2}, Ll2/t;->d(F)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eqz v5, :cond_2

    .line 38
    .line 39
    const/16 v5, 0x20

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    const/16 v5, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v1, v5

    .line 45
    :cond_3
    :goto_2
    and-int/lit8 v5, p7, 0x4

    .line 46
    .line 47
    if-nez v5, :cond_4

    .line 48
    .line 49
    invoke-virtual {v0, p3, p4}, Ll2/t;->f(J)Z

    .line 50
    .line 51
    .line 52
    move-result v7

    .line 53
    if-eqz v7, :cond_4

    .line 54
    .line 55
    const/16 v7, 0x100

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_4
    const/16 v7, 0x80

    .line 59
    .line 60
    :goto_3
    or-int/2addr v1, v7

    .line 61
    and-int/lit16 v7, v1, 0x93

    .line 62
    .line 63
    const/16 v8, 0x92

    .line 64
    .line 65
    const/4 v9, 0x0

    .line 66
    const/4 v10, 0x1

    .line 67
    if-eq v7, v8, :cond_5

    .line 68
    .line 69
    move v7, v10

    .line 70
    goto :goto_4

    .line 71
    :cond_5
    move v7, v9

    .line 72
    :goto_4
    and-int/2addr v1, v10

    .line 73
    invoke-virtual {v0, v1, v7}, Ll2/t;->O(IZ)Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    if-eqz v1, :cond_a

    .line 78
    .line 79
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 80
    .line 81
    .line 82
    and-int/lit8 v1, p6, 0x1

    .line 83
    .line 84
    if-eqz v1, :cond_8

    .line 85
    .line 86
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-eqz v1, :cond_6

    .line 91
    .line 92
    goto :goto_5

    .line 93
    :cond_6
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 94
    .line 95
    .line 96
    move v1, p2

    .line 97
    :cond_7
    move-wide v5, p3

    .line 98
    goto :goto_7

    .line 99
    :cond_8
    :goto_5
    if-eqz v3, :cond_9

    .line 100
    .line 101
    sget v1, Lk2/c0;->b:F

    .line 102
    .line 103
    goto :goto_6

    .line 104
    :cond_9
    move v1, p2

    .line 105
    :goto_6
    and-int/lit8 v3, p7, 0x4

    .line 106
    .line 107
    if-eqz v3, :cond_7

    .line 108
    .line 109
    sget-object v3, Lk2/c0;->a:Lk2/l;

    .line 110
    .line 111
    invoke-static {v3, v0}, Lh2/g1;->d(Lk2/l;Ll2/o;)J

    .line 112
    .line 113
    .line 114
    move-result-wide v3

    .line 115
    move-wide v5, v3

    .line 116
    :goto_7
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 117
    .line 118
    .line 119
    const/high16 v3, 0x3f800000    # 1.0f

    .line 120
    .line 121
    invoke-static {p1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v3

    .line 125
    invoke-static {v3, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 130
    .line 131
    invoke-static {v3, v5, v6, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 132
    .line 133
    .line 134
    move-result-object v3

    .line 135
    invoke-static {v3, v0, v9}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 136
    .line 137
    .line 138
    move v3, v1

    .line 139
    move-wide v4, v5

    .line 140
    goto :goto_8

    .line 141
    :cond_a
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 142
    .line 143
    .line 144
    move v3, p2

    .line 145
    move-wide v4, p3

    .line 146
    :goto_8
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 147
    .line 148
    .line 149
    move-result-object v8

    .line 150
    if-eqz v8, :cond_b

    .line 151
    .line 152
    new-instance v0, Lh2/ya;

    .line 153
    .line 154
    move-object v1, p0

    .line 155
    move-object v2, p1

    .line 156
    move/from16 v6, p6

    .line 157
    .line 158
    move/from16 v7, p7

    .line 159
    .line 160
    invoke-direct/range {v0 .. v7}, Lh2/ya;-><init>(Lh2/za;Lx2/s;FJII)V

    .line 161
    .line 162
    .line 163
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 164
    .line 165
    :cond_b
    return-void
.end method

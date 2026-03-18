.class public abstract Lh2/q6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget v0, Lk2/y;->a:F

    .line 2
    .line 3
    sput v0, Lh2/q6;->a:F

    .line 4
    .line 5
    const/16 v0, 0x8

    .line 6
    .line 7
    int-to-float v0, v0

    .line 8
    sput v0, Lh2/q6;->b:F

    .line 9
    .line 10
    new-instance v0, Lgz0/e0;

    .line 11
    .line 12
    const/16 v1, 0x11

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Ll2/e0;

    .line 18
    .line 19
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 20
    .line 21
    .line 22
    sput-object v1, Lh2/q6;->c:Ll2/e0;

    .line 23
    .line 24
    return-void
.end method

.method public static final a(Lx2/s;JJFLk1/q1;Lt2/b;Ll2/o;I)V
    .locals 12

    .line 1
    move-object/from16 v9, p8

    .line 2
    .line 3
    check-cast v9, Ll2/t;

    .line 4
    .line 5
    const v0, 0x3ed4477e

    .line 6
    .line 7
    .line 8
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v9, p1, p2}, Ll2/t;->f(J)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v1, 0x20

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    move v0, v1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/16 v0, 0x10

    .line 22
    .line 23
    :goto_0
    or-int v0, p9, v0

    .line 24
    .line 25
    or-int/lit16 v0, v0, 0x2080

    .line 26
    .line 27
    const v4, 0x12493

    .line 28
    .line 29
    .line 30
    and-int/2addr v4, v0

    .line 31
    const v5, 0x12492

    .line 32
    .line 33
    .line 34
    const/4 v10, 0x0

    .line 35
    const/4 v6, 0x1

    .line 36
    if-eq v4, v5, :cond_1

    .line 37
    .line 38
    move v4, v6

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move v4, v10

    .line 41
    :goto_1
    and-int/2addr v0, v6

    .line 42
    invoke-virtual {v9, v0, v4}, Ll2/t;->O(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eqz v0, :cond_4

    .line 47
    .line 48
    invoke-virtual {v9}, Ll2/t;->T()V

    .line 49
    .line 50
    .line 51
    and-int/lit8 v0, p9, 0x1

    .line 52
    .line 53
    if-eqz v0, :cond_3

    .line 54
    .line 55
    invoke-virtual {v9}, Ll2/t;->y()Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_2

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_2
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 63
    .line 64
    .line 65
    move-wide v4, p3

    .line 66
    move-object/from16 v7, p6

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_3
    :goto_2
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 70
    .line 71
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    check-cast v0, Lh2/f1;

    .line 76
    .line 77
    invoke-static {v0, p1, p2}, Lh2/g1;->a(Lh2/f1;J)J

    .line 78
    .line 79
    .line 80
    move-result-wide v4

    .line 81
    sget v0, Lh2/o6;->a:I

    .line 82
    .line 83
    invoke-static {v9}, Li2/a1;->l(Ll2/o;)Lk1/l1;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    sget v6, Lk1/d;->h:I

    .line 88
    .line 89
    or-int/2addr v1, v6

    .line 90
    new-instance v6, Lk1/v0;

    .line 91
    .line 92
    invoke-direct {v6, v0, v1}, Lk1/v0;-><init>(Lk1/q1;I)V

    .line 93
    .line 94
    .line 95
    move-object v7, v6

    .line 96
    :goto_3
    invoke-virtual {v9}, Ll2/t;->r()V

    .line 97
    .line 98
    .line 99
    sget-object v0, Lh2/q6;->c:Ll2/e0;

    .line 100
    .line 101
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    move-object v11, v0

    .line 106
    check-cast v11, Lh2/i4;

    .line 107
    .line 108
    new-instance v0, Lh2/r6;

    .line 109
    .line 110
    move-object v1, p0

    .line 111
    move-wide v2, p1

    .line 112
    move/from16 v6, p5

    .line 113
    .line 114
    move-object/from16 v8, p7

    .line 115
    .line 116
    invoke-direct/range {v0 .. v8}, Lh2/r6;-><init>(Lx2/s;JJFLk1/q1;Lt2/b;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v11, v0, v9, v10}, Lh2/i4;->a(Lh2/r6;Ll2/o;I)V

    .line 120
    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_4
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 124
    .line 125
    .line 126
    move-wide v4, p3

    .line 127
    move-object/from16 v7, p6

    .line 128
    .line 129
    :goto_4
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 130
    .line 131
    .line 132
    move-result-object v10

    .line 133
    if-eqz v10, :cond_5

    .line 134
    .line 135
    new-instance v0, Lh2/p6;

    .line 136
    .line 137
    move-object v1, p0

    .line 138
    move-wide v2, p1

    .line 139
    move/from16 v6, p5

    .line 140
    .line 141
    move-object/from16 v8, p7

    .line 142
    .line 143
    move/from16 v9, p9

    .line 144
    .line 145
    invoke-direct/range {v0 .. v9}, Lh2/p6;-><init>(Lx2/s;JJFLk1/q1;Lt2/b;I)V

    .line 146
    .line 147
    .line 148
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 149
    .line 150
    :cond_5
    return-void
.end method

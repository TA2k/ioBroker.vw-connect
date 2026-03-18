.class public abstract Lt1/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x19

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lt1/b;->a:F

    .line 5
    .line 6
    const/high16 v1, 0x40000000    # 2.0f

    .line 7
    .line 8
    mul-float/2addr v0, v1

    .line 9
    const v1, 0x401a827a

    .line 10
    .line 11
    .line 12
    div-float/2addr v0, v1

    .line 13
    sput v0, Lt1/b;->b:F

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Le2/l;Lx2/s;JLl2/o;I)V
    .locals 9

    .line 1
    check-cast p4, Ll2/t;

    .line 2
    .line 3
    const v0, 0x69deb1cb

    .line 4
    .line 5
    .line 6
    invoke-virtual {p4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x4

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    move v0, v1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v0, 0x2

    .line 19
    :goto_0
    or-int/2addr v0, p5

    .line 20
    invoke-virtual {p4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    const/16 v2, 0x20

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/16 v2, 0x10

    .line 30
    .line 31
    :goto_1
    or-int/2addr v0, v2

    .line 32
    or-int/lit16 v0, v0, 0x80

    .line 33
    .line 34
    and-int/lit16 v2, v0, 0x93

    .line 35
    .line 36
    const/16 v3, 0x92

    .line 37
    .line 38
    const/4 v4, 0x0

    .line 39
    const/4 v5, 0x1

    .line 40
    if-eq v2, v3, :cond_2

    .line 41
    .line 42
    move v2, v5

    .line 43
    goto :goto_2

    .line 44
    :cond_2
    move v2, v4

    .line 45
    :goto_2
    and-int/lit8 v3, v0, 0x1

    .line 46
    .line 47
    invoke-virtual {p4, v3, v2}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    if-eqz v2, :cond_8

    .line 52
    .line 53
    invoke-virtual {p4}, Ll2/t;->T()V

    .line 54
    .line 55
    .line 56
    and-int/lit8 v2, p5, 0x1

    .line 57
    .line 58
    if-eqz v2, :cond_4

    .line 59
    .line 60
    invoke-virtual {p4}, Ll2/t;->y()Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-eqz v2, :cond_3

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_3
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 68
    .line 69
    .line 70
    and-int/lit16 v0, v0, -0x381

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_4
    :goto_3
    and-int/lit16 v0, v0, -0x381

    .line 74
    .line 75
    const-wide p2, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    :goto_4
    invoke-virtual {p4}, Ll2/t;->r()V

    .line 81
    .line 82
    .line 83
    and-int/lit8 v0, v0, 0xe

    .line 84
    .line 85
    if-eq v0, v1, :cond_5

    .line 86
    .line 87
    move v5, v4

    .line 88
    :cond_5
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    if-nez v5, :cond_6

    .line 93
    .line 94
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 95
    .line 96
    if-ne v1, v2, :cond_7

    .line 97
    .line 98
    :cond_6
    new-instance v1, Lpg/m;

    .line 99
    .line 100
    const/16 v2, 0xd

    .line 101
    .line 102
    invoke-direct {v1, p0, v2}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {p4, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    :cond_7
    check-cast v1, Lay0/k;

    .line 109
    .line 110
    invoke-static {p1, v4, v1}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    sget-object v2, Lx2/c;->e:Lx2/j;

    .line 115
    .line 116
    new-instance v3, Lh2/t3;

    .line 117
    .line 118
    invoke-direct {v3, p2, p3, v1}, Lh2/t3;-><init>(JLx2/s;)V

    .line 119
    .line 120
    .line 121
    const v1, -0x628ed1fe

    .line 122
    .line 123
    .line 124
    invoke-static {v1, p4, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    or-int/lit16 v0, v0, 0x1b0

    .line 129
    .line 130
    invoke-static {p0, v2, v1, p4, v0}, Lkp/o;->a(Le2/l;Lx2/e;Lt2/b;Ll2/o;I)V

    .line 131
    .line 132
    .line 133
    :goto_5
    move-wide v6, p2

    .line 134
    goto :goto_6

    .line 135
    :cond_8
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 136
    .line 137
    .line 138
    goto :goto_5

    .line 139
    :goto_6
    invoke-virtual {p4}, Ll2/t;->s()Ll2/u1;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    if-eqz p2, :cond_9

    .line 144
    .line 145
    new-instance v3, Li91/f2;

    .line 146
    .line 147
    move-object v4, p0

    .line 148
    move-object v5, p1

    .line 149
    move v8, p5

    .line 150
    invoke-direct/range {v3 .. v8}, Li91/f2;-><init>(Le2/l;Lx2/s;JI)V

    .line 151
    .line 152
    .line 153
    iput-object v3, p2, Ll2/u1;->d:Lay0/n;

    .line 154
    .line 155
    :cond_9
    return-void
.end method

.method public static final b(IILl2/o;Lx2/s;)V
    .locals 5

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x29616e63

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p1, 0x1

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    or-int/lit8 v2, p0, 0x6

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    invoke-virtual {p2, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    const/4 v2, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    move v2, v1

    .line 26
    :goto_0
    or-int/2addr v2, p0

    .line 27
    :goto_1
    and-int/lit8 v3, v2, 0x3

    .line 28
    .line 29
    const/4 v4, 0x1

    .line 30
    if-eq v3, v1, :cond_2

    .line 31
    .line 32
    move v1, v4

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    const/4 v1, 0x0

    .line 35
    :goto_2
    and-int/2addr v2, v4

    .line 36
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_4

    .line 41
    .line 42
    if-eqz v0, :cond_3

    .line 43
    .line 44
    sget-object p3, Lx2/p;->b:Lx2/p;

    .line 45
    .line 46
    :cond_3
    sget v0, Lt1/b;->b:F

    .line 47
    .line 48
    sget v1, Lt1/b;->a:F

    .line 49
    .line 50
    invoke-static {p3, v0, v1}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sget-object v1, Lt1/a;->d:Lt1/a;

    .line 55
    .line 56
    invoke-static {v0, v1}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    invoke-static {p2, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 61
    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 65
    .line 66
    .line 67
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    if-eqz p2, :cond_5

    .line 72
    .line 73
    new-instance v0, Ln70/d0;

    .line 74
    .line 75
    invoke-direct {v0, p3, p0, p1}, Ln70/d0;-><init>(Lx2/s;II)V

    .line 76
    .line 77
    .line 78
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 79
    .line 80
    :cond_5
    return-void
.end method

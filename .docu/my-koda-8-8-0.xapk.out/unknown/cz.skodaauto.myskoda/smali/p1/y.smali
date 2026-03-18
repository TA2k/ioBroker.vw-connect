.class public abstract Lp1/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:Lp1/o;

.field public static final c:Lp1/x;


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    const/16 v0, 0x38

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lp1/y;->a:F

    .line 5
    .line 6
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 7
    .line 8
    sget-object v8, Lh1/m;->c:Lh1/m;

    .line 9
    .line 10
    new-instance v9, Lp1/w;

    .line 11
    .line 12
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 16
    .line 17
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 18
    .line 19
    .line 20
    move-result-object v10

    .line 21
    new-instance v1, Lp1/o;

    .line 22
    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v10}, Lp1/o;-><init>(IIIIIILh1/n;Lt3/r0;Lvy0/b0;)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Lp1/y;->b:Lp1/o;

    .line 33
    .line 34
    new-instance v0, Lp1/x;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lp1/y;->c:Lp1/x;

    .line 40
    .line 41
    return-void
.end method

.method public static final a(Lp1/o;I)J
    .locals 8

    .line 1
    iget v0, p0, Lp1/o;->c:I

    .line 2
    .line 3
    iget v1, p0, Lp1/o;->b:I

    .line 4
    .line 5
    add-int/2addr v1, v0

    .line 6
    int-to-long v2, p1

    .line 7
    int-to-long v4, v1

    .line 8
    mul-long/2addr v2, v4

    .line 9
    iget p1, p0, Lp1/o;->f:I

    .line 10
    .line 11
    neg-int p1, p1

    .line 12
    int-to-long v4, p1

    .line 13
    add-long/2addr v2, v4

    .line 14
    iget v1, p0, Lp1/o;->d:I

    .line 15
    .line 16
    int-to-long v4, v1

    .line 17
    add-long/2addr v2, v4

    .line 18
    int-to-long v4, v0

    .line 19
    sub-long/2addr v2, v4

    .line 20
    iget-object v0, p0, Lp1/o;->e:Lg1/w1;

    .line 21
    .line 22
    sget-object v4, Lg1/w1;->e:Lg1/w1;

    .line 23
    .line 24
    if-ne v0, v4, :cond_0

    .line 25
    .line 26
    invoke-virtual {p0}, Lp1/o;->e()J

    .line 27
    .line 28
    .line 29
    move-result-wide v4

    .line 30
    const/16 v0, 0x20

    .line 31
    .line 32
    shr-long/2addr v4, v0

    .line 33
    :goto_0
    long-to-int v0, v4

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    invoke-virtual {p0}, Lp1/o;->e()J

    .line 36
    .line 37
    .line 38
    move-result-wide v4

    .line 39
    const-wide v6, 0xffffffffL

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    and-long/2addr v4, v6

    .line 45
    goto :goto_0

    .line 46
    :goto_1
    iget-object v4, p0, Lp1/o;->o:Lh1/n;

    .line 47
    .line 48
    iget p0, p0, Lp1/o;->b:I

    .line 49
    .line 50
    invoke-interface {v4, v0, p0, p1, v1}, Lh1/n;->a(IIII)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    const/4 p1, 0x0

    .line 55
    invoke-static {p0, p1, v0}, Lkp/r9;->e(III)I

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    sub-int/2addr v0, p0

    .line 60
    int-to-long p0, v0

    .line 61
    sub-long/2addr v2, p0

    .line 62
    const-wide/16 p0, 0x0

    .line 63
    .line 64
    cmp-long v0, v2, p0

    .line 65
    .line 66
    if-gez v0, :cond_1

    .line 67
    .line 68
    return-wide p0

    .line 69
    :cond_1
    return-wide v2
.end method

.method public static final b(ILay0/a;Ll2/o;II)Lp1/b;
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    and-int/2addr p4, v0

    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz p4, :cond_0

    .line 5
    .line 6
    move p0, v1

    .line 7
    :cond_0
    new-array p4, v1, [Ljava/lang/Object;

    .line 8
    .line 9
    sget-object v2, Lp1/b;->J:Lu2/l;

    .line 10
    .line 11
    and-int/lit8 v3, p3, 0xe

    .line 12
    .line 13
    xor-int/lit8 v3, v3, 0x6

    .line 14
    .line 15
    const/4 v4, 0x4

    .line 16
    if-le v3, v4, :cond_1

    .line 17
    .line 18
    move-object v3, p2

    .line 19
    check-cast v3, Ll2/t;

    .line 20
    .line 21
    invoke-virtual {v3, p0}, Ll2/t;->e(I)Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-nez v3, :cond_2

    .line 26
    .line 27
    :cond_1
    and-int/lit8 v3, p3, 0x6

    .line 28
    .line 29
    if-ne v3, v4, :cond_3

    .line 30
    .line 31
    :cond_2
    move v3, v0

    .line 32
    goto :goto_0

    .line 33
    :cond_3
    move v3, v1

    .line 34
    :goto_0
    and-int/lit8 v4, p3, 0x70

    .line 35
    .line 36
    xor-int/lit8 v4, v4, 0x30

    .line 37
    .line 38
    const/16 v5, 0x20

    .line 39
    .line 40
    if-le v4, v5, :cond_4

    .line 41
    .line 42
    move-object v4, p2

    .line 43
    check-cast v4, Ll2/t;

    .line 44
    .line 45
    const/4 v6, 0x0

    .line 46
    invoke-virtual {v4, v6}, Ll2/t;->d(F)Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    if-nez v4, :cond_5

    .line 51
    .line 52
    :cond_4
    and-int/lit8 v4, p3, 0x30

    .line 53
    .line 54
    if-ne v4, v5, :cond_6

    .line 55
    .line 56
    :cond_5
    move v4, v0

    .line 57
    goto :goto_1

    .line 58
    :cond_6
    move v4, v1

    .line 59
    :goto_1
    or-int/2addr v3, v4

    .line 60
    and-int/lit16 v4, p3, 0x380

    .line 61
    .line 62
    xor-int/lit16 v4, v4, 0x180

    .line 63
    .line 64
    const/16 v5, 0x100

    .line 65
    .line 66
    if-le v4, v5, :cond_7

    .line 67
    .line 68
    move-object v4, p2

    .line 69
    check-cast v4, Ll2/t;

    .line 70
    .line 71
    invoke-virtual {v4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-nez v4, :cond_9

    .line 76
    .line 77
    :cond_7
    and-int/lit16 p3, p3, 0x180

    .line 78
    .line 79
    if-ne p3, v5, :cond_8

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_8
    move v0, v1

    .line 83
    :cond_9
    :goto_2
    or-int p3, v3, v0

    .line 84
    .line 85
    check-cast p2, Ll2/t;

    .line 86
    .line 87
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    if-nez p3, :cond_a

    .line 92
    .line 93
    sget-object p3, Ll2/n;->a:Ll2/x0;

    .line 94
    .line 95
    if-ne v0, p3, :cond_b

    .line 96
    .line 97
    :cond_a
    new-instance v0, Lba0/h;

    .line 98
    .line 99
    const/4 p3, 0x6

    .line 100
    invoke-direct {v0, p0, p1, p3}, Lba0/h;-><init>(ILjava/lang/Object;I)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p2, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    :cond_b
    check-cast v0, Lay0/a;

    .line 107
    .line 108
    invoke-static {p4, v2, v0, p2, v1}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    check-cast p0, Lp1/b;

    .line 113
    .line 114
    iget-object p2, p0, Lp1/b;->I:Ll2/j1;

    .line 115
    .line 116
    invoke-virtual {p2, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    return-object p0
.end method

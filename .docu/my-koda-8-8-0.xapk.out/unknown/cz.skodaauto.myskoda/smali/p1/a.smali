.class public final Lp1/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo3/a;


# instance fields
.field public final d:Lp1/v;


# direct methods
.method public constructor <init>(Lp1/v;)V
    .locals 1

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lp1/a;->d:Lp1/v;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final P(IJJ)J
    .locals 0

    .line 1
    const/4 p0, 0x2

    .line 2
    if-ne p1, p0, :cond_1

    .line 3
    .line 4
    sget-object p0, Lg1/w1;->d:Lg1/w1;

    .line 5
    .line 6
    const/16 p0, 0x20

    .line 7
    .line 8
    shr-long p0, p4, p0

    .line 9
    .line 10
    long-to-int p0, p0

    .line 11
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    const/4 p1, 0x0

    .line 16
    cmpg-float p0, p0, p1

    .line 17
    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/util/concurrent/CancellationException;

    .line 22
    .line 23
    const-string p1, "Scroll cancelled"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    :goto_0
    const-wide/16 p0, 0x0

    .line 30
    .line 31
    return-wide p0
.end method

.method public final i(JJLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    sget-object p0, Lg1/w1;->d:Lg1/w1;

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    const/4 p1, 0x1

    .line 7
    invoke-static {p3, p4, p1, p0, p0}, Lt4/q;->a(JIFF)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    new-instance p2, Lt4/q;

    .line 12
    .line 13
    invoke-direct {p2, p0, p1}, Lt4/q;-><init>(J)V

    .line 14
    .line 15
    .line 16
    return-object p2
.end method

.method public final z(IJ)J
    .locals 6

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-ne p1, v0, :cond_1

    .line 5
    .line 6
    iget-object p0, p0, Lp1/a;->d:Lp1/v;

    .line 7
    .line 8
    iget-object p1, p0, Lp1/v;->d:Lh8/o;

    .line 9
    .line 10
    iget-object v0, p0, Lp1/v;->d:Lh8/o;

    .line 11
    .line 12
    iget-object p1, p1, Lh8/o;->d:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Ll2/f1;

    .line 15
    .line 16
    invoke-virtual {p1}, Ll2/f1;->o()F

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    float-to-double v1, p1

    .line 25
    const-wide v3, 0x3eb0c6f7a0b5ed8dL    # 1.0E-6

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    cmpl-double p1, v1, v3

    .line 31
    .line 32
    if-lez p1, :cond_1

    .line 33
    .line 34
    iget-object p1, v0, Lh8/o;->d:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p1, Ll2/f1;

    .line 37
    .line 38
    invoke-virtual {p1}, Ll2/f1;->o()F

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    invoke-virtual {p0}, Lp1/v;->n()I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    int-to-float v1, v1

    .line 47
    mul-float/2addr p1, v1

    .line 48
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iget v1, v1, Lp1/o;->b:I

    .line 53
    .line 54
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    iget v2, v2, Lp1/o;->c:I

    .line 59
    .line 60
    add-int/2addr v1, v2

    .line 61
    int-to-float v1, v1

    .line 62
    iget-object v2, v0, Lh8/o;->d:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v2, Ll2/f1;

    .line 65
    .line 66
    invoke-virtual {v2}, Ll2/f1;->o()F

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    invoke-static {v2}, Ljava/lang/Math;->signum(F)F

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    neg-float v2, v2

    .line 75
    mul-float/2addr v1, v2

    .line 76
    add-float/2addr v1, p1

    .line 77
    iget-object v0, v0, Lh8/o;->d:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v0, Ll2/f1;

    .line 80
    .line 81
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    const/4 v2, 0x0

    .line 86
    cmpl-float v0, v0, v2

    .line 87
    .line 88
    if-lez v0, :cond_0

    .line 89
    .line 90
    move v5, v1

    .line 91
    move v1, p1

    .line 92
    move p1, v5

    .line 93
    :cond_0
    const/16 v0, 0x20

    .line 94
    .line 95
    shr-long v2, p2, v0

    .line 96
    .line 97
    long-to-int v2, v2

    .line 98
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    invoke-static {v2, p1, v1}, Lkp/r9;->d(FFF)F

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    neg-float p1, p1

    .line 107
    iget-object p0, p0, Lp1/v;->k:Lg1/f0;

    .line 108
    .line 109
    invoke-virtual {p0, p1}, Lg1/f0;->e(F)F

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    neg-float p0, p0

    .line 114
    sget-object p1, Lg1/w1;->d:Lg1/w1;

    .line 115
    .line 116
    const-wide v1, 0xffffffffL

    .line 117
    .line 118
    .line 119
    .line 120
    .line 121
    and-long p1, p2, v1

    .line 122
    .line 123
    long-to-int p1, p1

    .line 124
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    int-to-long p2, p0

    .line 133
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    int-to-long p0, p0

    .line 138
    shl-long/2addr p2, v0

    .line 139
    and-long/2addr p0, v1

    .line 140
    or-long/2addr p0, p2

    .line 141
    return-wide p0

    .line 142
    :cond_1
    const-wide/16 p0, 0x0

    .line 143
    .line 144
    return-wide p0
.end method

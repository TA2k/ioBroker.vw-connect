.class public abstract Ljr/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-wide/high16 v0, 0x4000000000000000L    # 2.0

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Math;->log(D)D

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static a(D)Z
    .locals 2

    .line 1
    invoke-static {p0, p1}, Llp/nc;->c(D)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    const-wide/16 v0, 0x0

    .line 8
    .line 9
    cmpl-double v0, p0, v0

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/nc;->b(D)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    invoke-static {v0, v1}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    rsub-int/lit8 v0, v0, 0x34

    .line 22
    .line 23
    invoke-static {p0, p1}, Ljava/lang/Math;->getExponent(D)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-gt v0, p0, :cond_1

    .line 28
    .line 29
    :cond_0
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_1
    const/4 p0, 0x0

    .line 32
    return p0
.end method

.method public static b(D)Z
    .locals 4

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmpl-double v0, p0, v0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-lez v0, :cond_0

    .line 7
    .line 8
    invoke-static {p0, p1}, Llp/nc;->c(D)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-static {p0, p1}, Llp/nc;->b(D)J

    .line 15
    .line 16
    .line 17
    move-result-wide p0

    .line 18
    const-wide/16 v2, 0x1

    .line 19
    .line 20
    sub-long v2, p0, v2

    .line 21
    .line 22
    and-long/2addr p0, v2

    .line 23
    const-wide/16 v2, 0x0

    .line 24
    .line 25
    cmp-long p0, p0, v2

    .line 26
    .line 27
    if-nez p0, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_0
    return v1
.end method

.method public static c(D)I
    .locals 6

    .line 1
    sget-object v0, Ljava/math/RoundingMode;->CEILING:Ljava/math/RoundingMode;

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    cmpl-double v1, p0, v1

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x1

    .line 9
    if-lez v1, :cond_0

    .line 10
    .line 11
    invoke-static {p0, p1}, Llp/nc;->c(D)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    move v1, v3

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v1, v2

    .line 20
    :goto_0
    const-string v4, "x must be positive and finite"

    .line 21
    .line 22
    invoke-static {v1, v4}, Lkp/i9;->c(ZLjava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0, p1}, Ljava/lang/Math;->getExponent(D)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-static {p0, p1}, Ljava/lang/Math;->getExponent(D)I

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    const/16 v5, -0x3fe

    .line 34
    .line 35
    if-lt v4, v5, :cond_6

    .line 36
    .line 37
    sget-object v4, Ljr/a;->a:[I

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    aget v0, v4, v0

    .line 44
    .line 45
    packed-switch v0, :pswitch_data_0

    .line 46
    .line 47
    .line 48
    new-instance p0, Ljava/lang/AssertionError;

    .line 49
    .line 50
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :pswitch_0
    invoke-static {p0, p1}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 55
    .line 56
    .line 57
    move-result-wide p0

    .line 58
    const-wide v4, 0xfffffffffffffL

    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    and-long/2addr p0, v4

    .line 64
    const-wide/high16 v4, 0x3ff0000000000000L    # 1.0

    .line 65
    .line 66
    or-long/2addr p0, v4

    .line 67
    invoke-static {p0, p1}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 68
    .line 69
    .line 70
    move-result-wide p0

    .line 71
    mul-double/2addr p0, p0

    .line 72
    const-wide/high16 v4, 0x4000000000000000L    # 2.0

    .line 73
    .line 74
    cmpl-double p0, p0, v4

    .line 75
    .line 76
    if-lez p0, :cond_3

    .line 77
    .line 78
    move v2, v3

    .line 79
    goto :goto_2

    .line 80
    :pswitch_1
    if-ltz v1, :cond_1

    .line 81
    .line 82
    move v2, v3

    .line 83
    :cond_1
    invoke-static {p0, p1}, Ljr/b;->b(D)Z

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    :goto_1
    xor-int/2addr p0, v3

    .line 88
    and-int/2addr v2, p0

    .line 89
    goto :goto_2

    .line 90
    :pswitch_2
    if-gez v1, :cond_2

    .line 91
    .line 92
    move v2, v3

    .line 93
    :cond_2
    invoke-static {p0, p1}, Ljr/b;->b(D)Z

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    goto :goto_1

    .line 98
    :pswitch_3
    invoke-static {p0, p1}, Ljr/b;->b(D)Z

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    xor-int/lit8 v2, p0, 0x1

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :pswitch_4
    invoke-static {p0, p1}, Ljr/b;->b(D)Z

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    if-eqz p0, :cond_5

    .line 110
    .line 111
    :cond_3
    :goto_2
    :pswitch_5
    if-eqz v2, :cond_4

    .line 112
    .line 113
    add-int/2addr v1, v3

    .line 114
    :cond_4
    return v1

    .line 115
    :cond_5
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 116
    .line 117
    const-string p1, "mode was UNNECESSARY, but rounding was necessary"

    .line 118
    .line 119
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_6
    const-wide/high16 v0, 0x4330000000000000L    # 4.503599627370496E15

    .line 124
    .line 125
    mul-double/2addr p0, v0

    .line 126
    invoke-static {p0, p1}, Ljr/b;->c(D)I

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    add-int/lit8 p0, p0, -0x34

    .line 131
    .line 132
    return p0

    .line 133
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_5
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

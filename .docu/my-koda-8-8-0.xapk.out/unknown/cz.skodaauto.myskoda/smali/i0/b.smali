.class public abstract Li0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Landroid/util/Rational;

.field public static final b:Landroid/util/Rational;

.field public static final c:Landroid/util/Rational;

.field public static final d:Landroid/util/Rational;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Landroid/util/Rational;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    const/4 v2, 0x3

    .line 5
    invoke-direct {v0, v1, v2}, Landroid/util/Rational;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Li0/b;->a:Landroid/util/Rational;

    .line 9
    .line 10
    new-instance v0, Landroid/util/Rational;

    .line 11
    .line 12
    invoke-direct {v0, v2, v1}, Landroid/util/Rational;-><init>(II)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Li0/b;->b:Landroid/util/Rational;

    .line 16
    .line 17
    new-instance v0, Landroid/util/Rational;

    .line 18
    .line 19
    const/16 v1, 0x10

    .line 20
    .line 21
    const/16 v2, 0x9

    .line 22
    .line 23
    invoke-direct {v0, v1, v2}, Landroid/util/Rational;-><init>(II)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Li0/b;->c:Landroid/util/Rational;

    .line 27
    .line 28
    new-instance v0, Landroid/util/Rational;

    .line 29
    .line 30
    invoke-direct {v0, v2, v1}, Landroid/util/Rational;-><init>(II)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Li0/b;->d:Landroid/util/Rational;

    .line 34
    .line 35
    return-void
.end method

.method public static a(Landroid/util/Rational;Landroid/util/Size;)Z
    .locals 5

    .line 1
    sget-object v0, Lo0/a;->b:Landroid/util/Size;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez p0, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    new-instance v2, Landroid/util/Rational;

    .line 8
    .line 9
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    invoke-direct {v2, v3, v4}, Landroid/util/Rational;-><init>(II)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, v2}, Landroid/util/Rational;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    mul-int/2addr v3, v2

    .line 36
    invoke-static {v0}, Lo0/a;->a(Landroid/util/Size;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-lt v3, v0, :cond_5

    .line 41
    .line 42
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    new-instance v2, Landroid/util/Rational;

    .line 51
    .line 52
    invoke-virtual {p0}, Landroid/util/Rational;->getDenominator()I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    invoke-virtual {p0}, Landroid/util/Rational;->getNumerator()I

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    invoke-direct {v2, v3, v4}, Landroid/util/Rational;-><init>(II)V

    .line 61
    .line 62
    .line 63
    rem-int/lit8 v3, v0, 0x10

    .line 64
    .line 65
    if-nez v3, :cond_3

    .line 66
    .line 67
    rem-int/lit8 v4, p1, 0x10

    .line 68
    .line 69
    if-nez v4, :cond_3

    .line 70
    .line 71
    add-int/lit8 v3, p1, -0x10

    .line 72
    .line 73
    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    invoke-static {v3, v0, p0}, Li0/b;->b(IILandroid/util/Rational;)Z

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-nez p0, :cond_2

    .line 82
    .line 83
    add-int/lit8 v0, v0, -0x10

    .line 84
    .line 85
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    invoke-static {p0, p1, v2}, Li0/b;->b(IILandroid/util/Rational;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-eqz p0, :cond_5

    .line 94
    .line 95
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 96
    return p0

    .line 97
    :cond_3
    if-nez v3, :cond_4

    .line 98
    .line 99
    invoke-static {p1, v0, p0}, Li0/b;->b(IILandroid/util/Rational;)Z

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    return p0

    .line 104
    :cond_4
    rem-int/lit8 p0, p1, 0x10

    .line 105
    .line 106
    if-nez p0, :cond_5

    .line 107
    .line 108
    invoke-static {v0, p1, v2}, Li0/b;->b(IILandroid/util/Rational;)Z

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    return p0

    .line 113
    :cond_5
    :goto_1
    return v1
.end method

.method public static b(IILandroid/util/Rational;)Z
    .locals 7

    .line 1
    rem-int/lit8 v0, p1, 0x10

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    move v0, v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v2

    .line 10
    :goto_0
    invoke-static {v0}, Ljp/ed;->a(Z)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p2}, Landroid/util/Rational;->getNumerator()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    mul-int/2addr v0, p0

    .line 18
    int-to-double v3, v0

    .line 19
    invoke-virtual {p2}, Landroid/util/Rational;->getDenominator()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    int-to-double v5, p0

    .line 24
    div-double/2addr v3, v5

    .line 25
    add-int/lit8 p0, p1, -0x10

    .line 26
    .line 27
    invoke-static {v2, p0}, Ljava/lang/Math;->max(II)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    int-to-double v5, p0

    .line 32
    cmpl-double p0, v3, v5

    .line 33
    .line 34
    if-lez p0, :cond_1

    .line 35
    .line 36
    add-int/lit8 p1, p1, 0x10

    .line 37
    .line 38
    int-to-double p0, p1

    .line 39
    cmpg-double p0, v3, p0

    .line 40
    .line 41
    if-gez p0, :cond_1

    .line 42
    .line 43
    return v1

    .line 44
    :cond_1
    return v2
.end method

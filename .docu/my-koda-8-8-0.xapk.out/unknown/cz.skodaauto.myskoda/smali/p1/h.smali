.class public final Lp1/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/u;


# instance fields
.field public final b:Lp1/v;

.field public final c:Lg1/u;


# direct methods
.method public constructor <init>(Lp1/v;Lg1/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp1/h;->b:Lp1/v;

    .line 5
    .line 6
    iput-object p2, p0, Lp1/h;->c:Lg1/u;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(FFF)F
    .locals 5

    .line 1
    iget-object v0, p0, Lp1/h;->c:Lg1/u;

    .line 2
    .line 3
    invoke-interface {v0, p1, p2, p3}, Lg1/u;->a(FFF)F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    cmpl-float v2, p1, v1

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v4, 0x1

    .line 12
    if-lez v2, :cond_0

    .line 13
    .line 14
    add-float/2addr p1, p2

    .line 15
    cmpl-float p1, p1, p3

    .line 16
    .line 17
    if-lez p1, :cond_1

    .line 18
    .line 19
    :goto_0
    move v3, v4

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    add-float/2addr p1, p2

    .line 22
    cmpg-float p1, p1, v1

    .line 23
    .line 24
    if-gtz p1, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    :goto_1
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    cmpg-float p1, p1, v1

    .line 32
    .line 33
    iget-object p0, p0, Lp1/h;->b:Lp1/v;

    .line 34
    .line 35
    if-nez p1, :cond_2

    .line 36
    .line 37
    goto :goto_4

    .line 38
    :cond_2
    if-eqz v3, :cond_5

    .line 39
    .line 40
    iget p1, p0, Lp1/v;->f:I

    .line 41
    .line 42
    int-to-float p1, p1

    .line 43
    const/4 p2, -0x1

    .line 44
    int-to-float p2, p2

    .line 45
    mul-float/2addr p1, p2

    .line 46
    :goto_2
    cmpl-float p2, v0, v1

    .line 47
    .line 48
    if-lez p2, :cond_3

    .line 49
    .line 50
    cmpg-float p2, p1, v0

    .line 51
    .line 52
    if-gez p2, :cond_3

    .line 53
    .line 54
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    int-to-float p2, p2

    .line 59
    add-float/2addr p1, p2

    .line 60
    goto :goto_2

    .line 61
    :cond_3
    :goto_3
    cmpg-float p2, v0, v1

    .line 62
    .line 63
    if-gez p2, :cond_4

    .line 64
    .line 65
    cmpl-float p2, p1, v0

    .line 66
    .line 67
    if-lez p2, :cond_4

    .line 68
    .line 69
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 70
    .line 71
    .line 72
    move-result p2

    .line 73
    int-to-float p2, p2

    .line 74
    sub-float/2addr p1, p2

    .line 75
    goto :goto_3

    .line 76
    :cond_4
    return p1

    .line 77
    :cond_5
    :goto_4
    iget p1, p0, Lp1/v;->f:I

    .line 78
    .line 79
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    int-to-double p1, p1

    .line 84
    const-wide v2, 0x3eb0c6f7a0b5ed8dL    # 1.0E-6

    .line 85
    .line 86
    .line 87
    .line 88
    .line 89
    cmpg-double p1, p1, v2

    .line 90
    .line 91
    if-gez p1, :cond_6

    .line 92
    .line 93
    return v1

    .line 94
    :cond_6
    iget p1, p0, Lp1/v;->f:I

    .line 95
    .line 96
    int-to-float p1, p1

    .line 97
    const/high16 p2, -0x40800000    # -1.0f

    .line 98
    .line 99
    mul-float/2addr p1, p2

    .line 100
    iget-object p2, p0, Lp1/v;->G:Ll2/j1;

    .line 101
    .line 102
    invoke-virtual {p2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    check-cast p2, Ljava/lang/Boolean;

    .line 107
    .line 108
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 109
    .line 110
    .line 111
    move-result p2

    .line 112
    if-eqz p2, :cond_7

    .line 113
    .line 114
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 115
    .line 116
    .line 117
    move-result p0

    .line 118
    int-to-float p0, p0

    .line 119
    add-float/2addr p1, p0

    .line 120
    :cond_7
    neg-float p0, p3

    .line 121
    invoke-static {p1, p0, p3}, Lkp/r9;->d(FFF)F

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    return p0
.end method

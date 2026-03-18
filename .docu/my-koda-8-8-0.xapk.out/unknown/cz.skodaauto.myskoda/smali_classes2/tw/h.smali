.class public final Ltw/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltw/l;


# instance fields
.field public final d:Ltw/g;

.field public e:F

.field public f:F


# direct methods
.method public constructor <init>(Ltw/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltw/h;->d:Ltw/g;

    .line 5
    .line 6
    const/high16 p1, 0x40800000    # 4.0f

    .line 7
    .line 8
    iput p1, p0, Ltw/h;->e:F

    .line 9
    .line 10
    const/high16 p1, 0x40000000    # 2.0f

    .line 11
    .line 12
    iput p1, p0, Ltw/h;->f:F

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lpw/f;Landroid/graphics/Path;FFFF)V
    .locals 5

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "path"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sub-float v0, p5, p3

    .line 12
    .line 13
    sub-float v1, p6, p4

    .line 14
    .line 15
    cmpl-float v2, v0, v1

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x0

    .line 19
    if-lez v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0, p1, v0}, Ltw/h;->b(Lpw/f;F)V

    .line 22
    .line 23
    .line 24
    move p1, v3

    .line 25
    :goto_0
    sub-float p5, v0, p1

    .line 26
    .line 27
    cmpl-float p5, p5, v3

    .line 28
    .line 29
    if-lez p5, :cond_3

    .line 30
    .line 31
    rem-int/lit8 p5, v4, 0x2

    .line 32
    .line 33
    if-nez p5, :cond_0

    .line 34
    .line 35
    add-float p5, p3, p1

    .line 36
    .line 37
    iget v1, p0, Ltw/h;->e:F

    .line 38
    .line 39
    add-float/2addr v1, p5

    .line 40
    invoke-virtual {p2, p5, p4}, Landroid/graphics/Path;->moveTo(FF)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p2, v1, p4}, Landroid/graphics/Path;->lineTo(FF)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p2, v1, p6}, Landroid/graphics/Path;->lineTo(FF)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2, p5, p6}, Landroid/graphics/Path;->lineTo(FF)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p2}, Landroid/graphics/Path;->close()V

    .line 53
    .line 54
    .line 55
    iget p5, p0, Ltw/h;->e:F

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_0
    iget p5, p0, Ltw/h;->f:F

    .line 59
    .line 60
    :goto_1
    add-float/2addr p1, p5

    .line 61
    add-int/lit8 v4, v4, 0x1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    invoke-virtual {p0, p1, v1}, Ltw/h;->b(Lpw/f;F)V

    .line 65
    .line 66
    .line 67
    move p1, v3

    .line 68
    :goto_2
    sub-float p6, v1, p1

    .line 69
    .line 70
    cmpl-float p6, p6, v3

    .line 71
    .line 72
    if-lez p6, :cond_3

    .line 73
    .line 74
    rem-int/lit8 p6, v4, 0x2

    .line 75
    .line 76
    if-nez p6, :cond_2

    .line 77
    .line 78
    add-float p6, p4, p1

    .line 79
    .line 80
    iget v0, p0, Ltw/h;->e:F

    .line 81
    .line 82
    add-float/2addr v0, p6

    .line 83
    invoke-virtual {p2, p3, p6}, Landroid/graphics/Path;->moveTo(FF)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p2, p5, p6}, Landroid/graphics/Path;->lineTo(FF)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p2, p5, v0}, Landroid/graphics/Path;->lineTo(FF)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {p2, p3, v0}, Landroid/graphics/Path;->lineTo(FF)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p2}, Landroid/graphics/Path;->close()V

    .line 96
    .line 97
    .line 98
    iget p6, p0, Ltw/h;->e:F

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_2
    iget p6, p0, Ltw/h;->f:F

    .line 102
    .line 103
    :goto_3
    add-float/2addr p1, p6

    .line 104
    add-int/lit8 v4, v4, 0x1

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_3
    return-void
.end method

.method public final b(Lpw/f;F)V
    .locals 5

    .line 1
    const/high16 v0, 0x40800000    # 4.0f

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lpw/f;->c(F)F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/high16 v1, 0x40000000    # 2.0f

    .line 8
    .line 9
    invoke-interface {p1, v1}, Lpw/f;->c(F)F

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    const/4 v1, 0x0

    .line 14
    cmpg-float v2, v0, v1

    .line 15
    .line 16
    if-nez v2, :cond_0

    .line 17
    .line 18
    cmpg-float v2, p1, v1

    .line 19
    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    iput p2, p0, Ltw/h;->e:F

    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    iget-object v2, p0, Ltw/h;->d:Ltw/g;

    .line 26
    .line 27
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    const/4 p2, 0x1

    .line 34
    if-ne v2, p2, :cond_1

    .line 35
    .line 36
    iput v0, p0, Ltw/h;->e:F

    .line 37
    .line 38
    iput p1, p0, Ltw/h;->f:F

    .line 39
    .line 40
    return-void

    .line 41
    :cond_1
    new-instance p0, La8/r0;

    .line 42
    .line 43
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_2
    add-float v2, v0, p1

    .line 48
    .line 49
    cmpg-float v3, p2, v2

    .line 50
    .line 51
    if-gez v3, :cond_3

    .line 52
    .line 53
    iput p2, p0, Ltw/h;->e:F

    .line 54
    .line 55
    iput v1, p0, Ltw/h;->f:F

    .line 56
    .line 57
    return-void

    .line 58
    :cond_3
    div-float v1, p2, v2

    .line 59
    .line 60
    float-to-double v3, v1

    .line 61
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 62
    .line 63
    .line 64
    move-result-wide v3

    .line 65
    double-to-float v1, v3

    .line 66
    mul-float/2addr v1, v2

    .line 67
    add-float/2addr v1, v0

    .line 68
    div-float/2addr p2, v1

    .line 69
    mul-float/2addr v0, p2

    .line 70
    iput v0, p0, Ltw/h;->e:F

    .line 71
    .line 72
    mul-float/2addr p1, p2

    .line 73
    iput p1, p0, Ltw/h;->f:F

    .line 74
    .line 75
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Ltw/h;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Ltw/k;->a:Lt0/c;

    .line 8
    .line 9
    check-cast p1, Ltw/h;

    .line 10
    .line 11
    invoke-virtual {v0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Ltw/h;->d:Ltw/g;

    .line 18
    .line 19
    iget-object p1, p1, Ltw/h;->d:Ltw/g;

    .line 20
    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0

    .line 26
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 27
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    sget-object v0, Ltw/k;->a:Lt0/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    const/high16 v2, 0x40800000    # 4.0f

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/high16 v2, 0x40000000    # 2.0f

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object p0, p0, Ltw/h;->d:Ltw/g;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

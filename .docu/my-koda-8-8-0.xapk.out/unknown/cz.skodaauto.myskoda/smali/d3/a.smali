.class public final Ld3/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:F

.field public c:F

.field public d:F

.field public e:F


# direct methods
.method public constructor <init>(FF)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Ld3/a;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Ld3/a;->c:F

    .line 3
    iput p2, p0, Ld3/a;->d:F

    return-void
.end method

.method public constructor <init>(FFFF)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ld3/a;->a:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput p1, p0, Ld3/a;->b:F

    .line 8
    iput p2, p0, Ld3/a;->c:F

    .line 9
    iput p3, p0, Ld3/a;->d:F

    .line 10
    iput p4, p0, Ld3/a;->e:F

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    iput p1, p0, Ld3/a;->a:I

    packed-switch p1, :pswitch_data_0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    iput p1, p0, Ld3/a;->b:F

    iput p1, p0, Ld3/a;->c:F

    iput p1, p0, Ld3/a;->d:F

    iput p1, p0, Ld3/a;->e:F

    return-void

    .line 5
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Ld3/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ld3/a;->a:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    iget v0, p1, Ld3/a;->b:F

    iput v0, p0, Ld3/a;->b:F

    .line 13
    iget v0, p1, Ld3/a;->c:F

    iput v0, p0, Ld3/a;->c:F

    .line 14
    iget v0, p1, Ld3/a;->d:F

    iput v0, p0, Ld3/a;->d:F

    .line 15
    iget p1, p1, Ld3/a;->e:F

    iput p1, p0, Ld3/a;->e:F

    return-void
.end method

.method public static a(Ld3/a;FFI)V
    .locals 2

    .line 1
    iget v0, p0, Ld3/a;->b:F

    .line 2
    .line 3
    and-int/lit8 v1, p3, 0x2

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget p1, p0, Ld3/a;->c:F

    .line 8
    .line 9
    :cond_0
    iget v1, p0, Ld3/a;->d:F

    .line 10
    .line 11
    and-int/lit8 p3, p3, 0x8

    .line 12
    .line 13
    if-eqz p3, :cond_1

    .line 14
    .line 15
    iget p2, p0, Ld3/a;->e:F

    .line 16
    .line 17
    :cond_1
    iput v0, p0, Ld3/a;->b:F

    .line 18
    .line 19
    iget p3, p0, Ld3/a;->c:F

    .line 20
    .line 21
    cmpg-float v0, p3, p1

    .line 22
    .line 23
    if-gez v0, :cond_2

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_2
    move p1, p3

    .line 27
    :goto_0
    iput p1, p0, Ld3/a;->c:F

    .line 28
    .line 29
    iput v1, p0, Ld3/a;->d:F

    .line 30
    .line 31
    iget p1, p0, Ld3/a;->e:F

    .line 32
    .line 33
    cmpg-float p3, p1, p2

    .line 34
    .line 35
    if-gez p3, :cond_3

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_3
    move p2, p1

    .line 39
    :goto_1
    iput p2, p0, Ld3/a;->e:F

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public b()F
    .locals 0

    .line 1
    iget p0, p0, Ld3/a;->e:F

    .line 2
    .line 3
    return p0
.end method

.method public c()F
    .locals 0

    .line 1
    iget p0, p0, Ld3/a;->c:F

    .line 2
    .line 3
    return p0
.end method

.method public d()F
    .locals 0

    .line 1
    iget p0, p0, Ld3/a;->d:F

    .line 2
    .line 3
    return p0
.end method

.method public e()F
    .locals 0

    .line 1
    iget p0, p0, Ld3/a;->b:F

    .line 2
    .line 3
    return p0
.end method

.method public f(FFFF)V
    .locals 1

    .line 1
    iget v0, p0, Ld3/a;->b:F

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/lang/Math;->max(FF)F

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iput p1, p0, Ld3/a;->b:F

    .line 8
    .line 9
    iget p1, p0, Ld3/a;->c:F

    .line 10
    .line 11
    invoke-static {p2, p1}, Ljava/lang/Math;->max(FF)F

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    iput p1, p0, Ld3/a;->c:F

    .line 16
    .line 17
    iget p1, p0, Ld3/a;->d:F

    .line 18
    .line 19
    invoke-static {p3, p1}, Ljava/lang/Math;->min(FF)F

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    iput p1, p0, Ld3/a;->d:F

    .line 24
    .line 25
    iget p1, p0, Ld3/a;->e:F

    .line 26
    .line 27
    invoke-static {p4, p1}, Ljava/lang/Math;->min(FF)F

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    iput p1, p0, Ld3/a;->e:F

    .line 32
    .line 33
    return-void
.end method

.method public g()Z
    .locals 4

    .line 1
    iget v0, p0, Ld3/a;->b:F

    .line 2
    .line 3
    iget v1, p0, Ld3/a;->d:F

    .line 4
    .line 5
    cmpl-float v0, v0, v1

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x1

    .line 9
    if-ltz v0, :cond_0

    .line 10
    .line 11
    move v0, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v0, v1

    .line 14
    :goto_0
    iget v3, p0, Ld3/a;->c:F

    .line 15
    .line 16
    iget p0, p0, Ld3/a;->e:F

    .line 17
    .line 18
    cmpl-float p0, v3, p0

    .line 19
    .line 20
    if-ltz p0, :cond_1

    .line 21
    .line 22
    move v1, v2

    .line 23
    :cond_1
    or-int p0, v0, v1

    .line 24
    .line 25
    return p0
.end method

.method public h()F
    .locals 1

    .line 1
    iget v0, p0, Ld3/a;->b:F

    .line 2
    .line 3
    iget p0, p0, Ld3/a;->d:F

    .line 4
    .line 5
    add-float/2addr v0, p0

    .line 6
    return v0
.end method

.method public i()F
    .locals 1

    .line 1
    iget v0, p0, Ld3/a;->c:F

    .line 2
    .line 3
    iget p0, p0, Ld3/a;->e:F

    .line 4
    .line 5
    add-float/2addr v0, p0

    .line 6
    return v0
.end method

.method public j()V
    .locals 6

    .line 1
    iget v0, p0, Ld3/a;->d:F

    .line 2
    .line 3
    iget v1, p0, Ld3/a;->c:F

    .line 4
    .line 5
    const/high16 v2, 0x3f800000    # 1.0f

    .line 6
    .line 7
    cmpl-float v3, v2, v1

    .line 8
    .line 9
    if-gtz v3, :cond_3

    .line 10
    .line 11
    cmpg-float v4, v2, v0

    .line 12
    .line 13
    if-ltz v4, :cond_3

    .line 14
    .line 15
    iput v2, p0, Ld3/a;->b:F

    .line 16
    .line 17
    cmpl-float v4, v1, v0

    .line 18
    .line 19
    const/4 v5, 0x0

    .line 20
    if-nez v4, :cond_0

    .line 21
    .line 22
    :goto_0
    move v2, v5

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    if-nez v3, :cond_1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    cmpl-float v3, v2, v0

    .line 28
    .line 29
    if-nez v3, :cond_2

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    div-float v1, v2, v1

    .line 33
    .line 34
    div-float v0, v2, v0

    .line 35
    .line 36
    sub-float/2addr v2, v0

    .line 37
    sub-float/2addr v1, v0

    .line 38
    div-float/2addr v2, v1

    .line 39
    :goto_1
    iput v2, p0, Ld3/a;->e:F

    .line 40
    .line 41
    return-void

    .line 42
    :cond_3
    new-instance p0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v2, "Requested zoomRatio 1.0 is not within valid range ["

    .line 45
    .line 46
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v0, " , "

    .line 53
    .line 54
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v0, "]"

    .line 61
    .line 62
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 70
    .line 71
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw v0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Ld3/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "["

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget v1, p0, Ld3/a;->b:F

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, " "

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v2, p0, Ld3/a;->c:F

    .line 29
    .line 30
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget v2, p0, Ld3/a;->d:F

    .line 37
    .line 38
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    iget p0, p0, Ld3/a;->e:F

    .line 45
    .line 46
    const-string v1, "]"

    .line 47
    .line 48
    invoke-static {p0, v1, v0}, Lkx/a;->g(FLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    const-string v1, "MutableRect("

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    iget v1, p0, Ld3/a;->b:F

    .line 61
    .line 62
    invoke-static {v1}, Ljp/af;->e(F)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const-string v1, ", "

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    iget v2, p0, Ld3/a;->c:F

    .line 75
    .line 76
    invoke-static {v2}, Ljp/af;->e(F)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    iget v2, p0, Ld3/a;->d:F

    .line 87
    .line 88
    invoke-static {v2}, Ljp/af;->e(F)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget p0, p0, Ld3/a;->e:F

    .line 99
    .line 100
    invoke-static {p0}, Ljp/af;->e(F)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    const/16 p0, 0x29

    .line 108
    .line 109
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

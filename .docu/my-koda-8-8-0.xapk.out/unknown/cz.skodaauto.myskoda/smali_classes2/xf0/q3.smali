.class public final Lxf0/q3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:F

.field public final b:F

.field public final c:F

.field public final d:F

.field public final e:F

.field public final f:F


# direct methods
.method public constructor <init>(FFFFFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxf0/q3;->a:F

    .line 5
    .line 6
    iput p2, p0, Lxf0/q3;->b:F

    .line 7
    .line 8
    iput p3, p0, Lxf0/q3;->c:F

    .line 9
    .line 10
    iput p4, p0, Lxf0/q3;->d:F

    .line 11
    .line 12
    iput p5, p0, Lxf0/q3;->e:F

    .line 13
    .line 14
    iput p6, p0, Lxf0/q3;->f:F

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lxf0/q3;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lxf0/q3;

    .line 10
    .line 11
    iget v0, p0, Lxf0/q3;->a:F

    .line 12
    .line 13
    iget v1, p1, Lxf0/q3;->a:F

    .line 14
    .line 15
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget v0, p0, Lxf0/q3;->b:F

    .line 23
    .line 24
    iget v1, p1, Lxf0/q3;->b:F

    .line 25
    .line 26
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_3
    iget v0, p0, Lxf0/q3;->c:F

    .line 34
    .line 35
    iget v1, p1, Lxf0/q3;->c:F

    .line 36
    .line 37
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_4

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_4
    iget v0, p0, Lxf0/q3;->d:F

    .line 45
    .line 46
    iget v1, p1, Lxf0/q3;->d:F

    .line 47
    .line 48
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-nez v0, :cond_5

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_5
    iget v0, p0, Lxf0/q3;->e:F

    .line 56
    .line 57
    iget v1, p1, Lxf0/q3;->e:F

    .line 58
    .line 59
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-nez v0, :cond_6

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_6
    iget p0, p0, Lxf0/q3;->f:F

    .line 67
    .line 68
    iget p1, p1, Lxf0/q3;->f:F

    .line 69
    .line 70
    invoke-static {p0, p1}, Lt4/f;->a(FF)Z

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    if-nez p0, :cond_7

    .line 75
    .line 76
    :goto_0
    const/4 p0, 0x0

    .line 77
    return p0

    .line 78
    :cond_7
    :goto_1
    const/4 p0, 0x1

    .line 79
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lxf0/q3;->a:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

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
    iget v2, p0, Lxf0/q3;->b:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lxf0/q3;->c:F

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Lxf0/q3;->d:F

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget v2, p0, Lxf0/q3;->e:F

    .line 29
    .line 30
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget p0, p0, Lxf0/q3;->f:F

    .line 35
    .line 36
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    add-int/2addr p0, v0

    .line 41
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 8

    .line 1
    iget v0, p0, Lxf0/q3;->a:F

    .line 2
    .line 3
    invoke-static {v0}, Lt4/f;->b(F)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v1, p0, Lxf0/q3;->b:F

    .line 8
    .line 9
    invoke-static {v1}, Lt4/f;->b(F)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget v2, p0, Lxf0/q3;->c:F

    .line 14
    .line 15
    invoke-static {v2}, Lt4/f;->b(F)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    iget v3, p0, Lxf0/q3;->d:F

    .line 20
    .line 21
    invoke-static {v3}, Lt4/f;->b(F)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    iget v4, p0, Lxf0/q3;->e:F

    .line 26
    .line 27
    invoke-static {v4}, Lt4/f;->b(F)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    iget p0, p0, Lxf0/q3;->f:F

    .line 32
    .line 33
    invoke-static {p0}, Lt4/f;->b(F)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-string v5, ", containerHeight="

    .line 38
    .line 39
    const-string v6, ", paddingStart="

    .line 40
    .line 41
    const-string v7, "TextFieldIconDimensions(containerWidth="

    .line 42
    .line 43
    invoke-static {v7, v0, v5, v1, v6}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    const-string v1, ", paddingTop="

    .line 48
    .line 49
    const-string v5, ", paddingEnd="

    .line 50
    .line 51
    invoke-static {v0, v2, v1, v3, v5}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const-string v1, ", paddingBottom="

    .line 55
    .line 56
    const-string v2, ")"

    .line 57
    .line 58
    invoke-static {v0, v4, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method

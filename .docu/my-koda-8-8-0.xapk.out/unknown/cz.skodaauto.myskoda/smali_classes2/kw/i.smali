.class public final Lkw/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:F

.field public b:F

.field public c:F

.field public d:F

.field public e:F


# direct methods
.method public static synthetic b(Lkw/i;FFI)V
    .locals 8

    .line 1
    and-int/lit8 v0, p3, 0x8

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move v6, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v6, p1

    .line 9
    :goto_0
    and-int/lit8 p1, p3, 0x10

    .line 10
    .line 11
    if-eqz p1, :cond_1

    .line 12
    .line 13
    move v7, v1

    .line 14
    goto :goto_1

    .line 15
    :cond_1
    move v7, p2

    .line 16
    :goto_1
    const/4 v3, 0x0

    .line 17
    const/4 v4, 0x0

    .line 18
    const/4 v5, 0x0

    .line 19
    move-object v2, p0

    .line 20
    invoke-virtual/range {v2 .. v7}, Lkw/i;->a(FFFFF)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a(FFFFF)V
    .locals 2

    .line 1
    iget v0, p0, Lkw/i;->a:F

    .line 2
    .line 3
    cmpg-float v1, v0, p1

    .line 4
    .line 5
    if-gez v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move p1, v0

    .line 9
    :goto_0
    iget v0, p0, Lkw/i;->b:F

    .line 10
    .line 11
    cmpg-float v1, v0, p2

    .line 12
    .line 13
    if-gez v1, :cond_1

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_1
    move p2, v0

    .line 17
    :goto_1
    iget v0, p0, Lkw/i;->c:F

    .line 18
    .line 19
    cmpg-float v1, v0, p3

    .line 20
    .line 21
    if-gez v1, :cond_2

    .line 22
    .line 23
    goto :goto_2

    .line 24
    :cond_2
    move p3, v0

    .line 25
    :goto_2
    iget v0, p0, Lkw/i;->d:F

    .line 26
    .line 27
    cmpg-float v1, v0, p4

    .line 28
    .line 29
    if-gez v1, :cond_3

    .line 30
    .line 31
    goto :goto_3

    .line 32
    :cond_3
    move p4, v0

    .line 33
    :goto_3
    iget v0, p0, Lkw/i;->e:F

    .line 34
    .line 35
    cmpg-float v1, v0, p5

    .line 36
    .line 37
    if-gez v1, :cond_4

    .line 38
    .line 39
    goto :goto_4

    .line 40
    :cond_4
    move p5, v0

    .line 41
    :goto_4
    iput p1, p0, Lkw/i;->a:F

    .line 42
    .line 43
    iput p2, p0, Lkw/i;->b:F

    .line 44
    .line 45
    iput p3, p0, Lkw/i;->c:F

    .line 46
    .line 47
    iput p4, p0, Lkw/i;->d:F

    .line 48
    .line 49
    iput p5, p0, Lkw/i;->e:F

    .line 50
    .line 51
    return-void
.end method

.method public final c(Lkw/g;)F
    .locals 5

    .line 1
    iget v0, p0, Lkw/i;->a:F

    .line 2
    .line 3
    invoke-interface {p1}, Lkw/g;->j()Lmw/b;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-interface {v1}, Lmw/b;->d()D

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-interface {p1}, Lkw/g;->j()Lmw/b;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-interface {p1}, Lmw/b;->b()D

    .line 16
    .line 17
    .line 18
    move-result-wide v3

    .line 19
    div-double/2addr v1, v3

    .line 20
    double-to-float p1, v1

    .line 21
    mul-float/2addr v0, p1

    .line 22
    iget p1, p0, Lkw/i;->b:F

    .line 23
    .line 24
    iget p0, p0, Lkw/i;->c:F

    .line 25
    .line 26
    add-float/2addr p1, p0

    .line 27
    add-float/2addr p1, v0

    .line 28
    return p1
.end method

.method public final d()F
    .locals 1

    .line 1
    iget v0, p0, Lkw/i;->b:F

    .line 2
    .line 3
    iget p0, p0, Lkw/i;->d:F

    .line 4
    .line 5
    add-float/2addr v0, p0

    .line 6
    return v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lkw/i;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lkw/i;

    .line 12
    .line 13
    iget v1, p0, Lkw/i;->a:F

    .line 14
    .line 15
    iget v3, p1, Lkw/i;->a:F

    .line 16
    .line 17
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget v1, p0, Lkw/i;->b:F

    .line 25
    .line 26
    iget v3, p1, Lkw/i;->b:F

    .line 27
    .line 28
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget v1, p0, Lkw/i;->c:F

    .line 36
    .line 37
    iget v3, p1, Lkw/i;->c:F

    .line 38
    .line 39
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget v1, p0, Lkw/i;->d:F

    .line 47
    .line 48
    iget v3, p1, Lkw/i;->d:F

    .line 49
    .line 50
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget p0, p0, Lkw/i;->e:F

    .line 58
    .line 59
    iget p1, p1, Lkw/i;->e:F

    .line 60
    .line 61
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-eqz p0, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lkw/i;->a:F

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
    iget v2, p0, Lkw/i;->b:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lkw/i;->c:F

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Lkw/i;->d:F

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget p0, p0, Lkw/i;->e:F

    .line 29
    .line 30
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, v0

    .line 35
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MutableHorizontalDimensions(xSpacing="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lkw/i;->a:F

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", scalableStartPadding="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Lkw/i;->b:F

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", scalableEndPadding="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lkw/i;->c:F

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", unscalableStartPadding="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget v1, p0, Lkw/i;->d:F

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", unscalableEndPadding="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget p0, p0, Lkw/i;->e:F

    .line 49
    .line 50
    const/16 v1, 0x29

    .line 51
    .line 52
    invoke-static {v0, p0, v1}, La7/g0;->i(Ljava/lang/StringBuilder;FC)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

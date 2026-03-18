.class public final Ld3/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Ld3/c;


# instance fields
.field public final a:F

.field public final b:F

.field public final c:F

.field public final d:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ld3/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1, v1, v1}, Ld3/c;-><init>(FFFF)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ld3/c;->e:Ld3/c;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(FFFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ld3/c;->a:F

    .line 5
    .line 6
    iput p2, p0, Ld3/c;->b:F

    .line 7
    .line 8
    iput p3, p0, Ld3/c;->c:F

    .line 9
    .line 10
    iput p4, p0, Ld3/c;->d:F

    .line 11
    .line 12
    return-void
.end method

.method public static a(Ld3/c;FFI)Ld3/c;
    .locals 2

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget p1, p0, Ld3/c;->a:F

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p3, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget v0, p0, Ld3/c;->b:F

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_1
    const/high16 v0, -0x800000    # Float.NEGATIVE_INFINITY

    .line 15
    .line 16
    :goto_0
    and-int/lit8 v1, p3, 0x4

    .line 17
    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    iget p2, p0, Ld3/c;->c:F

    .line 21
    .line 22
    :cond_2
    and-int/lit8 p3, p3, 0x8

    .line 23
    .line 24
    if-eqz p3, :cond_3

    .line 25
    .line 26
    iget p0, p0, Ld3/c;->d:F

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_3
    const/high16 p0, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 30
    .line 31
    :goto_1
    new-instance p3, Ld3/c;

    .line 32
    .line 33
    invoke-direct {p3, p1, v0, p2, p0}, Ld3/c;-><init>(FFFF)V

    .line 34
    .line 35
    .line 36
    return-object p3
.end method


# virtual methods
.method public final b()J
    .locals 6

    .line 1
    iget v0, p0, Ld3/c;->c:F

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->a:F

    .line 4
    .line 5
    sub-float/2addr v0, v1

    .line 6
    const/high16 v2, 0x40000000    # 2.0f

    .line 7
    .line 8
    div-float/2addr v0, v2

    .line 9
    add-float/2addr v0, v1

    .line 10
    iget v1, p0, Ld3/c;->d:F

    .line 11
    .line 12
    iget p0, p0, Ld3/c;->b:F

    .line 13
    .line 14
    sub-float/2addr v1, p0

    .line 15
    div-float/2addr v1, v2

    .line 16
    add-float/2addr v1, p0

    .line 17
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    int-to-long v2, p0

    .line 22
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    int-to-long v0, p0

    .line 27
    const/16 p0, 0x20

    .line 28
    .line 29
    shl-long/2addr v2, p0

    .line 30
    const-wide v4, 0xffffffffL

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    and-long/2addr v0, v4

    .line 36
    or-long/2addr v0, v2

    .line 37
    return-wide v0
.end method

.method public final c()J
    .locals 6

    .line 1
    iget v0, p0, Ld3/c;->c:F

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->a:F

    .line 4
    .line 5
    sub-float/2addr v0, v1

    .line 6
    iget v1, p0, Ld3/c;->d:F

    .line 7
    .line 8
    iget p0, p0, Ld3/c;->b:F

    .line 9
    .line 10
    sub-float/2addr v1, p0

    .line 11
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    int-to-long v2, p0

    .line 16
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    int-to-long v0, p0

    .line 21
    const/16 p0, 0x20

    .line 22
    .line 23
    shl-long/2addr v2, p0

    .line 24
    const-wide v4, 0xffffffffL

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    and-long/2addr v0, v4

    .line 30
    or-long/2addr v0, v2

    .line 31
    return-wide v0
.end method

.method public final d()J
    .locals 6

    .line 1
    iget v0, p0, Ld3/c;->a:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    int-to-long v0, v0

    .line 8
    iget p0, p0, Ld3/c;->b:F

    .line 9
    .line 10
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    int-to-long v2, p0

    .line 15
    const/16 p0, 0x20

    .line 16
    .line 17
    shl-long/2addr v0, p0

    .line 18
    const-wide v4, 0xffffffffL

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    and-long/2addr v2, v4

    .line 24
    or-long/2addr v0, v2

    .line 25
    return-wide v0
.end method

.method public final e(Ld3/c;)Ld3/c;
    .locals 5

    .line 1
    new-instance v0, Ld3/c;

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->a:F

    .line 4
    .line 5
    iget v2, p1, Ld3/c;->a:F

    .line 6
    .line 7
    invoke-static {v1, v2}, Ljava/lang/Math;->max(FF)F

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    iget v2, p0, Ld3/c;->b:F

    .line 12
    .line 13
    iget v3, p1, Ld3/c;->b:F

    .line 14
    .line 15
    invoke-static {v2, v3}, Ljava/lang/Math;->max(FF)F

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    iget v3, p0, Ld3/c;->c:F

    .line 20
    .line 21
    iget v4, p1, Ld3/c;->c:F

    .line 22
    .line 23
    invoke-static {v3, v4}, Ljava/lang/Math;->min(FF)F

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    iget p0, p0, Ld3/c;->d:F

    .line 28
    .line 29
    iget p1, p1, Ld3/c;->d:F

    .line 30
    .line 31
    invoke-static {p0, p1}, Ljava/lang/Math;->min(FF)F

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-direct {v0, v1, v2, v3, p0}, Ld3/c;-><init>(FFFF)V

    .line 36
    .line 37
    .line 38
    return-object v0
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
    instance-of v1, p1, Ld3/c;

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
    check-cast p1, Ld3/c;

    .line 12
    .line 13
    iget v1, p0, Ld3/c;->a:F

    .line 14
    .line 15
    iget v3, p1, Ld3/c;->a:F

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
    iget v1, p0, Ld3/c;->b:F

    .line 25
    .line 26
    iget v3, p1, Ld3/c;->b:F

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
    iget v1, p0, Ld3/c;->c:F

    .line 36
    .line 37
    iget v3, p1, Ld3/c;->c:F

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
    iget p0, p0, Ld3/c;->d:F

    .line 47
    .line 48
    iget p1, p1, Ld3/c;->d:F

    .line 49
    .line 50
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-eqz p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final f()Z
    .locals 4

    .line 1
    iget v0, p0, Ld3/c;->a:F

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->c:F

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
    iget v3, p0, Ld3/c;->b:F

    .line 15
    .line 16
    iget p0, p0, Ld3/c;->d:F

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

.method public final g(Ld3/c;)Z
    .locals 5

    .line 1
    iget v0, p0, Ld3/c;->a:F

    .line 2
    .line 3
    iget v1, p1, Ld3/c;->c:F

    .line 4
    .line 5
    cmpg-float v0, v0, v1

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x1

    .line 9
    if-gez v0, :cond_0

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
    iget v3, p1, Ld3/c;->a:F

    .line 15
    .line 16
    iget v4, p0, Ld3/c;->c:F

    .line 17
    .line 18
    cmpg-float v3, v3, v4

    .line 19
    .line 20
    if-gez v3, :cond_1

    .line 21
    .line 22
    move v3, v2

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v3, v1

    .line 25
    :goto_1
    and-int/2addr v0, v3

    .line 26
    iget v3, p0, Ld3/c;->b:F

    .line 27
    .line 28
    iget v4, p1, Ld3/c;->d:F

    .line 29
    .line 30
    cmpg-float v3, v3, v4

    .line 31
    .line 32
    if-gez v3, :cond_2

    .line 33
    .line 34
    move v3, v2

    .line 35
    goto :goto_2

    .line 36
    :cond_2
    move v3, v1

    .line 37
    :goto_2
    and-int/2addr v0, v3

    .line 38
    iget p1, p1, Ld3/c;->b:F

    .line 39
    .line 40
    iget p0, p0, Ld3/c;->d:F

    .line 41
    .line 42
    cmpg-float p0, p1, p0

    .line 43
    .line 44
    if-gez p0, :cond_3

    .line 45
    .line 46
    move v1, v2

    .line 47
    :cond_3
    and-int p0, v0, v1

    .line 48
    .line 49
    return p0
.end method

.method public final h(FF)Ld3/c;
    .locals 4

    .line 1
    new-instance v0, Ld3/c;

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->a:F

    .line 4
    .line 5
    add-float/2addr v1, p1

    .line 6
    iget v2, p0, Ld3/c;->b:F

    .line 7
    .line 8
    add-float/2addr v2, p2

    .line 9
    iget v3, p0, Ld3/c;->c:F

    .line 10
    .line 11
    add-float/2addr v3, p1

    .line 12
    iget p0, p0, Ld3/c;->d:F

    .line 13
    .line 14
    add-float/2addr p0, p2

    .line 15
    invoke-direct {v0, v1, v2, v3, p0}, Ld3/c;-><init>(FFFF)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Ld3/c;->a:F

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
    iget v2, p0, Ld3/c;->b:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Ld3/c;->c:F

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget p0, p0, Ld3/c;->d:F

    .line 23
    .line 24
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public final i(J)Ld3/c;
    .locals 5

    .line 1
    new-instance v0, Ld3/c;

    .line 2
    .line 3
    const/16 v1, 0x20

    .line 4
    .line 5
    shr-long v1, p1, v1

    .line 6
    .line 7
    long-to-int v1, v1

    .line 8
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    iget v3, p0, Ld3/c;->a:F

    .line 13
    .line 14
    add-float/2addr v2, v3

    .line 15
    const-wide v3, 0xffffffffL

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    and-long/2addr p1, v3

    .line 21
    long-to-int p1, p1

    .line 22
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    iget v3, p0, Ld3/c;->b:F

    .line 27
    .line 28
    add-float/2addr p2, v3

    .line 29
    iget v3, p0, Ld3/c;->c:F

    .line 30
    .line 31
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    add-float/2addr v1, v3

    .line 36
    iget p0, p0, Ld3/c;->d:F

    .line 37
    .line 38
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    add-float/2addr p1, p0

    .line 43
    invoke-direct {v0, v2, p2, v1, p1}, Ld3/c;-><init>(FFFF)V

    .line 44
    .line 45
    .line 46
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Rect.fromLTRB("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Ld3/c;->a:F

    .line 9
    .line 10
    invoke-static {v1}, Ljp/af;->e(F)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", "

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget v2, p0, Ld3/c;->b:F

    .line 23
    .line 24
    invoke-static {v2}, Ljp/af;->e(F)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    iget v2, p0, Ld3/c;->c:F

    .line 35
    .line 36
    invoke-static {v2}, Ljp/af;->e(F)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget p0, p0, Ld3/c;->d:F

    .line 47
    .line 48
    invoke-static {p0}, Ljp/af;->e(F)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const/16 p0, 0x29

    .line 56
    .line 57
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0
.end method

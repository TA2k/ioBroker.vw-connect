.class public final Lg3/h;
.super Lg3/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:F

.field public final b:F

.field public final c:I

.field public final d:I

.field public final e:Le3/j;


# direct methods
.method public constructor <init>(FFIILe3/j;I)V
    .locals 2

    .line 1
    and-int/lit8 v0, p6, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/high16 p2, 0x40800000    # 4.0f

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p6, 0x4

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    move p3, v1

    .line 13
    :cond_1
    and-int/lit8 v0, p6, 0x8

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    move p4, v1

    .line 18
    :cond_2
    and-int/lit8 p6, p6, 0x10

    .line 19
    .line 20
    if-eqz p6, :cond_3

    .line 21
    .line 22
    const/4 p5, 0x0

    .line 23
    :cond_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    .line 25
    .line 26
    iput p1, p0, Lg3/h;->a:F

    .line 27
    .line 28
    iput p2, p0, Lg3/h;->b:F

    .line 29
    .line 30
    iput p3, p0, Lg3/h;->c:I

    .line 31
    .line 32
    iput p4, p0, Lg3/h;->d:I

    .line 33
    .line 34
    iput-object p5, p0, Lg3/h;->e:Le3/j;

    .line 35
    .line 36
    return-void
.end method


# virtual methods
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
    instance-of v1, p1, Lg3/h;

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
    check-cast p1, Lg3/h;

    .line 12
    .line 13
    iget v1, p1, Lg3/h;->a:F

    .line 14
    .line 15
    iget v3, p0, Lg3/h;->a:F

    .line 16
    .line 17
    cmpg-float v1, v3, v1

    .line 18
    .line 19
    if-nez v1, :cond_3

    .line 20
    .line 21
    iget v1, p0, Lg3/h;->b:F

    .line 22
    .line 23
    iget v3, p1, Lg3/h;->b:F

    .line 24
    .line 25
    cmpg-float v1, v1, v3

    .line 26
    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    iget v1, p0, Lg3/h;->c:I

    .line 30
    .line 31
    iget v3, p1, Lg3/h;->c:I

    .line 32
    .line 33
    if-ne v1, v3, :cond_3

    .line 34
    .line 35
    iget v1, p0, Lg3/h;->d:I

    .line 36
    .line 37
    iget v3, p1, Lg3/h;->d:I

    .line 38
    .line 39
    if-ne v1, v3, :cond_3

    .line 40
    .line 41
    iget-object p0, p0, Lg3/h;->e:Le3/j;

    .line 42
    .line 43
    iget-object p1, p1, Lg3/h;->e:Le3/j;

    .line 44
    .line 45
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    if-nez p0, :cond_2

    .line 50
    .line 51
    return v2

    .line 52
    :cond_2
    return v0

    .line 53
    :cond_3
    return v2
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lg3/h;->a:F

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
    iget v2, p0, Lg3/h;->b:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lg3/h;->c:I

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Lg3/h;->d:I

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object p0, p0, Lg3/h;->e:Le3/j;

    .line 29
    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 p0, 0x0

    .line 38
    :goto_0
    add-int/2addr v0, p0

    .line 39
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Stroke(width="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lg3/h;->a:F

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", miter="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Lg3/h;->b:F

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", cap="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, "Unknown"

    .line 29
    .line 30
    const/4 v2, 0x2

    .line 31
    const-string v3, "Round"

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    iget v5, p0, Lg3/h;->c:I

    .line 35
    .line 36
    if-nez v5, :cond_0

    .line 37
    .line 38
    const-string v5, "Butt"

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    if-ne v5, v4, :cond_1

    .line 42
    .line 43
    move-object v5, v3

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    if-ne v5, v2, :cond_2

    .line 46
    .line 47
    const-string v5, "Square"

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    move-object v5, v1

    .line 51
    :goto_0
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v5, ", join="

    .line 55
    .line 56
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    iget v5, p0, Lg3/h;->d:I

    .line 60
    .line 61
    if-nez v5, :cond_3

    .line 62
    .line 63
    const-string v1, "Miter"

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    if-ne v5, v4, :cond_4

    .line 67
    .line 68
    move-object v1, v3

    .line 69
    goto :goto_1

    .line 70
    :cond_4
    if-ne v5, v2, :cond_5

    .line 71
    .line 72
    const-string v1, "Bevel"

    .line 73
    .line 74
    :cond_5
    :goto_1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v1, ", pathEffect="

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Lg3/h;->e:Le3/j;

    .line 83
    .line 84
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const/16 p0, 0x29

    .line 88
    .line 89
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method

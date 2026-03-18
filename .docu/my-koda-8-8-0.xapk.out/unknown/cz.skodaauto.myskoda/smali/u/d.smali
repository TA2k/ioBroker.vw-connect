.class public final Lu/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:Z

.field public final c:I

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Landroid/util/Range;

.field public final j:Z


# direct methods
.method public constructor <init>(IZIZZZZZLandroid/util/Range;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lu/d;->a:I

    .line 5
    .line 6
    iput-boolean p2, p0, Lu/d;->b:Z

    .line 7
    .line 8
    iput p3, p0, Lu/d;->c:I

    .line 9
    .line 10
    iput-boolean p4, p0, Lu/d;->d:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lu/d;->e:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lu/d;->f:Z

    .line 15
    .line 16
    iput-boolean p7, p0, Lu/d;->g:Z

    .line 17
    .line 18
    iput-boolean p8, p0, Lu/d;->h:Z

    .line 19
    .line 20
    if-eqz p9, :cond_0

    .line 21
    .line 22
    iput-object p9, p0, Lu/d;->i:Landroid/util/Range;

    .line 23
    .line 24
    iput-boolean p10, p0, Lu/d;->j:Z

    .line 25
    .line 26
    return-void

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 28
    .line 29
    const-string p1, "Null getTargetFpsRange"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of v0, p1, Lu/d;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    check-cast p1, Lu/d;

    .line 9
    .line 10
    iget v0, p0, Lu/d;->a:I

    .line 11
    .line 12
    iget v1, p1, Lu/d;->a:I

    .line 13
    .line 14
    if-ne v0, v1, :cond_1

    .line 15
    .line 16
    iget-boolean v0, p0, Lu/d;->b:Z

    .line 17
    .line 18
    iget-boolean v1, p1, Lu/d;->b:Z

    .line 19
    .line 20
    if-ne v0, v1, :cond_1

    .line 21
    .line 22
    iget v0, p0, Lu/d;->c:I

    .line 23
    .line 24
    iget v1, p1, Lu/d;->c:I

    .line 25
    .line 26
    if-ne v0, v1, :cond_1

    .line 27
    .line 28
    iget-boolean v0, p0, Lu/d;->d:Z

    .line 29
    .line 30
    iget-boolean v1, p1, Lu/d;->d:Z

    .line 31
    .line 32
    if-ne v0, v1, :cond_1

    .line 33
    .line 34
    iget-boolean v0, p0, Lu/d;->e:Z

    .line 35
    .line 36
    iget-boolean v1, p1, Lu/d;->e:Z

    .line 37
    .line 38
    if-ne v0, v1, :cond_1

    .line 39
    .line 40
    iget-boolean v0, p0, Lu/d;->f:Z

    .line 41
    .line 42
    iget-boolean v1, p1, Lu/d;->f:Z

    .line 43
    .line 44
    if-ne v0, v1, :cond_1

    .line 45
    .line 46
    iget-boolean v0, p0, Lu/d;->g:Z

    .line 47
    .line 48
    iget-boolean v1, p1, Lu/d;->g:Z

    .line 49
    .line 50
    if-ne v0, v1, :cond_1

    .line 51
    .line 52
    iget-boolean v0, p0, Lu/d;->h:Z

    .line 53
    .line 54
    iget-boolean v1, p1, Lu/d;->h:Z

    .line 55
    .line 56
    if-ne v0, v1, :cond_1

    .line 57
    .line 58
    iget-object v0, p0, Lu/d;->i:Landroid/util/Range;

    .line 59
    .line 60
    iget-object v1, p1, Lu/d;->i:Landroid/util/Range;

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-eqz v0, :cond_1

    .line 67
    .line 68
    iget-boolean p0, p0, Lu/d;->j:Z

    .line 69
    .line 70
    iget-boolean p1, p1, Lu/d;->j:Z

    .line 71
    .line 72
    if-ne p0, p1, :cond_1

    .line 73
    .line 74
    :goto_0
    const/4 p0, 0x1

    .line 75
    return p0

    .line 76
    :cond_1
    const/4 p0, 0x0

    .line 77
    return p0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    iget v0, p0, Lu/d;->a:I

    .line 2
    .line 3
    const v1, 0xf4243

    .line 4
    .line 5
    .line 6
    xor-int/2addr v0, v1

    .line 7
    mul-int/2addr v0, v1

    .line 8
    iget-boolean v2, p0, Lu/d;->b:Z

    .line 9
    .line 10
    const/16 v3, 0x4d5

    .line 11
    .line 12
    const/16 v4, 0x4cf

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    move v2, v4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v2, v3

    .line 19
    :goto_0
    xor-int/2addr v0, v2

    .line 20
    mul-int/2addr v0, v1

    .line 21
    iget v2, p0, Lu/d;->c:I

    .line 22
    .line 23
    xor-int/2addr v0, v2

    .line 24
    mul-int/2addr v0, v1

    .line 25
    iget-boolean v2, p0, Lu/d;->d:Z

    .line 26
    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    move v2, v4

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v2, v3

    .line 32
    :goto_1
    xor-int/2addr v0, v2

    .line 33
    mul-int/2addr v0, v1

    .line 34
    iget-boolean v2, p0, Lu/d;->e:Z

    .line 35
    .line 36
    if-eqz v2, :cond_2

    .line 37
    .line 38
    move v2, v4

    .line 39
    goto :goto_2

    .line 40
    :cond_2
    move v2, v3

    .line 41
    :goto_2
    xor-int/2addr v0, v2

    .line 42
    mul-int/2addr v0, v1

    .line 43
    iget-boolean v2, p0, Lu/d;->f:Z

    .line 44
    .line 45
    if-eqz v2, :cond_3

    .line 46
    .line 47
    move v2, v4

    .line 48
    goto :goto_3

    .line 49
    :cond_3
    move v2, v3

    .line 50
    :goto_3
    xor-int/2addr v0, v2

    .line 51
    mul-int/2addr v0, v1

    .line 52
    iget-boolean v2, p0, Lu/d;->g:Z

    .line 53
    .line 54
    if-eqz v2, :cond_4

    .line 55
    .line 56
    move v2, v4

    .line 57
    goto :goto_4

    .line 58
    :cond_4
    move v2, v3

    .line 59
    :goto_4
    xor-int/2addr v0, v2

    .line 60
    mul-int/2addr v0, v1

    .line 61
    iget-boolean v2, p0, Lu/d;->h:Z

    .line 62
    .line 63
    if-eqz v2, :cond_5

    .line 64
    .line 65
    move v2, v4

    .line 66
    goto :goto_5

    .line 67
    :cond_5
    move v2, v3

    .line 68
    :goto_5
    xor-int/2addr v0, v2

    .line 69
    mul-int/2addr v0, v1

    .line 70
    iget-object v2, p0, Lu/d;->i:Landroid/util/Range;

    .line 71
    .line 72
    invoke-virtual {v2}, Landroid/util/Range;->hashCode()I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    xor-int/2addr v0, v2

    .line 77
    mul-int/2addr v0, v1

    .line 78
    iget-boolean p0, p0, Lu/d;->j:Z

    .line 79
    .line 80
    if-eqz p0, :cond_6

    .line 81
    .line 82
    move v3, v4

    .line 83
    :cond_6
    xor-int p0, v0, v3

    .line 84
    .line 85
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "FeatureSettings{getCameraMode="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lu/d;->a:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", hasVideoCapture="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lu/d;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", getRequiredMaxBitDepth="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lu/d;->c:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", isPreviewStabilizationOn="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-boolean v1, p0, Lu/d;->d:Z

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", isUltraHdrOn="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Lu/d;->e:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", isHighSpeedOn="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-boolean v1, p0, Lu/d;->f:Z

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", isFeatureComboInvocation="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-boolean v1, p0, Lu/d;->g:Z

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", requiresFeatureComboQuery="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-boolean v1, p0, Lu/d;->h:Z

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", getTargetFpsRange="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lu/d;->i:Landroid/util/Range;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", isStrictFpsRequired="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-boolean p0, p0, Lu/d;->j:Z

    .line 99
    .line 100
    const-string v1, "}"

    .line 101
    .line 102
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0
.end method

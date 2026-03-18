.class public final Lbg0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:I

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Z

.field public final f:Lbg0/b;

.field public final g:Lbg0/a;

.field public final h:F

.field public final i:I

.field public final j:I

.field public final k:I


# direct methods
.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;ZLbg0/b;Lbg0/a;FIII)V
    .locals 3

    .line 1
    sget-object v0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 2
    .line 3
    sget-object v1, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "osVersionName"

    .line 6
    .line 7
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "manufacturer"

    .line 11
    .line 12
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "model"

    .line 16
    .line 17
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lbg0/c;->a:Ljava/lang/String;

    .line 24
    .line 25
    iput p2, p0, Lbg0/c;->b:I

    .line 26
    .line 27
    iput-object p3, p0, Lbg0/c;->c:Ljava/lang/String;

    .line 28
    .line 29
    iput-object p4, p0, Lbg0/c;->d:Ljava/lang/String;

    .line 30
    .line 31
    iput-boolean p5, p0, Lbg0/c;->e:Z

    .line 32
    .line 33
    iput-object p6, p0, Lbg0/c;->f:Lbg0/b;

    .line 34
    .line 35
    iput-object p7, p0, Lbg0/c;->g:Lbg0/a;

    .line 36
    .line 37
    iput p8, p0, Lbg0/c;->h:F

    .line 38
    .line 39
    iput p9, p0, Lbg0/c;->i:I

    .line 40
    .line 41
    iput p10, p0, Lbg0/c;->j:I

    .line 42
    .line 43
    iput p11, p0, Lbg0/c;->k:I

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Lbg0/c;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lbg0/c;

    .line 12
    .line 13
    iget-object v0, p0, Lbg0/c;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p1, Lbg0/c;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto/16 :goto_0

    .line 24
    .line 25
    :cond_2
    iget v0, p0, Lbg0/c;->b:I

    .line 26
    .line 27
    iget v1, p1, Lbg0/c;->b:I

    .line 28
    .line 29
    if-eq v0, v1, :cond_3

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_3
    sget-object v0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-nez v0, :cond_4

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_4
    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-nez v0, :cond_5

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_5
    iget-object v0, p0, Lbg0/c;->c:Ljava/lang/String;

    .line 51
    .line 52
    iget-object v1, p1, Lbg0/c;->c:Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_6

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_6
    iget-object v0, p0, Lbg0/c;->d:Ljava/lang/String;

    .line 62
    .line 63
    iget-object v1, p1, Lbg0/c;->d:Ljava/lang/String;

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-nez v0, :cond_7

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_7
    iget-boolean v0, p0, Lbg0/c;->e:Z

    .line 73
    .line 74
    iget-boolean v1, p1, Lbg0/c;->e:Z

    .line 75
    .line 76
    if-eq v0, v1, :cond_8

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_8
    iget-object v0, p0, Lbg0/c;->f:Lbg0/b;

    .line 80
    .line 81
    iget-object v1, p1, Lbg0/c;->f:Lbg0/b;

    .line 82
    .line 83
    if-eq v0, v1, :cond_9

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_9
    iget-object v0, p0, Lbg0/c;->g:Lbg0/a;

    .line 87
    .line 88
    iget-object v1, p1, Lbg0/c;->g:Lbg0/a;

    .line 89
    .line 90
    if-eq v0, v1, :cond_a

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_a
    iget v0, p0, Lbg0/c;->h:F

    .line 94
    .line 95
    iget v1, p1, Lbg0/c;->h:F

    .line 96
    .line 97
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    if-eqz v0, :cond_b

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_b
    iget v0, p0, Lbg0/c;->i:I

    .line 105
    .line 106
    iget v1, p1, Lbg0/c;->i:I

    .line 107
    .line 108
    if-eq v0, v1, :cond_c

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_c
    iget v0, p0, Lbg0/c;->j:I

    .line 112
    .line 113
    iget v1, p1, Lbg0/c;->j:I

    .line 114
    .line 115
    if-eq v0, v1, :cond_d

    .line 116
    .line 117
    goto :goto_0

    .line 118
    :cond_d
    iget p0, p0, Lbg0/c;->k:I

    .line 119
    .line 120
    iget p1, p1, Lbg0/c;->k:I

    .line 121
    .line 122
    if-eq p0, p1, :cond_e

    .line 123
    .line 124
    :goto_0
    const/4 p0, 0x0

    .line 125
    return p0

    .line 126
    :cond_e
    :goto_1
    const/4 p0, 0x1

    .line 127
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lbg0/c;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget v2, p0, Lbg0/c;->b:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    sget-object v2, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    sget-object v2, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lbg0/c;->c:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lbg0/c;->d:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Lbg0/c;->e:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lbg0/c;->f:Lbg0/b;

    .line 47
    .line 48
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    add-int/2addr v2, v0

    .line 53
    mul-int/2addr v2, v1

    .line 54
    iget-object v0, p0, Lbg0/c;->g:Lbg0/a;

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    add-int/2addr v0, v2

    .line 61
    mul-int/2addr v0, v1

    .line 62
    iget v2, p0, Lbg0/c;->h:F

    .line 63
    .line 64
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget v2, p0, Lbg0/c;->i:I

    .line 69
    .line 70
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget v2, p0, Lbg0/c;->j:I

    .line 75
    .line 76
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    iget p0, p0, Lbg0/c;->k:I

    .line 81
    .line 82
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    add-int/2addr p0, v0

    .line 87
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 7

    .line 1
    sget-object v0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 2
    .line 3
    sget-object v1, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, ", osVersionCode="

    .line 6
    .line 7
    const-string v3, ", manufacturer="

    .line 8
    .line 9
    const-string v4, "DeviceConfiguration(osVersionName="

    .line 10
    .line 11
    iget v5, p0, Lbg0/c;->b:I

    .line 12
    .line 13
    iget-object v6, p0, Lbg0/c;->a:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v4, v5, v6, v2, v3}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    const-string v3, ", model="

    .line 20
    .line 21
    const-string v4, ", language="

    .line 22
    .line 23
    invoke-static {v2, v0, v3, v1, v4}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v0, ", localization="

    .line 27
    .line 28
    const-string v1, ", nightMode="

    .line 29
    .line 30
    iget-object v3, p0, Lbg0/c;->c:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Lbg0/c;->d:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v2, v3, v0, v4, v1}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-boolean v0, p0, Lbg0/c;->e:Z

    .line 38
    .line 39
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v0, ", screenSize="

    .line 43
    .line 44
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-object v0, p0, Lbg0/c;->f:Lbg0/b;

    .line 48
    .line 49
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v0, ", screenDensityBucket="

    .line 53
    .line 54
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    iget-object v0, p0, Lbg0/c;->g:Lbg0/a;

    .line 58
    .line 59
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v0, ", textScale="

    .line 63
    .line 64
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget v0, p0, Lbg0/c;->h:F

    .line 68
    .line 69
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v0, ", screenDensityInDpi="

    .line 73
    .line 74
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v0, ", screenWidthInDp="

    .line 78
    .line 79
    const-string v1, ", screenHeightInDp="

    .line 80
    .line 81
    iget v3, p0, Lbg0/c;->i:I

    .line 82
    .line 83
    iget v4, p0, Lbg0/c;->j:I

    .line 84
    .line 85
    invoke-static {v2, v3, v0, v4, v1}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 86
    .line 87
    .line 88
    const-string v0, ")"

    .line 89
    .line 90
    iget p0, p0, Lbg0/c;->k:I

    .line 91
    .line 92
    invoke-static {p0, v0, v2}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method

.class public final Ltz/c0;
.super Llp/p0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:I

.field public final e:I

.field public final f:I

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Ljava/lang/Integer;

.field public final k:Ljava/lang/Integer;

.field public final l:Lqr0/l;

.field public final m:Lqr0/l;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIZZZLjava/lang/Integer;Ljava/lang/Integer;)V
    .locals 1

    .line 1
    const-string v0, "limitText"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "rangeText"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Ltz/c0;->a:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p2, p0, Ltz/c0;->b:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p3, p0, Ltz/c0;->c:Ljava/lang/String;

    .line 19
    .line 20
    iput p4, p0, Ltz/c0;->d:I

    .line 21
    .line 22
    iput p5, p0, Ltz/c0;->e:I

    .line 23
    .line 24
    iput p6, p0, Ltz/c0;->f:I

    .line 25
    .line 26
    iput-boolean p7, p0, Ltz/c0;->g:Z

    .line 27
    .line 28
    iput-boolean p8, p0, Ltz/c0;->h:Z

    .line 29
    .line 30
    iput-boolean p9, p0, Ltz/c0;->i:Z

    .line 31
    .line 32
    iput-object p10, p0, Ltz/c0;->j:Ljava/lang/Integer;

    .line 33
    .line 34
    iput-object p11, p0, Ltz/c0;->k:Ljava/lang/Integer;

    .line 35
    .line 36
    sget-object p1, Lrd0/o;->a:Lqr0/l;

    .line 37
    .line 38
    iput-object p1, p0, Ltz/c0;->l:Lqr0/l;

    .line 39
    .line 40
    sget-object p1, Lrd0/o;->b:Lqr0/l;

    .line 41
    .line 42
    iput-object p1, p0, Ltz/c0;->m:Lqr0/l;

    .line 43
    .line 44
    return-void
.end method

.method public static b(Ltz/c0;Ljava/lang/String;II)Ltz/c0;
    .locals 12

    .line 1
    iget-object v2, p0, Ltz/c0;->b:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v3, p0, Ltz/c0;->c:Ljava/lang/String;

    .line 4
    .line 5
    iget v4, p0, Ltz/c0;->d:I

    .line 6
    .line 7
    iget v5, p0, Ltz/c0;->e:I

    .line 8
    .line 9
    and-int/lit8 v0, p3, 0x20

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget p2, p0, Ltz/c0;->f:I

    .line 14
    .line 15
    :cond_0
    move v6, p2

    .line 16
    iget-boolean v7, p0, Ltz/c0;->g:Z

    .line 17
    .line 18
    and-int/lit16 p2, p3, 0x80

    .line 19
    .line 20
    if-eqz p2, :cond_1

    .line 21
    .line 22
    iget-boolean p2, p0, Ltz/c0;->h:Z

    .line 23
    .line 24
    :goto_0
    move v8, p2

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    const/4 p2, 0x0

    .line 27
    goto :goto_0

    .line 28
    :goto_1
    iget-boolean v9, p0, Ltz/c0;->i:Z

    .line 29
    .line 30
    iget-object v10, p0, Ltz/c0;->j:Ljava/lang/Integer;

    .line 31
    .line 32
    iget-object v11, p0, Ltz/c0;->k:Ljava/lang/Integer;

    .line 33
    .line 34
    const-string p0, "limitText"

    .line 35
    .line 36
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string p0, "rangeText"

    .line 40
    .line 41
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v0, Ltz/c0;

    .line 45
    .line 46
    move-object v1, p1

    .line 47
    invoke-direct/range {v0 .. v11}, Ltz/c0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIZZZLjava/lang/Integer;Ljava/lang/Integer;)V

    .line 48
    .line 49
    .line 50
    return-object v0
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
    instance-of v1, p1, Ltz/c0;

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
    check-cast p1, Ltz/c0;

    .line 12
    .line 13
    iget-object v1, p0, Ltz/c0;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ltz/c0;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Ltz/c0;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Ltz/c0;->b:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Ltz/c0;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Ltz/c0;->c:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget v1, p0, Ltz/c0;->d:I

    .line 47
    .line 48
    iget v3, p1, Ltz/c0;->d:I

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget v1, p0, Ltz/c0;->e:I

    .line 54
    .line 55
    iget v3, p1, Ltz/c0;->e:I

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget v1, p0, Ltz/c0;->f:I

    .line 61
    .line 62
    iget v3, p1, Ltz/c0;->f:I

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean v1, p0, Ltz/c0;->g:Z

    .line 68
    .line 69
    iget-boolean v3, p1, Ltz/c0;->g:Z

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-boolean v1, p0, Ltz/c0;->h:Z

    .line 75
    .line 76
    iget-boolean v3, p1, Ltz/c0;->h:Z

    .line 77
    .line 78
    if-eq v1, v3, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-boolean v1, p0, Ltz/c0;->i:Z

    .line 82
    .line 83
    iget-boolean v3, p1, Ltz/c0;->i:Z

    .line 84
    .line 85
    if-eq v1, v3, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-object v1, p0, Ltz/c0;->j:Ljava/lang/Integer;

    .line 89
    .line 90
    iget-object v3, p1, Ltz/c0;->j:Ljava/lang/Integer;

    .line 91
    .line 92
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    if-nez v1, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    iget-object p0, p0, Ltz/c0;->k:Ljava/lang/Integer;

    .line 100
    .line 101
    iget-object p1, p1, Ltz/c0;->k:Ljava/lang/Integer;

    .line 102
    .line 103
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    if-nez p0, :cond_c

    .line 108
    .line 109
    return v2

    .line 110
    :cond_c
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ltz/c0;->a:Ljava/lang/String;

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
    iget-object v2, p0, Ltz/c0;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Ltz/c0;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Ltz/c0;->d:I

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget v2, p0, Ltz/c0;->e:I

    .line 29
    .line 30
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget v2, p0, Ltz/c0;->f:I

    .line 35
    .line 36
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Ltz/c0;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Ltz/c0;->h:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v2, p0, Ltz/c0;->i:Z

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    const/4 v2, 0x0

    .line 59
    iget-object v3, p0, Ltz/c0;->j:Ljava/lang/Integer;

    .line 60
    .line 61
    if-nez v3, :cond_0

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_0

    .line 65
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    :goto_0
    add-int/2addr v0, v3

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-object p0, p0, Ltz/c0;->k:Ljava/lang/Integer;

    .line 72
    .line 73
    if-nez p0, :cond_1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    :goto_1
    add-int/2addr v0, v2

    .line 81
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", chargeText="

    .line 2
    .line 3
    const-string v1, ", rangeText="

    .line 4
    .line 5
    const-string v2, "Enabled(limitText="

    .line 6
    .line 7
    iget-object v3, p0, Ltz/c0;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Ltz/c0;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", chargePercent="

    .line 16
    .line 17
    const-string v2, ", limitPercent="

    .line 18
    .line 19
    iget-object v3, p0, Ltz/c0;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget v4, p0, Ltz/c0;->d:I

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->z(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", limitPercentSetting="

    .line 27
    .line 28
    const-string v2, ", isPulsing="

    .line 29
    .line 30
    iget v3, p0, Ltz/c0;->e:I

    .line 31
    .line 32
    iget v4, p0, Ltz/c0;->f:I

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", isLimitEnabled="

    .line 38
    .line 39
    const-string v2, ", shouldShowDischargingPulse="

    .line 40
    .line 41
    iget-boolean v3, p0, Ltz/c0;->g:Z

    .line 42
    .line 43
    iget-boolean v4, p0, Ltz/c0;->h:Z

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Ltz/c0;->i:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", minBatteryPercent="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Ltz/c0;->j:Ljava/lang/Integer;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", chargeStateIconResId="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v1, ")"

    .line 69
    .line 70
    iget-object p0, p0, Ltz/c0;->k:Ljava/lang/Integer;

    .line 71
    .line 72
    invoke-static {v0, p0, v1}, Lkx/a;->l(Ljava/lang/StringBuilder;Ljava/lang/Integer;Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

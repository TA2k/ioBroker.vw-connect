.class public final Landroidx/compose/material3/IndicatorLineElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0081\u0008\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/material3/IndicatorLineElement;",
        "Lv3/z0;",
        "Lh2/h5;",
        "material3"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:Z

.field public final c:Z

.field public final d:Li1/l;

.field public final e:Lh2/eb;

.field public final f:Le3/n0;


# direct methods
.method public constructor <init>(ZZLi1/l;Lh2/eb;Le3/n0;)V
    .locals 1

    .line 1
    sget-object v0, Lh2/hb;->a:Lh2/hb;

    .line 2
    .line 3
    sget-object v0, Lh2/hb;->a:Lh2/hb;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    iput-boolean p1, p0, Landroidx/compose/material3/IndicatorLineElement;->b:Z

    .line 9
    .line 10
    iput-boolean p2, p0, Landroidx/compose/material3/IndicatorLineElement;->c:Z

    .line 11
    .line 12
    iput-object p3, p0, Landroidx/compose/material3/IndicatorLineElement;->d:Li1/l;

    .line 13
    .line 14
    iput-object p4, p0, Landroidx/compose/material3/IndicatorLineElement;->e:Lh2/eb;

    .line 15
    .line 16
    iput-object p5, p0, Landroidx/compose/material3/IndicatorLineElement;->f:Le3/n0;

    .line 17
    .line 18
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
    instance-of v0, p1, Landroidx/compose/material3/IndicatorLineElement;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Landroidx/compose/material3/IndicatorLineElement;

    .line 10
    .line 11
    iget-boolean v0, p0, Landroidx/compose/material3/IndicatorLineElement;->b:Z

    .line 12
    .line 13
    iget-boolean v1, p1, Landroidx/compose/material3/IndicatorLineElement;->b:Z

    .line 14
    .line 15
    if-eq v0, v1, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    iget-boolean v0, p0, Landroidx/compose/material3/IndicatorLineElement;->c:Z

    .line 19
    .line 20
    iget-boolean v1, p1, Landroidx/compose/material3/IndicatorLineElement;->c:Z

    .line 21
    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    iget-object v0, p0, Landroidx/compose/material3/IndicatorLineElement;->d:Li1/l;

    .line 26
    .line 27
    iget-object v1, p1, Landroidx/compose/material3/IndicatorLineElement;->d:Li1/l;

    .line 28
    .line 29
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_4

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_4
    iget-object v0, p0, Landroidx/compose/material3/IndicatorLineElement;->e:Lh2/eb;

    .line 37
    .line 38
    iget-object v1, p1, Landroidx/compose/material3/IndicatorLineElement;->e:Lh2/eb;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Lh2/eb;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_5

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_5
    iget-object p0, p0, Landroidx/compose/material3/IndicatorLineElement;->f:Le3/n0;

    .line 48
    .line 49
    iget-object p1, p1, Landroidx/compose/material3/IndicatorLineElement;->f:Le3/n0;

    .line 50
    .line 51
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    if-nez p0, :cond_6

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_6
    sget p0, Lh2/hb;->e:F

    .line 59
    .line 60
    invoke-static {p0, p0}, Lt4/f;->a(FF)Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    if-nez p0, :cond_7

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_7
    sget p0, Lh2/hb;->d:F

    .line 68
    .line 69
    invoke-static {p0, p0}, Lt4/f;->a(FF)Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    if-nez p0, :cond_8

    .line 74
    .line 75
    :goto_0
    const/4 p0, 0x0

    .line 76
    return p0

    .line 77
    :cond_8
    :goto_1
    const/4 p0, 0x1

    .line 78
    return p0
.end method

.method public final h()Lx2/r;
    .locals 6

    .line 1
    new-instance v0, Lh2/h5;

    .line 2
    .line 3
    sget-object v1, Lh2/hb;->a:Lh2/hb;

    .line 4
    .line 5
    sget-object v1, Lh2/hb;->a:Lh2/hb;

    .line 6
    .line 7
    iget-boolean v1, p0, Landroidx/compose/material3/IndicatorLineElement;->b:Z

    .line 8
    .line 9
    iget-boolean v2, p0, Landroidx/compose/material3/IndicatorLineElement;->c:Z

    .line 10
    .line 11
    iget-object v3, p0, Landroidx/compose/material3/IndicatorLineElement;->d:Li1/l;

    .line 12
    .line 13
    iget-object v4, p0, Landroidx/compose/material3/IndicatorLineElement;->e:Lh2/eb;

    .line 14
    .line 15
    iget-object v5, p0, Landroidx/compose/material3/IndicatorLineElement;->f:Le3/n0;

    .line 16
    .line 17
    invoke-direct/range {v0 .. v5}, Lh2/h5;-><init>(ZZLi1/l;Lh2/eb;Le3/n0;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Landroidx/compose/material3/IndicatorLineElement;->b:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-boolean v2, p0, Landroidx/compose/material3/IndicatorLineElement;->c:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Landroidx/compose/material3/IndicatorLineElement;->d:Li1/l;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Landroidx/compose/material3/IndicatorLineElement;->e:Lh2/eb;

    .line 25
    .line 26
    invoke-virtual {v0}, Lh2/eb;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    add-int/2addr v0, v2

    .line 31
    mul-int/2addr v0, v1

    .line 32
    iget-object p0, p0, Landroidx/compose/material3/IndicatorLineElement;->f:Le3/n0;

    .line 33
    .line 34
    if-nez p0, :cond_0

    .line 35
    .line 36
    const/4 p0, 0x0

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    :goto_0
    add-int/2addr v0, p0

    .line 43
    mul-int/2addr v0, v1

    .line 44
    sget p0, Lh2/hb;->e:F

    .line 45
    .line 46
    invoke-static {p0, v0, v1}, La7/g0;->c(FII)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    sget v0, Lh2/hb;->d:F

    .line 51
    .line 52
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    add-int/2addr v0, p0

    .line 57
    return v0
.end method

.method public final j(Lx2/r;)V
    .locals 8

    .line 1
    check-cast p1, Lh2/h5;

    .line 2
    .line 3
    sget v0, Lh2/hb;->e:F

    .line 4
    .line 5
    sget v1, Lh2/hb;->d:F

    .line 6
    .line 7
    iget-boolean v2, p1, Lh2/h5;->t:Z

    .line 8
    .line 9
    iget-boolean v3, p0, Landroidx/compose/material3/IndicatorLineElement;->b:Z

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    if-eq v2, v3, :cond_0

    .line 13
    .line 14
    iput-boolean v3, p1, Lh2/h5;->t:Z

    .line 15
    .line 16
    move v2, v4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v2, 0x0

    .line 19
    :goto_0
    iget-boolean v3, p1, Lh2/h5;->u:Z

    .line 20
    .line 21
    iget-boolean v5, p0, Landroidx/compose/material3/IndicatorLineElement;->c:Z

    .line 22
    .line 23
    if-eq v3, v5, :cond_1

    .line 24
    .line 25
    iput-boolean v5, p1, Lh2/h5;->u:Z

    .line 26
    .line 27
    move v2, v4

    .line 28
    :cond_1
    iget-object v3, p1, Lh2/h5;->v:Li1/l;

    .line 29
    .line 30
    iget-object v5, p0, Landroidx/compose/material3/IndicatorLineElement;->d:Li1/l;

    .line 31
    .line 32
    if-eq v3, v5, :cond_3

    .line 33
    .line 34
    iput-object v5, p1, Lh2/h5;->v:Li1/l;

    .line 35
    .line 36
    iget-object v3, p1, Lh2/h5;->z:Lvy0/x1;

    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    if-eqz v3, :cond_2

    .line 40
    .line 41
    invoke-virtual {v3, v5}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 42
    .line 43
    .line 44
    :cond_2
    invoke-virtual {p1}, Lx2/r;->L0()Lvy0/b0;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    new-instance v6, Lh2/g5;

    .line 49
    .line 50
    const/4 v7, 0x3

    .line 51
    invoke-direct {v6, p1, v5, v7}, Lh2/g5;-><init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    invoke-static {v3, v5, v5, v6, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    iput-object v3, p1, Lh2/h5;->z:Lvy0/x1;

    .line 59
    .line 60
    :cond_3
    iget-object v3, p1, Lh2/h5;->A:Lh2/eb;

    .line 61
    .line 62
    iget-object v5, p0, Landroidx/compose/material3/IndicatorLineElement;->e:Lh2/eb;

    .line 63
    .line 64
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    if-nez v3, :cond_4

    .line 69
    .line 70
    iput-object v5, p1, Lh2/h5;->A:Lh2/eb;

    .line 71
    .line 72
    move v2, v4

    .line 73
    :cond_4
    iget-object v3, p1, Lh2/h5;->C:Le3/n0;

    .line 74
    .line 75
    iget-object p0, p0, Landroidx/compose/material3/IndicatorLineElement;->f:Le3/n0;

    .line 76
    .line 77
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-nez v3, :cond_6

    .line 82
    .line 83
    iget-object v2, p1, Lh2/h5;->C:Le3/n0;

    .line 84
    .line 85
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    if-nez v2, :cond_5

    .line 90
    .line 91
    iput-object p0, p1, Lh2/h5;->C:Le3/n0;

    .line 92
    .line 93
    iget-object p0, p1, Lh2/h5;->E:Lb3/c;

    .line 94
    .line 95
    invoke-virtual {p0}, Lb3/c;->X0()V

    .line 96
    .line 97
    .line 98
    :cond_5
    move v2, v4

    .line 99
    :cond_6
    iget p0, p1, Lh2/h5;->w:F

    .line 100
    .line 101
    invoke-static {p0, v0}, Lt4/f;->a(FF)Z

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-nez p0, :cond_7

    .line 106
    .line 107
    iput v0, p1, Lh2/h5;->w:F

    .line 108
    .line 109
    move v2, v4

    .line 110
    :cond_7
    iget p0, p1, Lh2/h5;->x:F

    .line 111
    .line 112
    invoke-static {p0, v1}, Lt4/f;->a(FF)Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-nez p0, :cond_8

    .line 117
    .line 118
    iput v1, p1, Lh2/h5;->x:F

    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_8
    move v4, v2

    .line 122
    :goto_1
    if-eqz v4, :cond_9

    .line 123
    .line 124
    invoke-virtual {p1}, Lh2/h5;->b1()V

    .line 125
    .line 126
    .line 127
    :cond_9
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "IndicatorLineElement(enabled="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean v1, p0, Landroidx/compose/material3/IndicatorLineElement;->b:Z

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isError="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Landroidx/compose/material3/IndicatorLineElement;->c:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", interactionSource="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Landroidx/compose/material3/IndicatorLineElement;->d:Li1/l;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", colors="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Landroidx/compose/material3/IndicatorLineElement;->e:Lh2/eb;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", textFieldShape="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Landroidx/compose/material3/IndicatorLineElement;->f:Le3/n0;

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string p0, ", focusedIndicatorLineThickness="

    .line 54
    .line 55
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    sget p0, Lh2/hb;->e:F

    .line 59
    .line 60
    const-string v1, ", unfocusedIndicatorLineThickness="

    .line 61
    .line 62
    invoke-static {p0, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->t(FLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 63
    .line 64
    .line 65
    sget p0, Lh2/hb;->d:F

    .line 66
    .line 67
    invoke-static {p0}, Lt4/f;->b(F)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const/16 p0, 0x29

    .line 75
    .line 76
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method

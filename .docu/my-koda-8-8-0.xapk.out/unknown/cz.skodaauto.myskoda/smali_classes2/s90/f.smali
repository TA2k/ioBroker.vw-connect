.class public final Ls90/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Ljava/lang/String;

.field public final i:Ljava/util/List;

.field public final j:Lql0/g;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLjava/lang/String;Ljava/util/List;Lql0/g;)V
    .locals 1

    .line 1
    const-string v0, "checkpoints"

    .line 2
    .line 3
    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ls90/f;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Ls90/f;->b:Ljava/lang/String;

    .line 12
    .line 13
    iput-object p3, p0, Ls90/f;->c:Ljava/lang/String;

    .line 14
    .line 15
    iput-boolean p4, p0, Ls90/f;->d:Z

    .line 16
    .line 17
    iput-boolean p5, p0, Ls90/f;->e:Z

    .line 18
    .line 19
    iput-boolean p6, p0, Ls90/f;->f:Z

    .line 20
    .line 21
    iput-boolean p7, p0, Ls90/f;->g:Z

    .line 22
    .line 23
    iput-object p8, p0, Ls90/f;->h:Ljava/lang/String;

    .line 24
    .line 25
    iput-object p9, p0, Ls90/f;->i:Ljava/util/List;

    .line 26
    .line 27
    iput-object p10, p0, Ls90/f;->j:Lql0/g;

    .line 28
    .line 29
    return-void
.end method

.method public static a(Ls90/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLjava/lang/String;Ljava/util/ArrayList;Lql0/g;I)Ls90/f;
    .locals 11

    .line 1
    move/from16 v0, p11

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Ls90/f;->a:Ljava/lang/String;

    .line 8
    .line 9
    :cond_0
    move-object v1, p1

    .line 10
    and-int/lit8 p1, v0, 0x2

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p2, p0, Ls90/f;->b:Ljava/lang/String;

    .line 15
    .line 16
    :cond_1
    move-object v2, p2

    .line 17
    and-int/lit8 p1, v0, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-object p3, p0, Ls90/f;->c:Ljava/lang/String;

    .line 22
    .line 23
    :cond_2
    move-object v3, p3

    .line 24
    and-int/lit8 p1, v0, 0x8

    .line 25
    .line 26
    if-eqz p1, :cond_3

    .line 27
    .line 28
    iget-boolean p4, p0, Ls90/f;->d:Z

    .line 29
    .line 30
    :cond_3
    move v4, p4

    .line 31
    and-int/lit8 p1, v0, 0x10

    .line 32
    .line 33
    if-eqz p1, :cond_4

    .line 34
    .line 35
    iget-boolean p1, p0, Ls90/f;->e:Z

    .line 36
    .line 37
    move v5, p1

    .line 38
    goto :goto_0

    .line 39
    :cond_4
    move/from16 v5, p5

    .line 40
    .line 41
    :goto_0
    and-int/lit8 p1, v0, 0x20

    .line 42
    .line 43
    if-eqz p1, :cond_5

    .line 44
    .line 45
    iget-boolean p1, p0, Ls90/f;->f:Z

    .line 46
    .line 47
    move v6, p1

    .line 48
    goto :goto_1

    .line 49
    :cond_5
    move/from16 v6, p6

    .line 50
    .line 51
    :goto_1
    and-int/lit8 p1, v0, 0x40

    .line 52
    .line 53
    if-eqz p1, :cond_6

    .line 54
    .line 55
    iget-boolean p1, p0, Ls90/f;->g:Z

    .line 56
    .line 57
    move v7, p1

    .line 58
    goto :goto_2

    .line 59
    :cond_6
    move/from16 v7, p7

    .line 60
    .line 61
    :goto_2
    and-int/lit16 p1, v0, 0x80

    .line 62
    .line 63
    if-eqz p1, :cond_7

    .line 64
    .line 65
    iget-object p1, p0, Ls90/f;->h:Ljava/lang/String;

    .line 66
    .line 67
    move-object v8, p1

    .line 68
    goto :goto_3

    .line 69
    :cond_7
    move-object/from16 v8, p8

    .line 70
    .line 71
    :goto_3
    and-int/lit16 p1, v0, 0x100

    .line 72
    .line 73
    if-eqz p1, :cond_8

    .line 74
    .line 75
    iget-object p1, p0, Ls90/f;->i:Ljava/util/List;

    .line 76
    .line 77
    move-object v9, p1

    .line 78
    goto :goto_4

    .line 79
    :cond_8
    move-object/from16 v9, p9

    .line 80
    .line 81
    :goto_4
    and-int/lit16 p1, v0, 0x200

    .line 82
    .line 83
    if-eqz p1, :cond_9

    .line 84
    .line 85
    iget-object p1, p0, Ls90/f;->j:Lql0/g;

    .line 86
    .line 87
    move-object v10, p1

    .line 88
    goto :goto_5

    .line 89
    :cond_9
    move-object/from16 v10, p10

    .line 90
    .line 91
    :goto_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    const-string p0, "checkpoints"

    .line 95
    .line 96
    invoke-static {v9, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    new-instance v0, Ls90/f;

    .line 100
    .line 101
    invoke-direct/range {v0 .. v10}, Ls90/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLjava/lang/String;Ljava/util/List;Lql0/g;)V

    .line 102
    .line 103
    .line 104
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
    instance-of v1, p1, Ls90/f;

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
    check-cast p1, Ls90/f;

    .line 12
    .line 13
    iget-object v1, p1, Ls90/f;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p0, Ls90/f;->a:Ljava/lang/String;

    .line 16
    .line 17
    if-nez v3, :cond_3

    .line 18
    .line 19
    if-nez v1, :cond_2

    .line 20
    .line 21
    move v1, v0

    .line 22
    goto :goto_1

    .line 23
    :cond_2
    :goto_0
    move v1, v2

    .line 24
    goto :goto_1

    .line 25
    :cond_3
    if-nez v1, :cond_4

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_4
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    :goto_1
    if-nez v1, :cond_5

    .line 33
    .line 34
    return v2

    .line 35
    :cond_5
    iget-object v1, p0, Ls90/f;->b:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Ls90/f;->b:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_6

    .line 44
    .line 45
    return v2

    .line 46
    :cond_6
    iget-object v1, p0, Ls90/f;->c:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Ls90/f;->c:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_7

    .line 55
    .line 56
    return v2

    .line 57
    :cond_7
    iget-boolean v1, p0, Ls90/f;->d:Z

    .line 58
    .line 59
    iget-boolean v3, p1, Ls90/f;->d:Z

    .line 60
    .line 61
    if-eq v1, v3, :cond_8

    .line 62
    .line 63
    return v2

    .line 64
    :cond_8
    iget-boolean v1, p0, Ls90/f;->e:Z

    .line 65
    .line 66
    iget-boolean v3, p1, Ls90/f;->e:Z

    .line 67
    .line 68
    if-eq v1, v3, :cond_9

    .line 69
    .line 70
    return v2

    .line 71
    :cond_9
    iget-boolean v1, p0, Ls90/f;->f:Z

    .line 72
    .line 73
    iget-boolean v3, p1, Ls90/f;->f:Z

    .line 74
    .line 75
    if-eq v1, v3, :cond_a

    .line 76
    .line 77
    return v2

    .line 78
    :cond_a
    iget-boolean v1, p0, Ls90/f;->g:Z

    .line 79
    .line 80
    iget-boolean v3, p1, Ls90/f;->g:Z

    .line 81
    .line 82
    if-eq v1, v3, :cond_b

    .line 83
    .line 84
    return v2

    .line 85
    :cond_b
    iget-object v1, p0, Ls90/f;->h:Ljava/lang/String;

    .line 86
    .line 87
    iget-object v3, p1, Ls90/f;->h:Ljava/lang/String;

    .line 88
    .line 89
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_c

    .line 94
    .line 95
    return v2

    .line 96
    :cond_c
    iget-object v1, p0, Ls90/f;->i:Ljava/util/List;

    .line 97
    .line 98
    iget-object v3, p1, Ls90/f;->i:Ljava/util/List;

    .line 99
    .line 100
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-nez v1, :cond_d

    .line 105
    .line 106
    return v2

    .line 107
    :cond_d
    iget-object p0, p0, Ls90/f;->j:Lql0/g;

    .line 108
    .line 109
    iget-object p1, p1, Ls90/f;->j:Lql0/g;

    .line 110
    .line 111
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-nez p0, :cond_e

    .line 116
    .line 117
    return v2

    .line 118
    :cond_e
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ls90/f;->a:Ljava/lang/String;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v1, v2

    .line 15
    iget-object v3, p0, Ls90/f;->b:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iget-object v3, p0, Ls90/f;->c:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget-boolean v3, p0, Ls90/f;->d:Z

    .line 28
    .line 29
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    iget-boolean v3, p0, Ls90/f;->e:Z

    .line 34
    .line 35
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    iget-boolean v3, p0, Ls90/f;->f:Z

    .line 40
    .line 41
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    iget-boolean v3, p0, Ls90/f;->g:Z

    .line 46
    .line 47
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    iget-object v3, p0, Ls90/f;->h:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    iget-object v3, p0, Ls90/f;->i:Ljava/util/List;

    .line 58
    .line 59
    invoke-static {v1, v2, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    iget-object p0, p0, Ls90/f;->j:Lql0/g;

    .line 64
    .line 65
    if-nez p0, :cond_1

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    invoke-virtual {p0}, Lql0/g;->hashCode()I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    :goto_1
    add-int/2addr v1, v0

    .line 73
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Ls90/f;->a:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "null"

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-static {v0}, Lss0/j0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    :goto_0
    const-string v1, ", deliveryDate="

    .line 13
    .line 14
    const-string v2, ", orderStatusName="

    .line 15
    .line 16
    const-string v3, "State(vin="

    .line 17
    .line 18
    iget-object v4, p0, Ls90/f;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {v3, v0, v1, v4, v2}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v1, ", isLoading="

    .line 25
    .line 26
    const-string v2, ", isRefreshing="

    .line 27
    .line 28
    iget-object v3, p0, Ls90/f;->c:Ljava/lang/String;

    .line 29
    .line 30
    iget-boolean v4, p0, Ls90/f;->d:Z

    .line 31
    .line 32
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 33
    .line 34
    .line 35
    const-string v1, ", isDataUnavailable="

    .line 36
    .line 37
    const-string v2, ", showActivateButton="

    .line 38
    .line 39
    iget-boolean v3, p0, Ls90/f;->e:Z

    .line 40
    .line 41
    iget-boolean v4, p0, Ls90/f;->f:Z

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v1, ", activateButtonText="

    .line 47
    .line 48
    const-string v2, ", checkpoints="

    .line 49
    .line 50
    iget-object v3, p0, Ls90/f;->h:Ljava/lang/String;

    .line 51
    .line 52
    iget-boolean v4, p0, Ls90/f;->g:Z

    .line 53
    .line 54
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Ls90/f;->i:Ljava/util/List;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", error="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Ls90/f;->j:Lql0/g;

    .line 68
    .line 69
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string p0, ")"

    .line 73
    .line 74
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method

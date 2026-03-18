.class public final Lbv0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Z

.field public final e:Ljava/lang/String;

.field public final f:Z

.field public final g:Z

.field public final h:I

.field public final i:Z

.field public final j:Lql0/g;


# direct methods
.method public constructor <init>(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZZIZLql0/g;)V
    .locals 1

    .line 1
    const-string v0, "renders"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lbv0/c;->a:Ljava/util/List;

    .line 10
    .line 11
    iput-object p2, p0, Lbv0/c;->b:Ljava/lang/String;

    .line 12
    .line 13
    iput-object p3, p0, Lbv0/c;->c:Ljava/lang/String;

    .line 14
    .line 15
    iput-boolean p4, p0, Lbv0/c;->d:Z

    .line 16
    .line 17
    iput-object p5, p0, Lbv0/c;->e:Ljava/lang/String;

    .line 18
    .line 19
    iput-boolean p6, p0, Lbv0/c;->f:Z

    .line 20
    .line 21
    iput-boolean p7, p0, Lbv0/c;->g:Z

    .line 22
    .line 23
    iput p8, p0, Lbv0/c;->h:I

    .line 24
    .line 25
    iput-boolean p9, p0, Lbv0/c;->i:Z

    .line 26
    .line 27
    iput-object p10, p0, Lbv0/c;->j:Lql0/g;

    .line 28
    .line 29
    return-void
.end method

.method public static a(Lbv0/c;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZZIZLql0/g;I)Lbv0/c;
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
    iget-object p1, p0, Lbv0/c;->a:Ljava/util/List;

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
    iget-object p2, p0, Lbv0/c;->b:Ljava/lang/String;

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
    iget-object p3, p0, Lbv0/c;->c:Ljava/lang/String;

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
    iget-boolean p4, p0, Lbv0/c;->d:Z

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
    iget-object p1, p0, Lbv0/c;->e:Ljava/lang/String;

    .line 36
    .line 37
    move-object v5, p1

    .line 38
    goto :goto_0

    .line 39
    :cond_4
    move-object/from16 v5, p5

    .line 40
    .line 41
    :goto_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    and-int/lit8 p1, v0, 0x40

    .line 45
    .line 46
    if-eqz p1, :cond_5

    .line 47
    .line 48
    iget-boolean p1, p0, Lbv0/c;->f:Z

    .line 49
    .line 50
    move v6, p1

    .line 51
    goto :goto_1

    .line 52
    :cond_5
    move/from16 v6, p6

    .line 53
    .line 54
    :goto_1
    and-int/lit16 p1, v0, 0x80

    .line 55
    .line 56
    if-eqz p1, :cond_6

    .line 57
    .line 58
    iget-boolean p1, p0, Lbv0/c;->g:Z

    .line 59
    .line 60
    move v7, p1

    .line 61
    goto :goto_2

    .line 62
    :cond_6
    move/from16 v7, p7

    .line 63
    .line 64
    :goto_2
    and-int/lit16 p1, v0, 0x100

    .line 65
    .line 66
    if-eqz p1, :cond_7

    .line 67
    .line 68
    iget p1, p0, Lbv0/c;->h:I

    .line 69
    .line 70
    move v8, p1

    .line 71
    goto :goto_3

    .line 72
    :cond_7
    move/from16 v8, p8

    .line 73
    .line 74
    :goto_3
    and-int/lit16 p1, v0, 0x200

    .line 75
    .line 76
    if-eqz p1, :cond_8

    .line 77
    .line 78
    iget-boolean p1, p0, Lbv0/c;->i:Z

    .line 79
    .line 80
    move v9, p1

    .line 81
    goto :goto_4

    .line 82
    :cond_8
    move/from16 v9, p9

    .line 83
    .line 84
    :goto_4
    and-int/lit16 p1, v0, 0x400

    .line 85
    .line 86
    if-eqz p1, :cond_9

    .line 87
    .line 88
    iget-object p1, p0, Lbv0/c;->j:Lql0/g;

    .line 89
    .line 90
    move-object v10, p1

    .line 91
    goto :goto_5

    .line 92
    :cond_9
    move-object/from16 v10, p10

    .line 93
    .line 94
    :goto_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    const-string p0, "renders"

    .line 98
    .line 99
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    const-string p0, "vehicleName"

    .line 103
    .line 104
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    new-instance v0, Lbv0/c;

    .line 108
    .line 109
    invoke-direct/range {v0 .. v10}, Lbv0/c;-><init>(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZZIZLql0/g;)V

    .line 110
    .line 111
    .line 112
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
    goto/16 :goto_3

    .line 5
    .line 6
    :cond_0
    instance-of v1, p1, Lbv0/c;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    goto/16 :goto_2

    .line 12
    .line 13
    :cond_1
    check-cast p1, Lbv0/c;

    .line 14
    .line 15
    iget-object v1, p0, Lbv0/c;->a:Ljava/util/List;

    .line 16
    .line 17
    iget-object v3, p1, Lbv0/c;->a:Ljava/util/List;

    .line 18
    .line 19
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-nez v1, :cond_2

    .line 24
    .line 25
    goto/16 :goto_2

    .line 26
    .line 27
    :cond_2
    iget-object v1, p0, Lbv0/c;->b:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v3, p1, Lbv0/c;->b:Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v1, :cond_3

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_3
    iget-object v1, p1, Lbv0/c;->c:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v3, p0, Lbv0/c;->c:Ljava/lang/String;

    .line 41
    .line 42
    if-nez v3, :cond_5

    .line 43
    .line 44
    if-nez v1, :cond_4

    .line 45
    .line 46
    move v1, v0

    .line 47
    goto :goto_1

    .line 48
    :cond_4
    :goto_0
    move v1, v2

    .line 49
    goto :goto_1

    .line 50
    :cond_5
    if-nez v1, :cond_6

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_6
    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    :goto_1
    if-nez v1, :cond_7

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_7
    iget-boolean v1, p0, Lbv0/c;->d:Z

    .line 61
    .line 62
    iget-boolean v3, p1, Lbv0/c;->d:Z

    .line 63
    .line 64
    if-eq v1, v3, :cond_8

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_8
    iget-object v1, p0, Lbv0/c;->e:Ljava/lang/String;

    .line 68
    .line 69
    iget-object v3, p1, Lbv0/c;->e:Ljava/lang/String;

    .line 70
    .line 71
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_9

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_9
    iget-boolean v1, p0, Lbv0/c;->f:Z

    .line 79
    .line 80
    iget-boolean v3, p1, Lbv0/c;->f:Z

    .line 81
    .line 82
    if-eq v1, v3, :cond_a

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_a
    iget-boolean v1, p0, Lbv0/c;->g:Z

    .line 86
    .line 87
    iget-boolean v3, p1, Lbv0/c;->g:Z

    .line 88
    .line 89
    if-eq v1, v3, :cond_b

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_b
    iget v1, p0, Lbv0/c;->h:I

    .line 93
    .line 94
    iget v3, p1, Lbv0/c;->h:I

    .line 95
    .line 96
    if-eq v1, v3, :cond_c

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_c
    iget-boolean v1, p0, Lbv0/c;->i:Z

    .line 100
    .line 101
    iget-boolean v3, p1, Lbv0/c;->i:Z

    .line 102
    .line 103
    if-eq v1, v3, :cond_d

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_d
    iget-object p0, p0, Lbv0/c;->j:Lql0/g;

    .line 107
    .line 108
    iget-object p1, p1, Lbv0/c;->j:Lql0/g;

    .line 109
    .line 110
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    if-nez p0, :cond_e

    .line 115
    .line 116
    :goto_2
    return v2

    .line 117
    :cond_e
    :goto_3
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lbv0/c;->a:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Lbv0/c;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v2, 0x0

    .line 17
    iget-object v3, p0, Lbv0/c;->c:Ljava/lang/String;

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    move v3, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_0
    add-int/2addr v0, v3

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-boolean v3, p0, Lbv0/c;->d:Z

    .line 30
    .line 31
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-object v3, p0, Lbv0/c;->e:Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    iget-boolean v3, p0, Lbv0/c;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    iget-boolean v3, p0, Lbv0/c;->g:Z

    .line 52
    .line 53
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    iget v3, p0, Lbv0/c;->h:I

    .line 58
    .line 59
    invoke-static {v3, v0, v1}, Lc1/j0;->g(III)I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    iget-boolean v3, p0, Lbv0/c;->i:Z

    .line 64
    .line 65
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    iget-object p0, p0, Lbv0/c;->j:Lql0/g;

    .line 70
    .line 71
    if-nez p0, :cond_1

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    invoke-virtual {p0}, Lql0/g;->hashCode()I

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    :goto_1
    add-int/2addr v0, v2

    .line 79
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lbv0/c;->c:Ljava/lang/String;

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
    new-instance v1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v2, "State(renders="

    .line 15
    .line 16
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v2, p0, Lbv0/c;->a:Ljava/util/List;

    .line 20
    .line 21
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string v2, ", vehicleName="

    .line 25
    .line 26
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    iget-object v2, p0, Lbv0/c;->b:Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v2, ", vin="

    .line 35
    .line 36
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v2, ", isActivationButtonVisible="

    .line 40
    .line 41
    const-string v3, ", activationButtonText="

    .line 42
    .line 43
    iget-boolean v4, p0, Lbv0/c;->d:Z

    .line 44
    .line 45
    invoke-static {v0, v2, v3, v1, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, ", currentPage=0, isLoading="

    .line 49
    .line 50
    const-string v2, ", isRefreshing="

    .line 51
    .line 52
    iget-object v3, p0, Lbv0/c;->e:Ljava/lang/String;

    .line 53
    .line 54
    iget-boolean v4, p0, Lbv0/c;->f:Z

    .line 55
    .line 56
    invoke-static {v3, v0, v2, v1, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 57
    .line 58
    .line 59
    iget-boolean v0, p0, Lbv0/c;->g:Z

    .line 60
    .line 61
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v0, ", selectedImageIndex="

    .line 65
    .line 66
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget v0, p0, Lbv0/c;->h:I

    .line 70
    .line 71
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v0, ", isClickHintVisible="

    .line 75
    .line 76
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-boolean v0, p0, Lbv0/c;->i:Z

    .line 80
    .line 81
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v0, ", error="

    .line 85
    .line 86
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object p0, p0, Lbv0/c;->j:Lql0/g;

    .line 90
    .line 91
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string p0, ")"

    .line 95
    .line 96
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method

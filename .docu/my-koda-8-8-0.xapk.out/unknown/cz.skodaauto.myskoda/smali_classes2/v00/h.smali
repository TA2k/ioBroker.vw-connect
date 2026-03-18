.class public final Lv00/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Z

.field public final c:Z

.field public final d:Ljava/lang/String;

.field public final e:Z

.field public final f:Lmh0/b;

.field public final g:I

.field public final h:Ljava/util/List;

.field public final i:Z

.field public final j:Z

.field public final k:Lv00/g;


# direct methods
.method public constructor <init>(Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;)V
    .locals 1

    .line 1
    const-string v0, "selectedCategory"

    .line 2
    .line 3
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "feedbackProgress"

    .line 7
    .line 8
    invoke-static {p11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lv00/h;->a:Ljava/lang/String;

    .line 15
    .line 16
    iput-boolean p2, p0, Lv00/h;->b:Z

    .line 17
    .line 18
    iput-boolean p3, p0, Lv00/h;->c:Z

    .line 19
    .line 20
    iput-object p4, p0, Lv00/h;->d:Ljava/lang/String;

    .line 21
    .line 22
    iput-boolean p5, p0, Lv00/h;->e:Z

    .line 23
    .line 24
    iput-object p6, p0, Lv00/h;->f:Lmh0/b;

    .line 25
    .line 26
    iput p7, p0, Lv00/h;->g:I

    .line 27
    .line 28
    iput-object p8, p0, Lv00/h;->h:Ljava/util/List;

    .line 29
    .line 30
    iput-boolean p9, p0, Lv00/h;->i:Z

    .line 31
    .line 32
    iput-boolean p10, p0, Lv00/h;->j:Z

    .line 33
    .line 34
    iput-object p11, p0, Lv00/h;->k:Lv00/g;

    .line 35
    .line 36
    return-void
.end method

.method public static a(Lv00/h;Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;I)Lv00/h;
    .locals 12

    .line 1
    move/from16 v0, p12

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lv00/h;->a:Ljava/lang/String;

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
    iget-boolean p2, p0, Lv00/h;->b:Z

    .line 15
    .line 16
    :cond_1
    move v2, p2

    .line 17
    and-int/lit8 p1, v0, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-boolean p3, p0, Lv00/h;->c:Z

    .line 22
    .line 23
    :cond_2
    move v3, p3

    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    and-int/lit8 p1, v0, 0x10

    .line 28
    .line 29
    if-eqz p1, :cond_3

    .line 30
    .line 31
    iget-object p1, p0, Lv00/h;->d:Ljava/lang/String;

    .line 32
    .line 33
    move-object v4, p1

    .line 34
    goto :goto_0

    .line 35
    :cond_3
    move-object/from16 v4, p4

    .line 36
    .line 37
    :goto_0
    and-int/lit8 p1, v0, 0x20

    .line 38
    .line 39
    if-eqz p1, :cond_4

    .line 40
    .line 41
    iget-boolean p1, p0, Lv00/h;->e:Z

    .line 42
    .line 43
    move v5, p1

    .line 44
    goto :goto_1

    .line 45
    :cond_4
    move/from16 v5, p5

    .line 46
    .line 47
    :goto_1
    and-int/lit8 p1, v0, 0x40

    .line 48
    .line 49
    if-eqz p1, :cond_5

    .line 50
    .line 51
    iget-object p1, p0, Lv00/h;->f:Lmh0/b;

    .line 52
    .line 53
    move-object v6, p1

    .line 54
    goto :goto_2

    .line 55
    :cond_5
    move-object/from16 v6, p6

    .line 56
    .line 57
    :goto_2
    and-int/lit16 p1, v0, 0x80

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget p1, p0, Lv00/h;->g:I

    .line 62
    .line 63
    move v7, p1

    .line 64
    goto :goto_3

    .line 65
    :cond_6
    move/from16 v7, p7

    .line 66
    .line 67
    :goto_3
    and-int/lit16 p1, v0, 0x100

    .line 68
    .line 69
    if-eqz p1, :cond_7

    .line 70
    .line 71
    iget-object p1, p0, Lv00/h;->h:Ljava/util/List;

    .line 72
    .line 73
    move-object v8, p1

    .line 74
    goto :goto_4

    .line 75
    :cond_7
    move-object/from16 v8, p8

    .line 76
    .line 77
    :goto_4
    and-int/lit16 p1, v0, 0x200

    .line 78
    .line 79
    if-eqz p1, :cond_8

    .line 80
    .line 81
    iget-boolean p1, p0, Lv00/h;->i:Z

    .line 82
    .line 83
    move v9, p1

    .line 84
    goto :goto_5

    .line 85
    :cond_8
    move/from16 v9, p9

    .line 86
    .line 87
    :goto_5
    and-int/lit16 p1, v0, 0x400

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    iget-boolean p1, p0, Lv00/h;->j:Z

    .line 92
    .line 93
    move v10, p1

    .line 94
    goto :goto_6

    .line 95
    :cond_9
    move/from16 v10, p10

    .line 96
    .line 97
    :goto_6
    and-int/lit16 p1, v0, 0x800

    .line 98
    .line 99
    if-eqz p1, :cond_a

    .line 100
    .line 101
    iget-object p1, p0, Lv00/h;->k:Lv00/g;

    .line 102
    .line 103
    move-object v11, p1

    .line 104
    goto :goto_7

    .line 105
    :cond_a
    move-object/from16 v11, p11

    .line 106
    .line 107
    :goto_7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    const-string p0, "feedback"

    .line 111
    .line 112
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    const-string p0, "personalInfoLink"

    .line 116
    .line 117
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    const-string p0, "selectedCategory"

    .line 121
    .line 122
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    const-string p0, "feedbackProgress"

    .line 126
    .line 127
    invoke-static {v11, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    new-instance v0, Lv00/h;

    .line 131
    .line 132
    invoke-direct/range {v0 .. v11}, Lv00/h;-><init>(Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;)V

    .line 133
    .line 134
    .line 135
    return-object v0
.end method


# virtual methods
.method public final b()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lv00/h;->f:Lmh0/b;

    .line 2
    .line 3
    sget-object v0, Lmh0/b;->m:Lmh0/b;

    .line 4
    .line 5
    if-eq p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

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
    instance-of v0, p1, Lv00/h;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lv00/h;

    .line 12
    .line 13
    iget-object v0, p0, Lv00/h;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p1, Lv00/h;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_2
    iget-boolean v0, p0, Lv00/h;->b:Z

    .line 25
    .line 26
    iget-boolean v1, p1, Lv00/h;->b:Z

    .line 27
    .line 28
    if-eq v0, v1, :cond_3

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_3
    iget-boolean v0, p0, Lv00/h;->c:Z

    .line 32
    .line 33
    iget-boolean v1, p1, Lv00/h;->c:Z

    .line 34
    .line 35
    if-eq v0, v1, :cond_4

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_4
    iget-object v0, p0, Lv00/h;->d:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v1, p1, Lv00/h;->d:Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-nez v0, :cond_5

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_5
    iget-boolean v0, p0, Lv00/h;->e:Z

    .line 50
    .line 51
    iget-boolean v1, p1, Lv00/h;->e:Z

    .line 52
    .line 53
    if-eq v0, v1, :cond_6

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_6
    iget-object v0, p0, Lv00/h;->f:Lmh0/b;

    .line 57
    .line 58
    iget-object v1, p1, Lv00/h;->f:Lmh0/b;

    .line 59
    .line 60
    if-eq v0, v1, :cond_7

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_7
    iget v0, p0, Lv00/h;->g:I

    .line 64
    .line 65
    iget v1, p1, Lv00/h;->g:I

    .line 66
    .line 67
    if-eq v0, v1, :cond_8

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_8
    iget-object v0, p0, Lv00/h;->h:Ljava/util/List;

    .line 71
    .line 72
    iget-object v1, p1, Lv00/h;->h:Ljava/util/List;

    .line 73
    .line 74
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-nez v0, :cond_9

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_9
    iget-boolean v0, p0, Lv00/h;->i:Z

    .line 82
    .line 83
    iget-boolean v1, p1, Lv00/h;->i:Z

    .line 84
    .line 85
    if-eq v0, v1, :cond_a

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_a
    iget-boolean v0, p0, Lv00/h;->j:Z

    .line 89
    .line 90
    iget-boolean v1, p1, Lv00/h;->j:Z

    .line 91
    .line 92
    if-eq v0, v1, :cond_b

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_b
    iget-object p0, p0, Lv00/h;->k:Lv00/g;

    .line 96
    .line 97
    iget-object p1, p1, Lv00/h;->k:Lv00/g;

    .line 98
    .line 99
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    if-nez p0, :cond_c

    .line 104
    .line 105
    :goto_0
    const/4 p0, 0x0

    .line 106
    return p0

    .line 107
    :cond_c
    :goto_1
    const/4 p0, 0x1

    .line 108
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lv00/h;->a:Ljava/lang/String;

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
    iget-boolean v2, p0, Lv00/h;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lv00/h;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v2, 0x5

    .line 23
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    iget-object v2, p0, Lv00/h;->d:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    iget-boolean v2, p0, Lv00/h;->e:Z

    .line 34
    .line 35
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    iget-object v2, p0, Lv00/h;->f:Lmh0/b;

    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    add-int/2addr v2, v0

    .line 46
    mul-int/2addr v2, v1

    .line 47
    iget v0, p0, Lv00/h;->g:I

    .line 48
    .line 49
    invoke-static {v0, v2, v1}, Lc1/j0;->g(III)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-object v2, p0, Lv00/h;->h:Ljava/util/List;

    .line 54
    .line 55
    if-nez v2, :cond_0

    .line 56
    .line 57
    const/4 v2, 0x0

    .line 58
    goto :goto_0

    .line 59
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    :goto_0
    add-int/2addr v0, v2

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-boolean v2, p0, Lv00/h;->i:Z

    .line 66
    .line 67
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    iget-boolean v2, p0, Lv00/h;->j:Z

    .line 72
    .line 73
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget-object p0, p0, Lv00/h;->k:Lv00/g;

    .line 78
    .line 79
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    add-int/2addr p0, v0

    .line 84
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", hideBottomSheet="

    .line 2
    .line 3
    const-string v1, ", isDebug="

    .line 4
    .line 5
    const-string v2, "State(feedback="

    .line 6
    .line 7
    iget-object v3, p0, Lv00/h;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Lv00/h;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", maxRating=5, personalInfoLink="

    .line 16
    .line 17
    const-string v2, ", isDeeplink="

    .line 18
    .line 19
    iget-object v3, p0, Lv00/h;->d:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v4, p0, Lv00/h;->c:Z

    .line 22
    .line 23
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 24
    .line 25
    .line 26
    iget-boolean v1, p0, Lv00/h;->e:Z

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", selectedCategory="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lv00/h;->f:Lmh0/b;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", selectedRating="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget v1, p0, Lv00/h;->g:I

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", selectedPhotos="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lv00/h;->h:Ljava/util/List;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", showBottomSheet="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", wantsToBeContacted="

    .line 67
    .line 68
    const-string v2, ", feedbackProgress="

    .line 69
    .line 70
    iget-boolean v3, p0, Lv00/h;->i:Z

    .line 71
    .line 72
    iget-boolean v4, p0, Lv00/h;->j:Z

    .line 73
    .line 74
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lv00/h;->k:Lv00/g;

    .line 78
    .line 79
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string p0, ")"

    .line 83
    .line 84
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0
.end method

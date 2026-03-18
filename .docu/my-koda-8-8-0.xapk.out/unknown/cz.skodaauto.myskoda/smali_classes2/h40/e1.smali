.class public final Lh40/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Z

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Landroid/net/Uri;

.field public final f:I

.field public final g:Z

.field public final h:Ljava/time/LocalDate;

.field public final i:Lh40/d1;

.field public final j:Ljava/lang/String;

.field public final k:Z

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Z

.field public final o:Z


# direct methods
.method public constructor <init>(Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;ZLjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh40/e1;->a:Lql0/g;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh40/e1;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Lh40/e1;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lh40/e1;->d:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lh40/e1;->e:Landroid/net/Uri;

    .line 13
    .line 14
    iput p6, p0, Lh40/e1;->f:I

    .line 15
    .line 16
    iput-boolean p7, p0, Lh40/e1;->g:Z

    .line 17
    .line 18
    iput-object p8, p0, Lh40/e1;->h:Ljava/time/LocalDate;

    .line 19
    .line 20
    iput-object p9, p0, Lh40/e1;->i:Lh40/d1;

    .line 21
    .line 22
    iput-object p10, p0, Lh40/e1;->j:Ljava/lang/String;

    .line 23
    .line 24
    iput-boolean p11, p0, Lh40/e1;->k:Z

    .line 25
    .line 26
    iput-object p12, p0, Lh40/e1;->l:Ljava/lang/String;

    .line 27
    .line 28
    const/4 p1, 0x0

    .line 29
    if-eqz p8, :cond_0

    .line 30
    .line 31
    invoke-static {p8}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move-object p2, p1

    .line 37
    :goto_0
    iput-object p2, p0, Lh40/e1;->m:Ljava/lang/String;

    .line 38
    .line 39
    const/4 p2, 0x0

    .line 40
    const/4 p3, 0x1

    .line 41
    if-eqz p12, :cond_2

    .line 42
    .line 43
    if-eqz p9, :cond_1

    .line 44
    .line 45
    iget-object p1, p9, Lh40/d1;->d:Ljava/lang/String;

    .line 46
    .line 47
    :cond_1
    invoke-static {p1, p12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-eqz p1, :cond_2

    .line 52
    .line 53
    move p1, p3

    .line 54
    goto :goto_1

    .line 55
    :cond_2
    move p1, p2

    .line 56
    :goto_1
    iput-boolean p1, p0, Lh40/e1;->n:Z

    .line 57
    .line 58
    if-eqz p8, :cond_3

    .line 59
    .line 60
    if-eqz p9, :cond_3

    .line 61
    .line 62
    if-eqz p1, :cond_3

    .line 63
    .line 64
    move p2, p3

    .line 65
    :cond_3
    iput-boolean p2, p0, Lh40/e1;->o:Z

    .line 66
    .line 67
    return-void
.end method

.method public static a(Lh40/e1;Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;Ljava/lang/String;I)Lh40/e1;
    .locals 13

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
    iget-object p1, p0, Lh40/e1;->a:Lql0/g;

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
    iget-boolean p2, p0, Lh40/e1;->b:Z

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
    iget-object p1, p0, Lh40/e1;->c:Ljava/lang/String;

    .line 22
    .line 23
    move-object v3, p1

    .line 24
    goto :goto_0

    .line 25
    :cond_2
    move-object/from16 v3, p3

    .line 26
    .line 27
    :goto_0
    and-int/lit8 p1, v0, 0x8

    .line 28
    .line 29
    if-eqz p1, :cond_3

    .line 30
    .line 31
    iget-object p1, p0, Lh40/e1;->d:Ljava/lang/String;

    .line 32
    .line 33
    move-object v4, p1

    .line 34
    goto :goto_1

    .line 35
    :cond_3
    move-object/from16 v4, p4

    .line 36
    .line 37
    :goto_1
    and-int/lit8 p1, v0, 0x10

    .line 38
    .line 39
    if-eqz p1, :cond_4

    .line 40
    .line 41
    iget-object p1, p0, Lh40/e1;->e:Landroid/net/Uri;

    .line 42
    .line 43
    move-object v5, p1

    .line 44
    goto :goto_2

    .line 45
    :cond_4
    move-object/from16 v5, p5

    .line 46
    .line 47
    :goto_2
    and-int/lit8 p1, v0, 0x20

    .line 48
    .line 49
    if-eqz p1, :cond_5

    .line 50
    .line 51
    iget p1, p0, Lh40/e1;->f:I

    .line 52
    .line 53
    move v6, p1

    .line 54
    goto :goto_3

    .line 55
    :cond_5
    move/from16 v6, p6

    .line 56
    .line 57
    :goto_3
    and-int/lit8 p1, v0, 0x40

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget-boolean p1, p0, Lh40/e1;->g:Z

    .line 62
    .line 63
    move v7, p1

    .line 64
    goto :goto_4

    .line 65
    :cond_6
    move/from16 v7, p7

    .line 66
    .line 67
    :goto_4
    and-int/lit16 p1, v0, 0x80

    .line 68
    .line 69
    if-eqz p1, :cond_7

    .line 70
    .line 71
    iget-object p1, p0, Lh40/e1;->h:Ljava/time/LocalDate;

    .line 72
    .line 73
    move-object v8, p1

    .line 74
    goto :goto_5

    .line 75
    :cond_7
    move-object/from16 v8, p8

    .line 76
    .line 77
    :goto_5
    and-int/lit16 p1, v0, 0x100

    .line 78
    .line 79
    if-eqz p1, :cond_8

    .line 80
    .line 81
    iget-object p1, p0, Lh40/e1;->i:Lh40/d1;

    .line 82
    .line 83
    move-object v9, p1

    .line 84
    goto :goto_6

    .line 85
    :cond_8
    move-object/from16 v9, p9

    .line 86
    .line 87
    :goto_6
    and-int/lit16 p1, v0, 0x200

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    iget-object p1, p0, Lh40/e1;->j:Ljava/lang/String;

    .line 92
    .line 93
    move-object v10, p1

    .line 94
    goto :goto_7

    .line 95
    :cond_9
    move-object/from16 v10, p10

    .line 96
    .line 97
    :goto_7
    and-int/lit16 p1, v0, 0x400

    .line 98
    .line 99
    if-eqz p1, :cond_a

    .line 100
    .line 101
    iget-boolean p1, p0, Lh40/e1;->k:Z

    .line 102
    .line 103
    :goto_8
    move v11, p1

    .line 104
    goto :goto_9

    .line 105
    :cond_a
    const/4 p1, 0x0

    .line 106
    goto :goto_8

    .line 107
    :goto_9
    and-int/lit16 p1, v0, 0x800

    .line 108
    .line 109
    if-eqz p1, :cond_b

    .line 110
    .line 111
    iget-object p1, p0, Lh40/e1;->l:Ljava/lang/String;

    .line 112
    .line 113
    move-object v12, p1

    .line 114
    goto :goto_a

    .line 115
    :cond_b
    move-object/from16 v12, p11

    .line 116
    .line 117
    :goto_a
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    const-string p0, "rewardId"

    .line 121
    .line 122
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    const-string p0, "rewardName"

    .line 126
    .line 127
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    new-instance v0, Lh40/e1;

    .line 131
    .line 132
    invoke-direct/range {v0 .. v12}, Lh40/e1;-><init>(Lql0/g;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;IZLjava/time/LocalDate;Lh40/d1;Ljava/lang/String;ZLjava/lang/String;)V

    .line 133
    .line 134
    .line 135
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
    instance-of v1, p1, Lh40/e1;

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
    check-cast p1, Lh40/e1;

    .line 12
    .line 13
    iget-object v1, p0, Lh40/e1;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lh40/e1;->a:Lql0/g;

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
    iget-boolean v1, p0, Lh40/e1;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lh40/e1;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lh40/e1;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lh40/e1;->c:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lh40/e1;->d:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lh40/e1;->d:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lh40/e1;->e:Landroid/net/Uri;

    .line 54
    .line 55
    iget-object v3, p1, Lh40/e1;->e:Landroid/net/Uri;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget v1, p0, Lh40/e1;->f:I

    .line 65
    .line 66
    iget v3, p1, Lh40/e1;->f:I

    .line 67
    .line 68
    if-eq v1, v3, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-boolean v1, p0, Lh40/e1;->g:Z

    .line 72
    .line 73
    iget-boolean v3, p1, Lh40/e1;->g:Z

    .line 74
    .line 75
    if-eq v1, v3, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    iget-object v1, p0, Lh40/e1;->h:Ljava/time/LocalDate;

    .line 79
    .line 80
    iget-object v3, p1, Lh40/e1;->h:Ljava/time/LocalDate;

    .line 81
    .line 82
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    if-nez v1, :cond_9

    .line 87
    .line 88
    return v2

    .line 89
    :cond_9
    iget-object v1, p0, Lh40/e1;->i:Lh40/d1;

    .line 90
    .line 91
    iget-object v3, p1, Lh40/e1;->i:Lh40/d1;

    .line 92
    .line 93
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    if-nez v1, :cond_a

    .line 98
    .line 99
    return v2

    .line 100
    :cond_a
    iget-object v1, p0, Lh40/e1;->j:Ljava/lang/String;

    .line 101
    .line 102
    iget-object v3, p1, Lh40/e1;->j:Ljava/lang/String;

    .line 103
    .line 104
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    if-nez v1, :cond_b

    .line 109
    .line 110
    return v2

    .line 111
    :cond_b
    iget-boolean v1, p0, Lh40/e1;->k:Z

    .line 112
    .line 113
    iget-boolean v3, p1, Lh40/e1;->k:Z

    .line 114
    .line 115
    if-eq v1, v3, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    iget-object p0, p0, Lh40/e1;->l:Ljava/lang/String;

    .line 119
    .line 120
    iget-object p1, p1, Lh40/e1;->l:Ljava/lang/String;

    .line 121
    .line 122
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result p0

    .line 126
    if-nez p0, :cond_d

    .line 127
    .line 128
    return v2

    .line 129
    :cond_d
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lh40/e1;->a:Lql0/g;

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
    invoke-virtual {v1}, Lql0/g;->hashCode()I

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
    iget-boolean v3, p0, Lh40/e1;->b:Z

    .line 16
    .line 17
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iget-object v3, p0, Lh40/e1;->c:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget-object v3, p0, Lh40/e1;->d:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    iget-object v3, p0, Lh40/e1;->e:Landroid/net/Uri;

    .line 34
    .line 35
    if-nez v3, :cond_1

    .line 36
    .line 37
    move v3, v0

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    invoke-virtual {v3}, Landroid/net/Uri;->hashCode()I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    :goto_1
    add-int/2addr v1, v3

    .line 44
    mul-int/2addr v1, v2

    .line 45
    iget v3, p0, Lh40/e1;->f:I

    .line 46
    .line 47
    invoke-static {v3, v1, v2}, Lc1/j0;->g(III)I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    iget-boolean v3, p0, Lh40/e1;->g:Z

    .line 52
    .line 53
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    iget-object v3, p0, Lh40/e1;->h:Ljava/time/LocalDate;

    .line 58
    .line 59
    if-nez v3, :cond_2

    .line 60
    .line 61
    move v3, v0

    .line 62
    goto :goto_2

    .line 63
    :cond_2
    invoke-virtual {v3}, Ljava/time/LocalDate;->hashCode()I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    :goto_2
    add-int/2addr v1, v3

    .line 68
    mul-int/2addr v1, v2

    .line 69
    iget-object v3, p0, Lh40/e1;->i:Lh40/d1;

    .line 70
    .line 71
    if-nez v3, :cond_3

    .line 72
    .line 73
    move v3, v0

    .line 74
    goto :goto_3

    .line 75
    :cond_3
    invoke-virtual {v3}, Lh40/d1;->hashCode()I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    :goto_3
    add-int/2addr v1, v3

    .line 80
    mul-int/2addr v1, v2

    .line 81
    iget-object v3, p0, Lh40/e1;->j:Ljava/lang/String;

    .line 82
    .line 83
    if-nez v3, :cond_4

    .line 84
    .line 85
    move v3, v0

    .line 86
    goto :goto_4

    .line 87
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    :goto_4
    add-int/2addr v1, v3

    .line 92
    mul-int/2addr v1, v2

    .line 93
    iget-boolean v3, p0, Lh40/e1;->k:Z

    .line 94
    .line 95
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    iget-object p0, p0, Lh40/e1;->l:Ljava/lang/String;

    .line 100
    .line 101
    if-nez p0, :cond_5

    .line 102
    .line 103
    goto :goto_5

    .line 104
    :cond_5
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    :goto_5
    add-int/2addr v1, v0

    .line 109
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isLoading="

    .line 2
    .line 3
    const-string v1, ", rewardId="

    .line 4
    .line 5
    const-string v2, "State(error="

    .line 6
    .line 7
    iget-object v3, p0, Lh40/e1;->a:Lql0/g;

    .line 8
    .line 9
    iget-boolean v4, p0, Lh40/e1;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lp3/m;->s(Ljava/lang/String;Lql0/g;Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", rewardName="

    .line 16
    .line 17
    const-string v2, ", imageUrl="

    .line 18
    .line 19
    iget-object v3, p0, Lh40/e1;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lh40/e1;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lh40/e1;->e:Landroid/net/Uri;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", points="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget v1, p0, Lh40/e1;->f:I

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", isDatePickerDialogVisible="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-boolean v1, p0, Lh40/e1;->g:Z

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", pickupDate="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lh40/e1;->h:Ljava/time/LocalDate;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", servicePartnerInfo="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    iget-object v1, p0, Lh40/e1;->i:Lh40/d1;

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v1, ", additionalInformation="

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    iget-object v1, p0, Lh40/e1;->j:Ljava/lang/String;

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v1, ", isServicePartnerInfoLoading="

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    iget-boolean v1, p0, Lh40/e1;->k:Z

    .line 87
    .line 88
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const-string v1, ", enrollmentCountryCode="

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    iget-object p0, p0, Lh40/e1;->l:Ljava/lang/String;

    .line 97
    .line 98
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string p0, ")"

    .line 102
    .line 103
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    return-object p0
.end method

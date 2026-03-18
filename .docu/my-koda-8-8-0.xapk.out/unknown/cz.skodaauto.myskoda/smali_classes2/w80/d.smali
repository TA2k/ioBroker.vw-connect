.class public final Lw80/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Lw80/b;

.field public final c:Ljava/util/List;

.field public final d:Z

.field public final e:I

.field public final f:Ljava/util/List;

.field public final g:Z

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Z

.field public final k:Lql0/g;

.field public final l:Z

.field public final m:Z


# direct methods
.method public constructor <init>(Ljava/util/List;Lw80/b;Ljava/util/List;ZILjava/util/List;ZLjava/lang/String;Ljava/lang/String;ZLql0/g;)V
    .locals 1

    .line 1
    const-string v0, "serviceDetails"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "selectedSubServices"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "extensions"

    .line 12
    .line 13
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lw80/d;->a:Ljava/util/List;

    .line 20
    .line 21
    iput-object p2, p0, Lw80/d;->b:Lw80/b;

    .line 22
    .line 23
    iput-object p3, p0, Lw80/d;->c:Ljava/util/List;

    .line 24
    .line 25
    iput-boolean p4, p0, Lw80/d;->d:Z

    .line 26
    .line 27
    iput p5, p0, Lw80/d;->e:I

    .line 28
    .line 29
    iput-object p6, p0, Lw80/d;->f:Ljava/util/List;

    .line 30
    .line 31
    iput-boolean p7, p0, Lw80/d;->g:Z

    .line 32
    .line 33
    iput-object p8, p0, Lw80/d;->h:Ljava/lang/String;

    .line 34
    .line 35
    iput-object p9, p0, Lw80/d;->i:Ljava/lang/String;

    .line 36
    .line 37
    iput-boolean p10, p0, Lw80/d;->j:Z

    .line 38
    .line 39
    iput-object p11, p0, Lw80/d;->k:Lql0/g;

    .line 40
    .line 41
    sget-object p3, Ler0/d;->i:Ler0/d;

    .line 42
    .line 43
    sget-object p4, Ler0/d;->e:Ler0/d;

    .line 44
    .line 45
    sget-object p5, Ler0/d;->f:Ler0/d;

    .line 46
    .line 47
    filled-new-array {p3, p4, p5}, [Ler0/d;

    .line 48
    .line 49
    .line 50
    move-result-object p3

    .line 51
    invoke-static {p3}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 52
    .line 53
    .line 54
    move-result-object p3

    .line 55
    check-cast p3, Ljava/lang/Iterable;

    .line 56
    .line 57
    if-eqz p2, :cond_0

    .line 58
    .line 59
    iget-object p2, p2, Lw80/b;->d:Ler0/d;

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    const/4 p2, 0x0

    .line 63
    :goto_0
    invoke-static {p3, p2}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p2

    .line 67
    const/4 p3, 0x1

    .line 68
    xor-int/2addr p2, p3

    .line 69
    iput-boolean p2, p0, Lw80/d;->l:Z

    .line 70
    .line 71
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    if-le p1, p3, :cond_1

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    const/4 p3, 0x0

    .line 79
    :goto_1
    iput-boolean p3, p0, Lw80/d;->m:Z

    .line 80
    .line 81
    return-void
.end method

.method public static a(Lw80/d;Ljava/util/List;Lw80/b;Ljava/util/List;ZILjava/util/ArrayList;ZLjava/lang/String;Ljava/lang/String;ZLql0/g;I)Lw80/d;
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
    iget-object p1, p0, Lw80/d;->a:Ljava/util/List;

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
    iget-object p2, p0, Lw80/d;->b:Lw80/b;

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
    iget-object p3, p0, Lw80/d;->c:Ljava/util/List;

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
    iget-boolean p1, p0, Lw80/d;->d:Z

    .line 29
    .line 30
    move v4, p1

    .line 31
    goto :goto_0

    .line 32
    :cond_3
    move/from16 v4, p4

    .line 33
    .line 34
    :goto_0
    and-int/lit8 p1, v0, 0x10

    .line 35
    .line 36
    if-eqz p1, :cond_4

    .line 37
    .line 38
    iget p1, p0, Lw80/d;->e:I

    .line 39
    .line 40
    move v5, p1

    .line 41
    goto :goto_1

    .line 42
    :cond_4
    move/from16 v5, p5

    .line 43
    .line 44
    :goto_1
    and-int/lit8 p1, v0, 0x20

    .line 45
    .line 46
    if-eqz p1, :cond_5

    .line 47
    .line 48
    iget-object p1, p0, Lw80/d;->f:Ljava/util/List;

    .line 49
    .line 50
    move-object v6, p1

    .line 51
    goto :goto_2

    .line 52
    :cond_5
    move-object/from16 v6, p6

    .line 53
    .line 54
    :goto_2
    and-int/lit8 p1, v0, 0x40

    .line 55
    .line 56
    if-eqz p1, :cond_6

    .line 57
    .line 58
    iget-boolean p1, p0, Lw80/d;->g:Z

    .line 59
    .line 60
    move v7, p1

    .line 61
    goto :goto_3

    .line 62
    :cond_6
    move/from16 v7, p7

    .line 63
    .line 64
    :goto_3
    and-int/lit16 p1, v0, 0x80

    .line 65
    .line 66
    if-eqz p1, :cond_7

    .line 67
    .line 68
    iget-object p1, p0, Lw80/d;->h:Ljava/lang/String;

    .line 69
    .line 70
    move-object v8, p1

    .line 71
    goto :goto_4

    .line 72
    :cond_7
    move-object/from16 v8, p8

    .line 73
    .line 74
    :goto_4
    and-int/lit16 p1, v0, 0x100

    .line 75
    .line 76
    if-eqz p1, :cond_8

    .line 77
    .line 78
    iget-object p1, p0, Lw80/d;->i:Ljava/lang/String;

    .line 79
    .line 80
    move-object v9, p1

    .line 81
    goto :goto_5

    .line 82
    :cond_8
    move-object/from16 v9, p9

    .line 83
    .line 84
    :goto_5
    and-int/lit16 p1, v0, 0x200

    .line 85
    .line 86
    if-eqz p1, :cond_9

    .line 87
    .line 88
    iget-boolean p1, p0, Lw80/d;->j:Z

    .line 89
    .line 90
    move v10, p1

    .line 91
    goto :goto_6

    .line 92
    :cond_9
    move/from16 v10, p10

    .line 93
    .line 94
    :goto_6
    and-int/lit16 p1, v0, 0x400

    .line 95
    .line 96
    if-eqz p1, :cond_a

    .line 97
    .line 98
    iget-object p1, p0, Lw80/d;->k:Lql0/g;

    .line 99
    .line 100
    move-object v11, p1

    .line 101
    goto :goto_7

    .line 102
    :cond_a
    move-object/from16 v11, p11

    .line 103
    .line 104
    :goto_7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    const-string p0, "serviceDetails"

    .line 108
    .line 109
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string p0, "selectedSubServices"

    .line 113
    .line 114
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string p0, "extensions"

    .line 118
    .line 119
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    new-instance v0, Lw80/d;

    .line 123
    .line 124
    invoke-direct/range {v0 .. v11}, Lw80/d;-><init>(Ljava/util/List;Lw80/b;Ljava/util/List;ZILjava/util/List;ZLjava/lang/String;Ljava/lang/String;ZLql0/g;)V

    .line 125
    .line 126
    .line 127
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
    instance-of v1, p1, Lw80/d;

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
    check-cast p1, Lw80/d;

    .line 12
    .line 13
    iget-object v1, p0, Lw80/d;->a:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lw80/d;->a:Ljava/util/List;

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
    iget-object v1, p0, Lw80/d;->b:Lw80/b;

    .line 25
    .line 26
    iget-object v3, p1, Lw80/d;->b:Lw80/b;

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
    iget-object v1, p0, Lw80/d;->c:Ljava/util/List;

    .line 36
    .line 37
    iget-object v3, p1, Lw80/d;->c:Ljava/util/List;

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
    iget-boolean v1, p0, Lw80/d;->d:Z

    .line 47
    .line 48
    iget-boolean v3, p1, Lw80/d;->d:Z

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget v1, p0, Lw80/d;->e:I

    .line 54
    .line 55
    iget v3, p1, Lw80/d;->e:I

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-object v1, p0, Lw80/d;->f:Ljava/util/List;

    .line 61
    .line 62
    iget-object v3, p1, Lw80/d;->f:Ljava/util/List;

    .line 63
    .line 64
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-boolean v1, p0, Lw80/d;->g:Z

    .line 72
    .line 73
    iget-boolean v3, p1, Lw80/d;->g:Z

    .line 74
    .line 75
    if-eq v1, v3, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    iget-object v1, p0, Lw80/d;->h:Ljava/lang/String;

    .line 79
    .line 80
    iget-object v3, p1, Lw80/d;->h:Ljava/lang/String;

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
    iget-object v1, p0, Lw80/d;->i:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v3, p1, Lw80/d;->i:Ljava/lang/String;

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
    iget-boolean v1, p0, Lw80/d;->j:Z

    .line 101
    .line 102
    iget-boolean v3, p1, Lw80/d;->j:Z

    .line 103
    .line 104
    if-eq v1, v3, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    iget-object p0, p0, Lw80/d;->k:Lql0/g;

    .line 108
    .line 109
    iget-object p1, p1, Lw80/d;->k:Lql0/g;

    .line 110
    .line 111
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-nez p0, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lw80/d;->a:Ljava/util/List;

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
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Lw80/d;->b:Lw80/b;

    .line 12
    .line 13
    if-nez v3, :cond_0

    .line 14
    .line 15
    move v3, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {v3}, Lw80/b;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    :goto_0
    add-int/2addr v0, v3

    .line 22
    mul-int/2addr v0, v1

    .line 23
    iget-object v3, p0, Lw80/d;->c:Ljava/util/List;

    .line 24
    .line 25
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-boolean v3, p0, Lw80/d;->d:Z

    .line 30
    .line 31
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget v3, p0, Lw80/d;->e:I

    .line 36
    .line 37
    invoke-static {v3, v0, v1}, Lc1/j0;->g(III)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    iget-object v3, p0, Lw80/d;->f:Ljava/util/List;

    .line 42
    .line 43
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iget-boolean v3, p0, Lw80/d;->g:Z

    .line 48
    .line 49
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-object v3, p0, Lw80/d;->h:Ljava/lang/String;

    .line 54
    .line 55
    if-nez v3, :cond_1

    .line 56
    .line 57
    move v3, v2

    .line 58
    goto :goto_1

    .line 59
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    :goto_1
    add-int/2addr v0, v3

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object v3, p0, Lw80/d;->i:Ljava/lang/String;

    .line 66
    .line 67
    if-nez v3, :cond_2

    .line 68
    .line 69
    move v3, v2

    .line 70
    goto :goto_2

    .line 71
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    :goto_2
    add-int/2addr v0, v3

    .line 76
    mul-int/2addr v0, v1

    .line 77
    iget-boolean v3, p0, Lw80/d;->j:Z

    .line 78
    .line 79
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    iget-object p0, p0, Lw80/d;->k:Lql0/g;

    .line 84
    .line 85
    if-nez p0, :cond_3

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_3
    invoke-virtual {p0}, Lql0/g;->hashCode()I

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    :goto_3
    add-int/2addr v0, v2

    .line 93
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(serviceDetails="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lw80/d;->a:Ljava/util/List;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", service="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lw80/d;->b:Lw80/b;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", selectedSubServices="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", showDefectDialog="

    .line 29
    .line 30
    const-string v2, ", selectedExtensionIndex="

    .line 31
    .line 32
    iget-object v3, p0, Lw80/d;->c:Ljava/util/List;

    .line 33
    .line 34
    iget-boolean v4, p0, Lw80/d;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget v1, p0, Lw80/d;->e:I

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", extensions="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Lw80/d;->f:Ljava/util/List;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", isExtensionPickerVisible="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", trialText="

    .line 60
    .line 61
    const-string v2, ", tryForFreeText="

    .line 62
    .line 63
    iget-object v3, p0, Lw80/d;->h:Ljava/lang/String;

    .line 64
    .line 65
    iget-boolean v4, p0, Lw80/d;->g:Z

    .line 66
    .line 67
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 68
    .line 69
    .line 70
    const-string v1, ", isLoading="

    .line 71
    .line 72
    const-string v2, ", error="

    .line 73
    .line 74
    iget-object v3, p0, Lw80/d;->i:Ljava/lang/String;

    .line 75
    .line 76
    iget-boolean v4, p0, Lw80/d;->j:Z

    .line 77
    .line 78
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 79
    .line 80
    .line 81
    iget-object p0, p0, Lw80/d;->k:Lql0/g;

    .line 82
    .line 83
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string p0, ")"

    .line 87
    .line 88
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0
.end method

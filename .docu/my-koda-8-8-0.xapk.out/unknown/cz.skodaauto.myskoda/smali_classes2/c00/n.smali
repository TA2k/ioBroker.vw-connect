.class public final Lc00/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Z

.field public final e:Z

.field public final f:Llf0/i;

.field public final g:Z

.field public final h:Z

.field public final i:Lqr0/q;

.field public final j:Lmb0/i;

.field public final k:Ljava/lang/Boolean;

.field public final l:Z


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;Llf0/i;)V
    .locals 16

    and-int/lit8 v0, p1, 0x1

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eqz v0, :cond_0

    move v4, v2

    goto :goto_0

    :cond_0
    move v4, v1

    :goto_0
    and-int/lit8 v0, p1, 0x2

    .line 1
    const-string v3, ""

    if-eqz v0, :cond_1

    move-object v5, v3

    goto :goto_1

    :cond_1
    const-string v0, "20 \u00b0C"

    move-object v5, v0

    :goto_1
    and-int/lit8 v0, p1, 0x4

    if-eqz v0, :cond_2

    move-object v6, v3

    goto :goto_2

    :cond_2
    move-object/from16 v6, p2

    :goto_2
    and-int/lit8 v0, p1, 0x8

    if-eqz v0, :cond_3

    move v7, v2

    goto :goto_3

    :cond_3
    move v7, v1

    :goto_3
    and-int/lit8 v0, p1, 0x10

    if-eqz v0, :cond_4

    move v8, v1

    goto :goto_4

    :cond_4
    move v8, v2

    :goto_4
    and-int/lit8 v0, p1, 0x20

    if-eqz v0, :cond_5

    .line 2
    sget-object v0, Llf0/i;->j:Llf0/i;

    move-object v9, v0

    goto :goto_5

    :cond_5
    move-object/from16 v9, p3

    :goto_5
    const/4 v11, 0x0

    const/4 v15, 0x0

    const/4 v10, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object/from16 v3, p0

    .line 3
    invoke-direct/range {v3 .. v15}, Lc00/n;-><init>(ZLjava/lang/String;Ljava/lang/String;ZZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;Z)V

    return-void
.end method

.method public constructor <init>(ZLjava/lang/String;Ljava/lang/String;ZZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;Z)V
    .locals 1

    const-string v0, "subtitle"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "description"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "viewMode"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-boolean p1, p0, Lc00/n;->a:Z

    .line 6
    iput-object p2, p0, Lc00/n;->b:Ljava/lang/String;

    .line 7
    iput-object p3, p0, Lc00/n;->c:Ljava/lang/String;

    .line 8
    iput-boolean p4, p0, Lc00/n;->d:Z

    .line 9
    iput-boolean p5, p0, Lc00/n;->e:Z

    .line 10
    iput-object p6, p0, Lc00/n;->f:Llf0/i;

    .line 11
    iput-boolean p7, p0, Lc00/n;->g:Z

    .line 12
    iput-boolean p8, p0, Lc00/n;->h:Z

    .line 13
    iput-object p9, p0, Lc00/n;->i:Lqr0/q;

    .line 14
    iput-object p10, p0, Lc00/n;->j:Lmb0/i;

    .line 15
    iput-object p11, p0, Lc00/n;->k:Ljava/lang/Boolean;

    .line 16
    iput-boolean p12, p0, Lc00/n;->l:Z

    return-void
.end method

.method public static a(Lc00/n;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;ZI)Lc00/n;
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
    iget-boolean p1, p0, Lc00/n;->a:Z

    .line 8
    .line 9
    :cond_0
    move v1, p1

    .line 10
    and-int/lit8 p1, v0, 0x2

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p2, p0, Lc00/n;->b:Ljava/lang/String;

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
    iget-object p1, p0, Lc00/n;->c:Ljava/lang/String;

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
    iget-boolean p1, p0, Lc00/n;->d:Z

    .line 32
    .line 33
    move v4, p1

    .line 34
    goto :goto_1

    .line 35
    :cond_3
    move/from16 v4, p4

    .line 36
    .line 37
    :goto_1
    and-int/lit8 p1, v0, 0x10

    .line 38
    .line 39
    if-eqz p1, :cond_4

    .line 40
    .line 41
    iget-boolean p1, p0, Lc00/n;->e:Z

    .line 42
    .line 43
    :goto_2
    move v5, p1

    .line 44
    goto :goto_3

    .line 45
    :cond_4
    const/4 p1, 0x0

    .line 46
    goto :goto_2

    .line 47
    :goto_3
    and-int/lit8 p1, v0, 0x20

    .line 48
    .line 49
    if-eqz p1, :cond_5

    .line 50
    .line 51
    iget-object p1, p0, Lc00/n;->f:Llf0/i;

    .line 52
    .line 53
    move-object v6, p1

    .line 54
    goto :goto_4

    .line 55
    :cond_5
    move-object/from16 v6, p5

    .line 56
    .line 57
    :goto_4
    and-int/lit8 p1, v0, 0x40

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget-boolean p1, p0, Lc00/n;->g:Z

    .line 62
    .line 63
    move v7, p1

    .line 64
    goto :goto_5

    .line 65
    :cond_6
    move/from16 v7, p6

    .line 66
    .line 67
    :goto_5
    and-int/lit16 p1, v0, 0x80

    .line 68
    .line 69
    if-eqz p1, :cond_7

    .line 70
    .line 71
    iget-boolean p1, p0, Lc00/n;->h:Z

    .line 72
    .line 73
    move v8, p1

    .line 74
    goto :goto_6

    .line 75
    :cond_7
    move/from16 v8, p7

    .line 76
    .line 77
    :goto_6
    and-int/lit16 p1, v0, 0x100

    .line 78
    .line 79
    if-eqz p1, :cond_8

    .line 80
    .line 81
    iget-object p1, p0, Lc00/n;->i:Lqr0/q;

    .line 82
    .line 83
    move-object v9, p1

    .line 84
    goto :goto_7

    .line 85
    :cond_8
    move-object/from16 v9, p8

    .line 86
    .line 87
    :goto_7
    and-int/lit16 p1, v0, 0x200

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    iget-object p1, p0, Lc00/n;->j:Lmb0/i;

    .line 92
    .line 93
    move-object v10, p1

    .line 94
    goto :goto_8

    .line 95
    :cond_9
    move-object/from16 v10, p9

    .line 96
    .line 97
    :goto_8
    and-int/lit16 p1, v0, 0x400

    .line 98
    .line 99
    if-eqz p1, :cond_a

    .line 100
    .line 101
    iget-object p1, p0, Lc00/n;->k:Ljava/lang/Boolean;

    .line 102
    .line 103
    move-object v11, p1

    .line 104
    goto :goto_9

    .line 105
    :cond_a
    move-object/from16 v11, p10

    .line 106
    .line 107
    :goto_9
    and-int/lit16 p1, v0, 0x800

    .line 108
    .line 109
    if-eqz p1, :cond_b

    .line 110
    .line 111
    iget-boolean p1, p0, Lc00/n;->l:Z

    .line 112
    .line 113
    move v12, p1

    .line 114
    goto :goto_a

    .line 115
    :cond_b
    move/from16 v12, p11

    .line 116
    .line 117
    :goto_a
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    const-string p0, "subtitle"

    .line 121
    .line 122
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    const-string p0, "description"

    .line 126
    .line 127
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    const-string p0, "viewMode"

    .line 131
    .line 132
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    new-instance v0, Lc00/n;

    .line 136
    .line 137
    invoke-direct/range {v0 .. v12}, Lc00/n;-><init>(ZLjava/lang/String;Ljava/lang/String;ZZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;Z)V

    .line 138
    .line 139
    .line 140
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
    instance-of v1, p1, Lc00/n;

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
    check-cast p1, Lc00/n;

    .line 12
    .line 13
    iget-boolean v1, p0, Lc00/n;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lc00/n;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lc00/n;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lc00/n;->b:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lc00/n;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lc00/n;->c:Ljava/lang/String;

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
    iget-boolean v1, p0, Lc00/n;->d:Z

    .line 43
    .line 44
    iget-boolean v3, p1, Lc00/n;->d:Z

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-boolean v1, p0, Lc00/n;->e:Z

    .line 50
    .line 51
    iget-boolean v3, p1, Lc00/n;->e:Z

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object v1, p0, Lc00/n;->f:Llf0/i;

    .line 57
    .line 58
    iget-object v3, p1, Lc00/n;->f:Llf0/i;

    .line 59
    .line 60
    if-eq v1, v3, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-boolean v1, p0, Lc00/n;->g:Z

    .line 64
    .line 65
    iget-boolean v3, p1, Lc00/n;->g:Z

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-boolean v1, p0, Lc00/n;->h:Z

    .line 71
    .line 72
    iget-boolean v3, p1, Lc00/n;->h:Z

    .line 73
    .line 74
    if-eq v1, v3, :cond_9

    .line 75
    .line 76
    return v2

    .line 77
    :cond_9
    iget-object v1, p0, Lc00/n;->i:Lqr0/q;

    .line 78
    .line 79
    iget-object v3, p1, Lc00/n;->i:Lqr0/q;

    .line 80
    .line 81
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-nez v1, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-object v1, p0, Lc00/n;->j:Lmb0/i;

    .line 89
    .line 90
    iget-object v3, p1, Lc00/n;->j:Lmb0/i;

    .line 91
    .line 92
    if-eq v1, v3, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-object v1, p0, Lc00/n;->k:Ljava/lang/Boolean;

    .line 96
    .line 97
    iget-object v3, p1, Lc00/n;->k:Ljava/lang/Boolean;

    .line 98
    .line 99
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-nez v1, :cond_c

    .line 104
    .line 105
    return v2

    .line 106
    :cond_c
    iget-boolean p0, p0, Lc00/n;->l:Z

    .line 107
    .line 108
    iget-boolean p1, p1, Lc00/n;->l:Z

    .line 109
    .line 110
    if-eq p0, p1, :cond_d

    .line 111
    .line 112
    return v2

    .line 113
    :cond_d
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lc00/n;->a:Z

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
    iget-object v2, p0, Lc00/n;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lc00/n;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lc00/n;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lc00/n;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lc00/n;->f:Llf0/i;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    add-int/2addr v2, v0

    .line 41
    mul-int/2addr v2, v1

    .line 42
    iget-boolean v0, p0, Lc00/n;->g:Z

    .line 43
    .line 44
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-boolean v2, p0, Lc00/n;->h:Z

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    const/4 v2, 0x0

    .line 55
    iget-object v3, p0, Lc00/n;->i:Lqr0/q;

    .line 56
    .line 57
    if-nez v3, :cond_0

    .line 58
    .line 59
    move v3, v2

    .line 60
    goto :goto_0

    .line 61
    :cond_0
    invoke-virtual {v3}, Lqr0/q;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    :goto_0
    add-int/2addr v0, v3

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-object v3, p0, Lc00/n;->j:Lmb0/i;

    .line 68
    .line 69
    if-nez v3, :cond_1

    .line 70
    .line 71
    move v3, v2

    .line 72
    goto :goto_1

    .line 73
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    :goto_1
    add-int/2addr v0, v3

    .line 78
    mul-int/2addr v0, v1

    .line 79
    iget-object v3, p0, Lc00/n;->k:Ljava/lang/Boolean;

    .line 80
    .line 81
    if-nez v3, :cond_2

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    :goto_2
    add-int/2addr v0, v2

    .line 89
    mul-int/2addr v0, v1

    .line 90
    iget-boolean p0, p0, Lc00/n;->l:Z

    .line 91
    .line 92
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    add-int/2addr p0, v0

    .line 97
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", subtitle="

    .line 2
    .line 3
    const-string v1, ", description="

    .line 4
    .line 5
    const-string v2, "State(switchChecked="

    .line 6
    .line 7
    iget-object v3, p0, Lc00/n;->b:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Lc00/n;->a:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v3, v1, v4}, La7/g0;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isSwitchEnabled="

    .line 16
    .line 17
    const-string v2, ", isLoading="

    .line 18
    .line 19
    iget-object v3, p0, Lc00/n;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v4, p0, Lc00/n;->d:Z

    .line 22
    .line 23
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 24
    .line 25
    .line 26
    iget-boolean v1, p0, Lc00/n;->e:Z

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", viewMode="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lc00/n;->f:Llf0/i;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", isNotifySilentLoading="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ", isSilentLoading="

    .line 47
    .line 48
    const-string v2, ", targetTemperature="

    .line 49
    .line 50
    iget-boolean v3, p0, Lc00/n;->g:Z

    .line 51
    .line 52
    iget-boolean v4, p0, Lc00/n;->h:Z

    .line 53
    .line 54
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lc00/n;->i:Lqr0/q;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", heaterSource="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget-object v1, p0, Lc00/n;->j:Lmb0/i;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, ", enableAirConditioningWithoutExternalPower="

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Lc00/n;->k:Ljava/lang/Boolean;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", hasOutsideTemperatureCapability="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-boolean p0, p0, Lc00/n;->l:Z

    .line 88
    .line 89
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string p0, ")"

    .line 93
    .line 94
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0
.end method

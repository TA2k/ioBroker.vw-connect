.class public final Le20/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Le20/e;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/util/List;

.field public final h:Ld20/a;

.field public final i:Ld20/a;

.field public final j:Ld20/a;

.field public final k:Ld20/b;

.field public final l:Ld20/b;

.field public final m:Ld20/b;

.field public final n:Z

.field public final o:Ld20/a;

.field public final p:Ld20/b;


# direct methods
.method public constructor <init>(ZZZLe20/e;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ld20/a;Ld20/a;Ld20/a;Ld20/b;Ld20/b;Ld20/b;)V
    .locals 1

    .line 1
    const-string v0, "selectedPeriod"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "insuranceCompanies"

    .line 7
    .line 8
    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-boolean p1, p0, Le20/f;->a:Z

    .line 15
    .line 16
    iput-boolean p2, p0, Le20/f;->b:Z

    .line 17
    .line 18
    iput-boolean p3, p0, Le20/f;->c:Z

    .line 19
    .line 20
    iput-object p4, p0, Le20/f;->d:Le20/e;

    .line 21
    .line 22
    iput-object p5, p0, Le20/f;->e:Ljava/lang/String;

    .line 23
    .line 24
    iput-object p6, p0, Le20/f;->f:Ljava/lang/String;

    .line 25
    .line 26
    iput-object p7, p0, Le20/f;->g:Ljava/util/List;

    .line 27
    .line 28
    iput-object p8, p0, Le20/f;->h:Ld20/a;

    .line 29
    .line 30
    iput-object p9, p0, Le20/f;->i:Ld20/a;

    .line 31
    .line 32
    iput-object p10, p0, Le20/f;->j:Ld20/a;

    .line 33
    .line 34
    iput-object p11, p0, Le20/f;->k:Ld20/b;

    .line 35
    .line 36
    iput-object p12, p0, Le20/f;->l:Ld20/b;

    .line 37
    .line 38
    iput-object p13, p0, Le20/f;->m:Ld20/b;

    .line 39
    .line 40
    const/4 p3, 0x1

    .line 41
    if-eqz p1, :cond_0

    .line 42
    .line 43
    if-nez p2, :cond_0

    .line 44
    .line 45
    move p1, p3

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 p1, 0x0

    .line 48
    :goto_0
    iput-boolean p1, p0, Le20/f;->n:Z

    .line 49
    .line 50
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    const/4 p2, 0x2

    .line 55
    if-eqz p1, :cond_3

    .line 56
    .line 57
    if-eq p1, p3, :cond_2

    .line 58
    .line 59
    if-ne p1, p2, :cond_1

    .line 60
    .line 61
    move-object p8, p10

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    new-instance p0, La8/r0;

    .line 64
    .line 65
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    move-object p8, p9

    .line 70
    :cond_3
    :goto_1
    iput-object p8, p0, Le20/f;->o:Ld20/a;

    .line 71
    .line 72
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-eqz p1, :cond_6

    .line 77
    .line 78
    if-eq p1, p3, :cond_5

    .line 79
    .line 80
    if-ne p1, p2, :cond_4

    .line 81
    .line 82
    move-object p11, p13

    .line 83
    goto :goto_2

    .line 84
    :cond_4
    new-instance p0, La8/r0;

    .line 85
    .line 86
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_5
    move-object p11, p12

    .line 91
    :cond_6
    :goto_2
    iput-object p11, p0, Le20/f;->p:Ld20/b;

    .line 92
    .line 93
    return-void
.end method

.method public static a(Le20/f;ZZZLe20/e;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ld20/a;Ld20/a;Ld20/a;Ld20/b;Ld20/b;Ld20/b;I)Le20/f;
    .locals 14

    .line 1
    move/from16 v0, p14

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-boolean p1, p0, Le20/f;->a:Z

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
    iget-boolean p1, p0, Le20/f;->b:Z

    .line 15
    .line 16
    move v2, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    move/from16 v2, p2

    .line 19
    .line 20
    :goto_0
    and-int/lit8 p1, v0, 0x4

    .line 21
    .line 22
    if-eqz p1, :cond_2

    .line 23
    .line 24
    iget-boolean p1, p0, Le20/f;->c:Z

    .line 25
    .line 26
    move v3, p1

    .line 27
    goto :goto_1

    .line 28
    :cond_2
    move/from16 v3, p3

    .line 29
    .line 30
    :goto_1
    and-int/lit8 p1, v0, 0x8

    .line 31
    .line 32
    if-eqz p1, :cond_3

    .line 33
    .line 34
    iget-object p1, p0, Le20/f;->d:Le20/e;

    .line 35
    .line 36
    move-object v4, p1

    .line 37
    goto :goto_2

    .line 38
    :cond_3
    move-object/from16 v4, p4

    .line 39
    .line 40
    :goto_2
    and-int/lit8 p1, v0, 0x10

    .line 41
    .line 42
    if-eqz p1, :cond_4

    .line 43
    .line 44
    iget-object p1, p0, Le20/f;->e:Ljava/lang/String;

    .line 45
    .line 46
    move-object v5, p1

    .line 47
    goto :goto_3

    .line 48
    :cond_4
    move-object/from16 v5, p5

    .line 49
    .line 50
    :goto_3
    and-int/lit8 p1, v0, 0x20

    .line 51
    .line 52
    if-eqz p1, :cond_5

    .line 53
    .line 54
    iget-object p1, p0, Le20/f;->f:Ljava/lang/String;

    .line 55
    .line 56
    move-object v6, p1

    .line 57
    goto :goto_4

    .line 58
    :cond_5
    move-object/from16 v6, p6

    .line 59
    .line 60
    :goto_4
    and-int/lit8 p1, v0, 0x40

    .line 61
    .line 62
    if-eqz p1, :cond_6

    .line 63
    .line 64
    iget-object p1, p0, Le20/f;->g:Ljava/util/List;

    .line 65
    .line 66
    move-object v7, p1

    .line 67
    goto :goto_5

    .line 68
    :cond_6
    move-object/from16 v7, p7

    .line 69
    .line 70
    :goto_5
    and-int/lit16 p1, v0, 0x80

    .line 71
    .line 72
    if-eqz p1, :cond_7

    .line 73
    .line 74
    iget-object p1, p0, Le20/f;->h:Ld20/a;

    .line 75
    .line 76
    move-object v8, p1

    .line 77
    goto :goto_6

    .line 78
    :cond_7
    move-object/from16 v8, p8

    .line 79
    .line 80
    :goto_6
    and-int/lit16 p1, v0, 0x100

    .line 81
    .line 82
    if-eqz p1, :cond_8

    .line 83
    .line 84
    iget-object p1, p0, Le20/f;->i:Ld20/a;

    .line 85
    .line 86
    move-object v9, p1

    .line 87
    goto :goto_7

    .line 88
    :cond_8
    move-object/from16 v9, p9

    .line 89
    .line 90
    :goto_7
    and-int/lit16 p1, v0, 0x200

    .line 91
    .line 92
    if-eqz p1, :cond_9

    .line 93
    .line 94
    iget-object p1, p0, Le20/f;->j:Ld20/a;

    .line 95
    .line 96
    move-object v10, p1

    .line 97
    goto :goto_8

    .line 98
    :cond_9
    move-object/from16 v10, p10

    .line 99
    .line 100
    :goto_8
    and-int/lit16 p1, v0, 0x400

    .line 101
    .line 102
    if-eqz p1, :cond_a

    .line 103
    .line 104
    iget-object p1, p0, Le20/f;->k:Ld20/b;

    .line 105
    .line 106
    move-object v11, p1

    .line 107
    goto :goto_9

    .line 108
    :cond_a
    move-object/from16 v11, p11

    .line 109
    .line 110
    :goto_9
    and-int/lit16 p1, v0, 0x800

    .line 111
    .line 112
    if-eqz p1, :cond_b

    .line 113
    .line 114
    iget-object p1, p0, Le20/f;->l:Ld20/b;

    .line 115
    .line 116
    move-object v12, p1

    .line 117
    goto :goto_a

    .line 118
    :cond_b
    move-object/from16 v12, p12

    .line 119
    .line 120
    :goto_a
    and-int/lit16 p1, v0, 0x1000

    .line 121
    .line 122
    if-eqz p1, :cond_c

    .line 123
    .line 124
    iget-object p1, p0, Le20/f;->m:Ld20/b;

    .line 125
    .line 126
    move-object v13, p1

    .line 127
    goto :goto_b

    .line 128
    :cond_c
    move-object/from16 v13, p13

    .line 129
    .line 130
    :goto_b
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    const-string p0, "selectedPeriod"

    .line 134
    .line 135
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    const-string p0, "insuranceCompanies"

    .line 139
    .line 140
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    new-instance v0, Le20/f;

    .line 144
    .line 145
    invoke-direct/range {v0 .. v13}, Le20/f;-><init>(ZZZLe20/e;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ld20/a;Ld20/a;Ld20/a;Ld20/b;Ld20/b;Ld20/b;)V

    .line 146
    .line 147
    .line 148
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
    instance-of v1, p1, Le20/f;

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
    check-cast p1, Le20/f;

    .line 12
    .line 13
    iget-boolean v1, p0, Le20/f;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Le20/f;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Le20/f;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Le20/f;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Le20/f;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Le20/f;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Le20/f;->d:Le20/e;

    .line 35
    .line 36
    iget-object v3, p1, Le20/f;->d:Le20/e;

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Le20/f;->e:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v3, p1, Le20/f;->e:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-object v1, p0, Le20/f;->f:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v3, p1, Le20/f;->f:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-nez v1, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-object v1, p0, Le20/f;->g:Ljava/util/List;

    .line 64
    .line 65
    iget-object v3, p1, Le20/f;->g:Ljava/util/List;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Le20/f;->h:Ld20/a;

    .line 75
    .line 76
    iget-object v3, p1, Le20/f;->h:Ld20/a;

    .line 77
    .line 78
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-nez v1, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-object v1, p0, Le20/f;->i:Ld20/a;

    .line 86
    .line 87
    iget-object v3, p1, Le20/f;->i:Ld20/a;

    .line 88
    .line 89
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-object v1, p0, Le20/f;->j:Ld20/a;

    .line 97
    .line 98
    iget-object v3, p1, Le20/f;->j:Ld20/a;

    .line 99
    .line 100
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-nez v1, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    iget-object v1, p0, Le20/f;->k:Ld20/b;

    .line 108
    .line 109
    iget-object v3, p1, Le20/f;->k:Ld20/b;

    .line 110
    .line 111
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-nez v1, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    iget-object v1, p0, Le20/f;->l:Ld20/b;

    .line 119
    .line 120
    iget-object v3, p1, Le20/f;->l:Ld20/b;

    .line 121
    .line 122
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    if-nez v1, :cond_d

    .line 127
    .line 128
    return v2

    .line 129
    :cond_d
    iget-object p0, p0, Le20/f;->m:Ld20/b;

    .line 130
    .line 131
    iget-object p1, p1, Le20/f;->m:Ld20/b;

    .line 132
    .line 133
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    if-nez p0, :cond_e

    .line 138
    .line 139
    return v2

    .line 140
    :cond_e
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Le20/f;->a:Z

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
    iget-boolean v2, p0, Le20/f;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Le20/f;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Le20/f;->d:Le20/e;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    add-int/2addr v2, v0

    .line 29
    mul-int/2addr v2, v1

    .line 30
    const/4 v0, 0x0

    .line 31
    iget-object v3, p0, Le20/f;->e:Ljava/lang/String;

    .line 32
    .line 33
    if-nez v3, :cond_0

    .line 34
    .line 35
    move v3, v0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    :goto_0
    add-int/2addr v2, v3

    .line 42
    mul-int/2addr v2, v1

    .line 43
    iget-object v3, p0, Le20/f;->f:Ljava/lang/String;

    .line 44
    .line 45
    if-nez v3, :cond_1

    .line 46
    .line 47
    move v3, v0

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    :goto_1
    add-int/2addr v2, v3

    .line 54
    mul-int/2addr v2, v1

    .line 55
    iget-object v3, p0, Le20/f;->g:Ljava/util/List;

    .line 56
    .line 57
    invoke-static {v2, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    iget-object v3, p0, Le20/f;->h:Ld20/a;

    .line 62
    .line 63
    if-nez v3, :cond_2

    .line 64
    .line 65
    move v3, v0

    .line 66
    goto :goto_2

    .line 67
    :cond_2
    invoke-virtual {v3}, Ld20/a;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    :goto_2
    add-int/2addr v2, v3

    .line 72
    mul-int/2addr v2, v1

    .line 73
    iget-object v3, p0, Le20/f;->i:Ld20/a;

    .line 74
    .line 75
    if-nez v3, :cond_3

    .line 76
    .line 77
    move v3, v0

    .line 78
    goto :goto_3

    .line 79
    :cond_3
    invoke-virtual {v3}, Ld20/a;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    :goto_3
    add-int/2addr v2, v3

    .line 84
    mul-int/2addr v2, v1

    .line 85
    iget-object v3, p0, Le20/f;->j:Ld20/a;

    .line 86
    .line 87
    if-nez v3, :cond_4

    .line 88
    .line 89
    move v3, v0

    .line 90
    goto :goto_4

    .line 91
    :cond_4
    invoke-virtual {v3}, Ld20/a;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    :goto_4
    add-int/2addr v2, v3

    .line 96
    mul-int/2addr v2, v1

    .line 97
    iget-object v3, p0, Le20/f;->k:Ld20/b;

    .line 98
    .line 99
    if-nez v3, :cond_5

    .line 100
    .line 101
    move v3, v0

    .line 102
    goto :goto_5

    .line 103
    :cond_5
    invoke-virtual {v3}, Ld20/b;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    :goto_5
    add-int/2addr v2, v3

    .line 108
    mul-int/2addr v2, v1

    .line 109
    iget-object v3, p0, Le20/f;->l:Ld20/b;

    .line 110
    .line 111
    if-nez v3, :cond_6

    .line 112
    .line 113
    move v3, v0

    .line 114
    goto :goto_6

    .line 115
    :cond_6
    invoke-virtual {v3}, Ld20/b;->hashCode()I

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    :goto_6
    add-int/2addr v2, v3

    .line 120
    mul-int/2addr v2, v1

    .line 121
    iget-object p0, p0, Le20/f;->m:Ld20/b;

    .line 122
    .line 123
    if-nez p0, :cond_7

    .line 124
    .line 125
    goto :goto_7

    .line 126
    :cond_7
    invoke-virtual {p0}, Ld20/b;->hashCode()I

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    :goto_7
    add-int/2addr v2, v0

    .line 131
    return v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isRefreshing="

    .line 2
    .line 3
    const-string v1, ", showInsurancePicker="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Le20/f;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Le20/f;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-boolean v1, p0, Le20/f;->c:Z

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", selectedPeriod="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Le20/f;->d:Le20/e;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", lastUpdateText="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", lastUpdateInsurerText="

    .line 36
    .line 37
    const-string v2, ", insuranceCompanies="

    .line 38
    .line 39
    iget-object v3, p0, Le20/f;->e:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v4, p0, Le20/f;->f:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Le20/f;->g:Ljava/util/List;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", weeklyScore="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Le20/f;->h:Ld20/a;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", monthlyScore="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    iget-object v1, p0, Le20/f;->i:Ld20/a;

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v1, ", quarterlyScore="

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    iget-object v1, p0, Le20/f;->j:Ld20/a;

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v1, ", weeklyDiff="

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    iget-object v1, p0, Le20/f;->k:Ld20/b;

    .line 87
    .line 88
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const-string v1, ", monthlyDiff="

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Le20/f;->l:Ld20/b;

    .line 97
    .line 98
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v1, ", quarterlyDiff="

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    iget-object p0, p0, Le20/f;->m:Ld20/b;

    .line 107
    .line 108
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    const-string p0, ")"

    .line 112
    .line 113
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    return-object p0
.end method

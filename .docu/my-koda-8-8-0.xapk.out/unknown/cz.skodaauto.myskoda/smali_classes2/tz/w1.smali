.class public final Ltz/w1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Lrd0/p;

.field public final c:Ljava/util/List;

.field public final d:Ljava/util/List;

.field public final e:Ltz/u1;

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Lql0/g;

.field public final k:Z

.field public final l:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Lrd0/p;Ljava/util/List;Ljava/util/List;Ltz/u1;ZZZZLql0/g;ZZ)V
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "timers"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "chargingSettings"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltz/w1;->a:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Ltz/w1;->b:Lrd0/p;

    .line 4
    iput-object p3, p0, Ltz/w1;->c:Ljava/util/List;

    .line 5
    iput-object p4, p0, Ltz/w1;->d:Ljava/util/List;

    .line 6
    iput-object p5, p0, Ltz/w1;->e:Ltz/u1;

    .line 7
    iput-boolean p6, p0, Ltz/w1;->f:Z

    .line 8
    iput-boolean p7, p0, Ltz/w1;->g:Z

    .line 9
    iput-boolean p8, p0, Ltz/w1;->h:Z

    .line 10
    iput-boolean p9, p0, Ltz/w1;->i:Z

    .line 11
    iput-object p10, p0, Ltz/w1;->j:Lql0/g;

    .line 12
    iput-boolean p11, p0, Ltz/w1;->k:Z

    .line 13
    iput-boolean p12, p0, Ltz/w1;->l:Z

    return-void
.end method

.method public synthetic constructor <init>(Lrd0/p;Ljava/util/List;Ljava/util/List;Ltz/u1;I)V
    .locals 14

    and-int/lit8 v0, p5, 0x1

    if-eqz v0, :cond_0

    .line 14
    const-string v0, ""

    :goto_0
    move-object v2, v0

    goto :goto_1

    .line 15
    :cond_0
    const-string v0, "Home"

    goto :goto_0

    :goto_1
    and-int/lit8 v0, p5, 0x2

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    move-object v3, v1

    goto :goto_2

    :cond_1
    move-object v3, p1

    :goto_2
    and-int/lit8 p1, p5, 0x4

    if-eqz p1, :cond_2

    .line 16
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    move-object v4, p1

    goto :goto_3

    :cond_2
    move-object/from16 v4, p2

    :goto_3
    and-int/lit8 p1, p5, 0x8

    if-eqz p1, :cond_3

    move-object v5, v1

    goto :goto_4

    :cond_3
    move-object/from16 v5, p3

    :goto_4
    and-int/lit8 p1, p5, 0x10

    if-eqz p1, :cond_4

    .line 17
    new-instance p1, Ltz/u1;

    invoke-direct {p1, v1, v1, v1, v1}, Ltz/u1;-><init>(Lqr0/l;Lqr0/l;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    move-object v6, p1

    goto :goto_5

    :cond_4
    move-object/from16 v6, p4

    :goto_5
    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    move-object v1, p0

    .line 18
    invoke-direct/range {v1 .. v13}, Ltz/w1;-><init>(Ljava/lang/String;Lrd0/p;Ljava/util/List;Ljava/util/List;Ltz/u1;ZZZZLql0/g;ZZ)V

    return-void
.end method

.method public static a(Ltz/w1;Ljava/lang/String;Lrd0/p;Ljava/util/ArrayList;Ljava/util/ArrayList;Ltz/u1;ZZZZLql0/g;ZZI)Ltz/w1;
    .locals 13

    .line 1
    move/from16 v0, p13

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Ltz/w1;->a:Ljava/lang/String;

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
    iget-object p2, p0, Ltz/w1;->b:Lrd0/p;

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
    iget-object p1, p0, Ltz/w1;->c:Ljava/util/List;

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
    iget-object p1, p0, Ltz/w1;->d:Ljava/util/List;

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
    iget-object p1, p0, Ltz/w1;->e:Ltz/u1;

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
    iget-boolean p1, p0, Ltz/w1;->f:Z

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
    iget-boolean p1, p0, Ltz/w1;->g:Z

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
    iget-boolean p1, p0, Ltz/w1;->h:Z

    .line 72
    .line 73
    move v8, p1

    .line 74
    goto :goto_5

    .line 75
    :cond_7
    move/from16 v8, p8

    .line 76
    .line 77
    :goto_5
    and-int/lit16 p1, v0, 0x100

    .line 78
    .line 79
    if-eqz p1, :cond_8

    .line 80
    .line 81
    iget-boolean p1, p0, Ltz/w1;->i:Z

    .line 82
    .line 83
    move v9, p1

    .line 84
    goto :goto_6

    .line 85
    :cond_8
    move/from16 v9, p9

    .line 86
    .line 87
    :goto_6
    and-int/lit16 p1, v0, 0x200

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    iget-object p1, p0, Ltz/w1;->j:Lql0/g;

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
    iget-boolean p1, p0, Ltz/w1;->k:Z

    .line 102
    .line 103
    move v11, p1

    .line 104
    goto :goto_8

    .line 105
    :cond_a
    move/from16 v11, p11

    .line 106
    .line 107
    :goto_8
    and-int/lit16 p1, v0, 0x800

    .line 108
    .line 109
    if-eqz p1, :cond_b

    .line 110
    .line 111
    iget-boolean p1, p0, Ltz/w1;->l:Z

    .line 112
    .line 113
    move v12, p1

    .line 114
    goto :goto_9

    .line 115
    :cond_b
    move/from16 v12, p12

    .line 116
    .line 117
    :goto_9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    const-string p0, "name"

    .line 121
    .line 122
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    const-string p0, "timers"

    .line 126
    .line 127
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    const-string p0, "chargingSettings"

    .line 131
    .line 132
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    new-instance v0, Ltz/w1;

    .line 136
    .line 137
    invoke-direct/range {v0 .. v12}, Ltz/w1;-><init>(Ljava/lang/String;Lrd0/p;Ljava/util/List;Ljava/util/List;Ltz/u1;ZZZZLql0/g;ZZ)V

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
    instance-of v1, p1, Ltz/w1;

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
    check-cast p1, Ltz/w1;

    .line 12
    .line 13
    iget-object v1, p0, Ltz/w1;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ltz/w1;->a:Ljava/lang/String;

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
    iget-object v1, p0, Ltz/w1;->b:Lrd0/p;

    .line 25
    .line 26
    iget-object v3, p1, Ltz/w1;->b:Lrd0/p;

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
    iget-object v1, p0, Ltz/w1;->c:Ljava/util/List;

    .line 36
    .line 37
    iget-object v3, p1, Ltz/w1;->c:Ljava/util/List;

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
    iget-object v1, p0, Ltz/w1;->d:Ljava/util/List;

    .line 47
    .line 48
    iget-object v3, p1, Ltz/w1;->d:Ljava/util/List;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Ltz/w1;->e:Ltz/u1;

    .line 58
    .line 59
    iget-object v3, p1, Ltz/w1;->e:Ltz/u1;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-boolean v1, p0, Ltz/w1;->f:Z

    .line 69
    .line 70
    iget-boolean v3, p1, Ltz/w1;->f:Z

    .line 71
    .line 72
    if-eq v1, v3, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-boolean v1, p0, Ltz/w1;->g:Z

    .line 76
    .line 77
    iget-boolean v3, p1, Ltz/w1;->g:Z

    .line 78
    .line 79
    if-eq v1, v3, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-boolean v1, p0, Ltz/w1;->h:Z

    .line 83
    .line 84
    iget-boolean v3, p1, Ltz/w1;->h:Z

    .line 85
    .line 86
    if-eq v1, v3, :cond_9

    .line 87
    .line 88
    return v2

    .line 89
    :cond_9
    iget-boolean v1, p0, Ltz/w1;->i:Z

    .line 90
    .line 91
    iget-boolean v3, p1, Ltz/w1;->i:Z

    .line 92
    .line 93
    if-eq v1, v3, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-object v1, p0, Ltz/w1;->j:Lql0/g;

    .line 97
    .line 98
    iget-object v3, p1, Ltz/w1;->j:Lql0/g;

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
    iget-boolean v1, p0, Ltz/w1;->k:Z

    .line 108
    .line 109
    iget-boolean v3, p1, Ltz/w1;->k:Z

    .line 110
    .line 111
    if-eq v1, v3, :cond_c

    .line 112
    .line 113
    return v2

    .line 114
    :cond_c
    iget-boolean p0, p0, Ltz/w1;->l:Z

    .line 115
    .line 116
    iget-boolean p1, p1, Ltz/w1;->l:Z

    .line 117
    .line 118
    if-eq p0, p1, :cond_d

    .line 119
    .line 120
    return v2

    .line 121
    :cond_d
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ltz/w1;->a:Ljava/lang/String;

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
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Ltz/w1;->b:Lrd0/p;

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
    invoke-virtual {v3}, Lrd0/p;->hashCode()I

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
    iget-object v3, p0, Ltz/w1;->c:Ljava/util/List;

    .line 24
    .line 25
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-object v3, p0, Ltz/w1;->d:Ljava/util/List;

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    move v3, v2

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_1
    add-int/2addr v0, v3

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v3, p0, Ltz/w1;->e:Ltz/u1;

    .line 42
    .line 43
    invoke-virtual {v3}, Ltz/u1;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    add-int/2addr v3, v0

    .line 48
    mul-int/2addr v3, v1

    .line 49
    iget-boolean v0, p0, Ltz/w1;->f:Z

    .line 50
    .line 51
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    iget-boolean v3, p0, Ltz/w1;->g:Z

    .line 56
    .line 57
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    iget-boolean v3, p0, Ltz/w1;->h:Z

    .line 62
    .line 63
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    iget-boolean v3, p0, Ltz/w1;->i:Z

    .line 68
    .line 69
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    iget-object v3, p0, Ltz/w1;->j:Lql0/g;

    .line 74
    .line 75
    if-nez v3, :cond_2

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_2
    invoke-virtual {v3}, Lql0/g;->hashCode()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    :goto_2
    add-int/2addr v0, v2

    .line 83
    mul-int/2addr v0, v1

    .line 84
    iget-boolean v2, p0, Ltz/w1;->k:Z

    .line 85
    .line 86
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    iget-boolean p0, p0, Ltz/w1;->l:Z

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
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(name="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ltz/w1;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", location="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ltz/w1;->b:Lrd0/p;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", timers="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", preferredChargingTimes="

    .line 29
    .line 30
    const-string v2, ", chargingSettings="

    .line 31
    .line 32
    iget-object v3, p0, Ltz/w1;->c:Ljava/util/List;

    .line 33
    .line 34
    iget-object v4, p0, Ltz/w1;->d:Ljava/util/List;

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Ltz/w1;->e:Ltz/u1;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", isSaveEnabled="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-boolean v1, p0, Ltz/w1;->f:Z

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", isDiscardDialogVisible="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", isOnboardingVisible="

    .line 60
    .line 61
    const-string v2, ", isDeleteDialogVisible="

    .line 62
    .line 63
    iget-boolean v3, p0, Ltz/w1;->g:Z

    .line 64
    .line 65
    iget-boolean v4, p0, Ltz/w1;->h:Z

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iget-boolean v1, p0, Ltz/w1;->i:Z

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", error="

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    iget-object v1, p0, Ltz/w1;->j:Lql0/g;

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, ", isMaximumChargeLimitVisible="

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v1, ", isMinimumChargeLimitVisible="

    .line 91
    .line 92
    const-string v2, ")"

    .line 93
    .line 94
    iget-boolean v3, p0, Ltz/w1;->k:Z

    .line 95
    .line 96
    iget-boolean p0, p0, Ltz/w1;->l:Z

    .line 97
    .line 98
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0
.end method

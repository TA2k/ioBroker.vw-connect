.class public final Lwk0/x1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Lwk0/f1;

.field public final f:Ljava/lang/Boolean;

.field public final g:Ljava/util/Map;

.field public final h:Ljava/util/List;

.field public final i:Ljava/lang/String;

.field public final j:Z

.field public final k:Lwk0/t;

.field public final l:Lwk0/j0;

.field public final m:Ljava/lang/Object;

.field public final n:Z

.field public final o:Z

.field public final p:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lwk0/f1;Ljava/lang/Boolean;Ljava/util/Map;Ljava/util/List;Ljava/lang/String;ZLwk0/t;Lwk0/j0;Ljava/lang/Object;ZZI)V
    .locals 20

    move/from16 v0, p16

    and-int/lit8 v1, v0, 0x1

    .line 1
    const-string v2, ""

    if-eqz v1, :cond_0

    move-object v4, v2

    goto :goto_0

    :cond_0
    move-object/from16 v4, p1

    :goto_0
    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_1

    move-object v5, v2

    goto :goto_1

    :cond_1
    move-object/from16 v5, p2

    :goto_1
    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_2

    move-object v6, v2

    goto :goto_2

    :cond_2
    move-object/from16 v6, p3

    :goto_2
    and-int/lit8 v1, v0, 0x8

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    move-object v7, v2

    goto :goto_3

    :cond_3
    move-object/from16 v7, p4

    :goto_3
    and-int/lit8 v1, v0, 0x10

    if-eqz v1, :cond_4

    move-object v8, v2

    goto :goto_4

    :cond_4
    move-object/from16 v8, p5

    :goto_4
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_5

    move-object v9, v2

    goto :goto_5

    :cond_5
    move-object/from16 v9, p6

    :goto_5
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_6

    move-object v10, v2

    goto :goto_6

    :cond_6
    move-object/from16 v10, p7

    :goto_6
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_7

    .line 2
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    move-object v11, v1

    goto :goto_7

    :cond_7
    move-object/from16 v11, p8

    :goto_7
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_8

    move-object v12, v2

    goto :goto_8

    :cond_8
    move-object/from16 v12, p9

    :goto_8
    and-int/lit16 v1, v0, 0x200

    const/4 v3, 0x0

    if-eqz v1, :cond_9

    move v13, v3

    goto :goto_9

    :cond_9
    move/from16 v13, p10

    :goto_9
    and-int/lit16 v1, v0, 0x400

    if-eqz v1, :cond_a

    move-object v14, v2

    goto :goto_a

    :cond_a
    move-object/from16 v14, p11

    :goto_a
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_b

    move-object v15, v2

    goto :goto_b

    :cond_b
    move-object/from16 v15, p12

    :goto_b
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_c

    move-object/from16 v16, v2

    goto :goto_c

    :cond_c
    move-object/from16 v16, p13

    :goto_c
    and-int/lit16 v1, v0, 0x2000

    if-eqz v1, :cond_d

    move/from16 v17, v3

    goto :goto_d

    :cond_d
    move/from16 v17, p14

    :goto_d
    and-int/lit16 v0, v0, 0x4000

    if-eqz v0, :cond_e

    move/from16 v18, v3

    goto :goto_e

    :cond_e
    move/from16 v18, p15

    :goto_e
    const/16 v19, 0x0

    move-object/from16 v3, p0

    .line 3
    invoke-direct/range {v3 .. v19}, Lwk0/x1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lwk0/f1;Ljava/lang/Boolean;Ljava/util/Map;Ljava/util/List;Ljava/lang/String;ZLwk0/t;Lwk0/j0;Ljava/lang/Object;ZZZ)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lwk0/f1;Ljava/lang/Boolean;Ljava/util/Map;Ljava/util/List;Ljava/lang/String;ZLwk0/t;Lwk0/j0;Ljava/lang/Object;ZZZ)V
    .locals 1

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "title"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "address"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "images"

    invoke-static {p8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lwk0/x1;->a:Ljava/lang/String;

    .line 6
    iput-object p2, p0, Lwk0/x1;->b:Ljava/lang/String;

    .line 7
    iput-object p3, p0, Lwk0/x1;->c:Ljava/lang/String;

    .line 8
    iput-object p4, p0, Lwk0/x1;->d:Ljava/lang/String;

    .line 9
    iput-object p5, p0, Lwk0/x1;->e:Lwk0/f1;

    .line 10
    iput-object p6, p0, Lwk0/x1;->f:Ljava/lang/Boolean;

    .line 11
    iput-object p7, p0, Lwk0/x1;->g:Ljava/util/Map;

    .line 12
    iput-object p8, p0, Lwk0/x1;->h:Ljava/util/List;

    .line 13
    iput-object p9, p0, Lwk0/x1;->i:Ljava/lang/String;

    .line 14
    iput-boolean p10, p0, Lwk0/x1;->j:Z

    .line 15
    iput-object p11, p0, Lwk0/x1;->k:Lwk0/t;

    .line 16
    iput-object p12, p0, Lwk0/x1;->l:Lwk0/j0;

    .line 17
    iput-object p13, p0, Lwk0/x1;->m:Ljava/lang/Object;

    .line 18
    iput-boolean p14, p0, Lwk0/x1;->n:Z

    move/from16 p1, p15

    .line 19
    iput-boolean p1, p0, Lwk0/x1;->o:Z

    move/from16 p1, p16

    .line 20
    iput-boolean p1, p0, Lwk0/x1;->p:Z

    return-void
.end method

.method public static a(Lwk0/x1;Lnx0/f;Ljava/lang/Object;I)Lwk0/x1;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p3

    .line 4
    .line 5
    iget-object v2, v0, Lwk0/x1;->a:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, v0, Lwk0/x1;->b:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, v0, Lwk0/x1;->c:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, v0, Lwk0/x1;->d:Ljava/lang/String;

    .line 12
    .line 13
    move-object v6, v5

    .line 14
    iget-object v5, v0, Lwk0/x1;->e:Lwk0/f1;

    .line 15
    .line 16
    move-object v7, v6

    .line 17
    iget-object v6, v0, Lwk0/x1;->f:Ljava/lang/Boolean;

    .line 18
    .line 19
    and-int/lit8 v8, v1, 0x40

    .line 20
    .line 21
    if-eqz v8, :cond_0

    .line 22
    .line 23
    iget-object v8, v0, Lwk0/x1;->g:Ljava/util/Map;

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move-object/from16 v8, p1

    .line 27
    .line 28
    :goto_0
    iget-object v9, v0, Lwk0/x1;->h:Ljava/util/List;

    .line 29
    .line 30
    iget-object v10, v0, Lwk0/x1;->i:Ljava/lang/String;

    .line 31
    .line 32
    move-object v11, v10

    .line 33
    iget-boolean v10, v0, Lwk0/x1;->j:Z

    .line 34
    .line 35
    move-object v12, v11

    .line 36
    iget-object v11, v0, Lwk0/x1;->k:Lwk0/t;

    .line 37
    .line 38
    move-object v13, v12

    .line 39
    iget-object v12, v0, Lwk0/x1;->l:Lwk0/j0;

    .line 40
    .line 41
    and-int/lit16 v14, v1, 0x1000

    .line 42
    .line 43
    if-eqz v14, :cond_1

    .line 44
    .line 45
    iget-object v14, v0, Lwk0/x1;->m:Ljava/lang/Object;

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    move-object/from16 v14, p2

    .line 49
    .line 50
    :goto_1
    and-int/lit16 v15, v1, 0x2000

    .line 51
    .line 52
    const/16 v16, 0x1

    .line 53
    .line 54
    if-eqz v15, :cond_2

    .line 55
    .line 56
    iget-boolean v15, v0, Lwk0/x1;->n:Z

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_2
    move/from16 v15, v16

    .line 60
    .line 61
    :goto_2
    iget-boolean v1, v0, Lwk0/x1;->o:Z

    .line 62
    .line 63
    const v17, 0x8000

    .line 64
    .line 65
    .line 66
    and-int v17, p3, v17

    .line 67
    .line 68
    if-eqz v17, :cond_3

    .line 69
    .line 70
    move/from16 v17, v1

    .line 71
    .line 72
    iget-boolean v1, v0, Lwk0/x1;->p:Z

    .line 73
    .line 74
    move/from16 v16, v1

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_3
    move/from16 v17, v1

    .line 78
    .line 79
    :goto_3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    const-string v0, "id"

    .line 83
    .line 84
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const-string v0, "title"

    .line 88
    .line 89
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v0, "address"

    .line 93
    .line 94
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    const-string v0, "images"

    .line 98
    .line 99
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    new-instance v0, Lwk0/x1;

    .line 103
    .line 104
    move-object v1, v2

    .line 105
    move-object v2, v3

    .line 106
    move-object v3, v4

    .line 107
    move-object v4, v7

    .line 108
    move-object v7, v8

    .line 109
    move-object v8, v9

    .line 110
    move-object v9, v13

    .line 111
    move-object v13, v14

    .line 112
    move v14, v15

    .line 113
    move/from16 v15, v17

    .line 114
    .line 115
    invoke-direct/range {v0 .. v16}, Lwk0/x1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lwk0/f1;Ljava/lang/Boolean;Ljava/util/Map;Ljava/util/List;Ljava/lang/String;ZLwk0/t;Lwk0/j0;Ljava/lang/Object;ZZZ)V

    .line 116
    .line 117
    .line 118
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
    instance-of v1, p1, Lwk0/x1;

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
    check-cast p1, Lwk0/x1;

    .line 12
    .line 13
    iget-object v1, p0, Lwk0/x1;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lwk0/x1;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lwk0/x1;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lwk0/x1;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lwk0/x1;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lwk0/x1;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lwk0/x1;->d:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lwk0/x1;->d:Ljava/lang/String;

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
    iget-object v1, p0, Lwk0/x1;->e:Lwk0/f1;

    .line 58
    .line 59
    iget-object v3, p1, Lwk0/x1;->e:Lwk0/f1;

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
    iget-object v1, p0, Lwk0/x1;->f:Ljava/lang/Boolean;

    .line 69
    .line 70
    iget-object v3, p1, Lwk0/x1;->f:Ljava/lang/Boolean;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lwk0/x1;->g:Ljava/util/Map;

    .line 80
    .line 81
    iget-object v3, p1, Lwk0/x1;->g:Ljava/util/Map;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget-object v1, p0, Lwk0/x1;->h:Ljava/util/List;

    .line 91
    .line 92
    iget-object v3, p1, Lwk0/x1;->h:Ljava/util/List;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Lwk0/x1;->i:Ljava/lang/String;

    .line 102
    .line 103
    iget-object v3, p1, Lwk0/x1;->i:Ljava/lang/String;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-boolean v1, p0, Lwk0/x1;->j:Z

    .line 113
    .line 114
    iget-boolean v3, p1, Lwk0/x1;->j:Z

    .line 115
    .line 116
    if-eq v1, v3, :cond_b

    .line 117
    .line 118
    return v2

    .line 119
    :cond_b
    iget-object v1, p0, Lwk0/x1;->k:Lwk0/t;

    .line 120
    .line 121
    iget-object v3, p1, Lwk0/x1;->k:Lwk0/t;

    .line 122
    .line 123
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    if-nez v1, :cond_c

    .line 128
    .line 129
    return v2

    .line 130
    :cond_c
    iget-object v1, p0, Lwk0/x1;->l:Lwk0/j0;

    .line 131
    .line 132
    iget-object v3, p1, Lwk0/x1;->l:Lwk0/j0;

    .line 133
    .line 134
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    if-nez v1, :cond_d

    .line 139
    .line 140
    return v2

    .line 141
    :cond_d
    iget-object v1, p0, Lwk0/x1;->m:Ljava/lang/Object;

    .line 142
    .line 143
    iget-object v3, p1, Lwk0/x1;->m:Ljava/lang/Object;

    .line 144
    .line 145
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    if-nez v1, :cond_e

    .line 150
    .line 151
    return v2

    .line 152
    :cond_e
    iget-boolean v1, p0, Lwk0/x1;->n:Z

    .line 153
    .line 154
    iget-boolean v3, p1, Lwk0/x1;->n:Z

    .line 155
    .line 156
    if-eq v1, v3, :cond_f

    .line 157
    .line 158
    return v2

    .line 159
    :cond_f
    iget-boolean v1, p0, Lwk0/x1;->o:Z

    .line 160
    .line 161
    iget-boolean v3, p1, Lwk0/x1;->o:Z

    .line 162
    .line 163
    if-eq v1, v3, :cond_10

    .line 164
    .line 165
    return v2

    .line 166
    :cond_10
    iget-boolean p0, p0, Lwk0/x1;->p:Z

    .line 167
    .line 168
    iget-boolean p1, p1, Lwk0/x1;->p:Z

    .line 169
    .line 170
    if-eq p0, p1, :cond_11

    .line 171
    .line 172
    return v2

    .line 173
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lwk0/x1;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lwk0/x1;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lwk0/x1;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v2, 0x0

    .line 23
    iget-object v3, p0, Lwk0/x1;->d:Ljava/lang/String;

    .line 24
    .line 25
    if-nez v3, :cond_0

    .line 26
    .line 27
    move v3, v2

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    :goto_0
    add-int/2addr v0, v3

    .line 34
    mul-int/2addr v0, v1

    .line 35
    iget-object v3, p0, Lwk0/x1;->e:Lwk0/f1;

    .line 36
    .line 37
    if-nez v3, :cond_1

    .line 38
    .line 39
    move v3, v2

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {v3}, Lwk0/f1;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    :goto_1
    add-int/2addr v0, v3

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-object v3, p0, Lwk0/x1;->f:Ljava/lang/Boolean;

    .line 48
    .line 49
    if-nez v3, :cond_2

    .line 50
    .line 51
    move v3, v2

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    :goto_2
    add-int/2addr v0, v3

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget-object v3, p0, Lwk0/x1;->g:Ljava/util/Map;

    .line 60
    .line 61
    if-nez v3, :cond_3

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_3

    .line 65
    :cond_3
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    :goto_3
    add-int/2addr v0, v3

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-object v3, p0, Lwk0/x1;->h:Ljava/util/List;

    .line 72
    .line 73
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget-object v3, p0, Lwk0/x1;->i:Ljava/lang/String;

    .line 78
    .line 79
    if-nez v3, :cond_4

    .line 80
    .line 81
    move v3, v2

    .line 82
    goto :goto_4

    .line 83
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    :goto_4
    add-int/2addr v0, v3

    .line 88
    mul-int/2addr v0, v1

    .line 89
    iget-boolean v3, p0, Lwk0/x1;->j:Z

    .line 90
    .line 91
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    iget-object v3, p0, Lwk0/x1;->k:Lwk0/t;

    .line 96
    .line 97
    if-nez v3, :cond_5

    .line 98
    .line 99
    move v3, v2

    .line 100
    goto :goto_5

    .line 101
    :cond_5
    invoke-virtual {v3}, Lwk0/t;->hashCode()I

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    :goto_5
    add-int/2addr v0, v3

    .line 106
    mul-int/2addr v0, v1

    .line 107
    iget-object v3, p0, Lwk0/x1;->l:Lwk0/j0;

    .line 108
    .line 109
    if-nez v3, :cond_6

    .line 110
    .line 111
    move v3, v2

    .line 112
    goto :goto_6

    .line 113
    :cond_6
    invoke-virtual {v3}, Lwk0/j0;->hashCode()I

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    :goto_6
    add-int/2addr v0, v3

    .line 118
    mul-int/2addr v0, v1

    .line 119
    iget-object v3, p0, Lwk0/x1;->m:Ljava/lang/Object;

    .line 120
    .line 121
    if-nez v3, :cond_7

    .line 122
    .line 123
    goto :goto_7

    .line 124
    :cond_7
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    :goto_7
    add-int/2addr v0, v2

    .line 129
    mul-int/2addr v0, v1

    .line 130
    iget-boolean v2, p0, Lwk0/x1;->n:Z

    .line 131
    .line 132
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    iget-boolean v2, p0, Lwk0/x1;->o:Z

    .line 137
    .line 138
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    iget-boolean p0, p0, Lwk0/x1;->p:Z

    .line 143
    .line 144
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 145
    .line 146
    .line 147
    move-result p0

    .line 148
    add-int/2addr p0, v0

    .line 149
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", title="

    .line 2
    .line 3
    const-string v1, ", address="

    .line 4
    .line 5
    const-string v2, "State(id="

    .line 6
    .line 7
    iget-object v3, p0, Lwk0/x1;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lwk0/x1;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", distance="

    .line 16
    .line 17
    const-string v2, ", placeReview="

    .line 18
    .line 19
    iget-object v3, p0, Lwk0/x1;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lwk0/x1;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lwk0/x1;->e:Lwk0/f1;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", isOpen="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lwk0/x1;->f:Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", openingHours="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lwk0/x1;->g:Ljava/util/Map;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", images="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lwk0/x1;->h:Ljava/util/List;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", description="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", isImageGalleryVisible="

    .line 67
    .line 68
    const-string v2, ", contact="

    .line 69
    .line 70
    iget-object v3, p0, Lwk0/x1;->i:Ljava/lang/String;

    .line 71
    .line 72
    iget-boolean v4, p0, Lwk0/x1;->j:Z

    .line 73
    .line 74
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Lwk0/x1;->k:Lwk0/t;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", offerSection="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-object v1, p0, Lwk0/x1;->l:Lwk0/j0;

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, ", specificPoiState="

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    iget-object v1, p0, Lwk0/x1;->m:Ljava/lang/Object;

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v1, ", isLoading="

    .line 103
    .line 104
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    iget-boolean v1, p0, Lwk0/x1;->n:Z

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v1, ", hasFailed="

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v1, ", isRefreshing="

    .line 118
    .line 119
    const-string v2, ")"

    .line 120
    .line 121
    iget-boolean v3, p0, Lwk0/x1;->o:Z

    .line 122
    .line 123
    iget-boolean p0, p0, Lwk0/x1;->p:Z

    .line 124
    .line 125
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0
.end method

.class public final Lnz/e;
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

.field public final h:Z

.field public final i:Z

.field public final j:Lnz/d;

.field public final k:Llf0/i;

.field public final l:Z

.field public final m:Z

.field public final n:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;IZZ)V
    .locals 18

    move/from16 v0, p2

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
    const-string v1, "30 min"

    move-object v5, v1

    :goto_1
    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_2

    :goto_2
    move-object v6, v2

    goto :goto_3

    :cond_2
    const-string v2, "Off"

    goto :goto_2

    :goto_3
    and-int/lit8 v1, v0, 0x8

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    const/4 v1, 0x1

    move v7, v1

    goto :goto_4

    :cond_3
    move v7, v2

    .line 2
    :goto_4
    sget-object v13, Lnz/d;->d:Lnz/d;

    .line 3
    sget-object v14, Llf0/i;->j:Llf0/i;

    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_4

    move v15, v2

    goto :goto_5

    :cond_4
    move/from16 v15, p3

    :goto_5
    and-int/lit16 v0, v0, 0x1000

    if-eqz v0, :cond_5

    move/from16 v16, v2

    goto :goto_6

    :cond_5
    move/from16 v16, p4

    :goto_6
    const/16 v17, 0x0

    const/4 v8, 0x1

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x1

    move-object/from16 v3, p0

    .line 4
    invoke-direct/range {v3 .. v17}, Lnz/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZLnz/d;Llf0/i;ZZZ)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZLnz/d;Llf0/i;ZZZ)V
    .locals 1

    const-string v0, "title"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "subtitle"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "description"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "viewMode"

    invoke-static {p11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Lnz/e;->a:Ljava/lang/String;

    .line 7
    iput-object p2, p0, Lnz/e;->b:Ljava/lang/String;

    .line 8
    iput-object p3, p0, Lnz/e;->c:Ljava/lang/String;

    .line 9
    iput-boolean p4, p0, Lnz/e;->d:Z

    .line 10
    iput-boolean p5, p0, Lnz/e;->e:Z

    .line 11
    iput-boolean p6, p0, Lnz/e;->f:Z

    .line 12
    iput-boolean p7, p0, Lnz/e;->g:Z

    .line 13
    iput-boolean p8, p0, Lnz/e;->h:Z

    .line 14
    iput-boolean p9, p0, Lnz/e;->i:Z

    .line 15
    iput-object p10, p0, Lnz/e;->j:Lnz/d;

    .line 16
    iput-object p11, p0, Lnz/e;->k:Llf0/i;

    .line 17
    iput-boolean p12, p0, Lnz/e;->l:Z

    .line 18
    iput-boolean p13, p0, Lnz/e;->m:Z

    .line 19
    iput-boolean p14, p0, Lnz/e;->n:Z

    return-void
.end method

.method public static a(Lnz/e;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLnz/d;Llf0/i;ZZZI)Lnz/e;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p13

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-object v2, v0, Lnz/e;->a:Ljava/lang/String;

    .line 10
    .line 11
    move-object v4, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object/from16 v4, p1

    .line 14
    .line 15
    :goto_0
    and-int/lit8 v2, v1, 0x2

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    iget-object v2, v0, Lnz/e;->b:Ljava/lang/String;

    .line 20
    .line 21
    move-object v5, v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move-object/from16 v5, p2

    .line 24
    .line 25
    :goto_1
    and-int/lit8 v2, v1, 0x4

    .line 26
    .line 27
    if-eqz v2, :cond_2

    .line 28
    .line 29
    iget-object v2, v0, Lnz/e;->c:Ljava/lang/String;

    .line 30
    .line 31
    move-object v6, v2

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    move-object/from16 v6, p3

    .line 34
    .line 35
    :goto_2
    and-int/lit8 v2, v1, 0x8

    .line 36
    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    iget-boolean v2, v0, Lnz/e;->d:Z

    .line 40
    .line 41
    :goto_3
    move v7, v2

    .line 42
    goto :goto_4

    .line 43
    :cond_3
    const/4 v2, 0x0

    .line 44
    goto :goto_3

    .line 45
    :goto_4
    iget-boolean v8, v0, Lnz/e;->e:Z

    .line 46
    .line 47
    and-int/lit8 v2, v1, 0x20

    .line 48
    .line 49
    if-eqz v2, :cond_4

    .line 50
    .line 51
    iget-boolean v2, v0, Lnz/e;->f:Z

    .line 52
    .line 53
    move v9, v2

    .line 54
    goto :goto_5

    .line 55
    :cond_4
    move/from16 v9, p4

    .line 56
    .line 57
    :goto_5
    and-int/lit8 v2, v1, 0x40

    .line 58
    .line 59
    if-eqz v2, :cond_5

    .line 60
    .line 61
    iget-boolean v2, v0, Lnz/e;->g:Z

    .line 62
    .line 63
    move v10, v2

    .line 64
    goto :goto_6

    .line 65
    :cond_5
    move/from16 v10, p5

    .line 66
    .line 67
    :goto_6
    and-int/lit16 v2, v1, 0x80

    .line 68
    .line 69
    if-eqz v2, :cond_6

    .line 70
    .line 71
    iget-boolean v2, v0, Lnz/e;->h:Z

    .line 72
    .line 73
    move v11, v2

    .line 74
    goto :goto_7

    .line 75
    :cond_6
    move/from16 v11, p6

    .line 76
    .line 77
    :goto_7
    and-int/lit16 v2, v1, 0x100

    .line 78
    .line 79
    if-eqz v2, :cond_7

    .line 80
    .line 81
    iget-boolean v2, v0, Lnz/e;->i:Z

    .line 82
    .line 83
    move v12, v2

    .line 84
    goto :goto_8

    .line 85
    :cond_7
    move/from16 v12, p7

    .line 86
    .line 87
    :goto_8
    and-int/lit16 v2, v1, 0x200

    .line 88
    .line 89
    if-eqz v2, :cond_8

    .line 90
    .line 91
    iget-object v2, v0, Lnz/e;->j:Lnz/d;

    .line 92
    .line 93
    move-object v13, v2

    .line 94
    goto :goto_9

    .line 95
    :cond_8
    move-object/from16 v13, p8

    .line 96
    .line 97
    :goto_9
    and-int/lit16 v2, v1, 0x400

    .line 98
    .line 99
    if-eqz v2, :cond_9

    .line 100
    .line 101
    iget-object v2, v0, Lnz/e;->k:Llf0/i;

    .line 102
    .line 103
    move-object v14, v2

    .line 104
    goto :goto_a

    .line 105
    :cond_9
    move-object/from16 v14, p9

    .line 106
    .line 107
    :goto_a
    and-int/lit16 v2, v1, 0x800

    .line 108
    .line 109
    if-eqz v2, :cond_a

    .line 110
    .line 111
    iget-boolean v2, v0, Lnz/e;->l:Z

    .line 112
    .line 113
    move v15, v2

    .line 114
    goto :goto_b

    .line 115
    :cond_a
    move/from16 v15, p10

    .line 116
    .line 117
    :goto_b
    and-int/lit16 v2, v1, 0x1000

    .line 118
    .line 119
    if-eqz v2, :cond_b

    .line 120
    .line 121
    iget-boolean v2, v0, Lnz/e;->m:Z

    .line 122
    .line 123
    move/from16 v16, v2

    .line 124
    .line 125
    goto :goto_c

    .line 126
    :cond_b
    move/from16 v16, p11

    .line 127
    .line 128
    :goto_c
    and-int/lit16 v1, v1, 0x2000

    .line 129
    .line 130
    if-eqz v1, :cond_c

    .line 131
    .line 132
    iget-boolean v1, v0, Lnz/e;->n:Z

    .line 133
    .line 134
    move/from16 v17, v1

    .line 135
    .line 136
    goto :goto_d

    .line 137
    :cond_c
    move/from16 v17, p12

    .line 138
    .line 139
    :goto_d
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    const-string v0, "title"

    .line 143
    .line 144
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    const-string v0, "subtitle"

    .line 148
    .line 149
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    const-string v0, "description"

    .line 153
    .line 154
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    const-string v0, "auxiliaryState"

    .line 158
    .line 159
    invoke-static {v13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    const-string v0, "viewMode"

    .line 163
    .line 164
    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    new-instance v3, Lnz/e;

    .line 168
    .line 169
    invoke-direct/range {v3 .. v17}, Lnz/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZLnz/d;Llf0/i;ZZZ)V

    .line 170
    .line 171
    .line 172
    return-object v3
.end method


# virtual methods
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
    instance-of v0, p1, Lnz/e;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lnz/e;

    .line 12
    .line 13
    iget-object v0, p0, Lnz/e;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p1, Lnz/e;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto/16 :goto_0

    .line 24
    .line 25
    :cond_2
    iget-object v0, p0, Lnz/e;->b:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v1, p1, Lnz/e;->b:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_3
    iget-object v0, p0, Lnz/e;->c:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v1, p1, Lnz/e;->c:Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_4

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_4
    iget-boolean v0, p0, Lnz/e;->d:Z

    .line 48
    .line 49
    iget-boolean v1, p1, Lnz/e;->d:Z

    .line 50
    .line 51
    if-eq v0, v1, :cond_5

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_5
    iget-boolean v0, p0, Lnz/e;->e:Z

    .line 55
    .line 56
    iget-boolean v1, p1, Lnz/e;->e:Z

    .line 57
    .line 58
    if-eq v0, v1, :cond_6

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_6
    iget-boolean v0, p0, Lnz/e;->f:Z

    .line 62
    .line 63
    iget-boolean v1, p1, Lnz/e;->f:Z

    .line 64
    .line 65
    if-eq v0, v1, :cond_7

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_7
    iget-boolean v0, p0, Lnz/e;->g:Z

    .line 69
    .line 70
    iget-boolean v1, p1, Lnz/e;->g:Z

    .line 71
    .line 72
    if-eq v0, v1, :cond_8

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_8
    iget-boolean v0, p0, Lnz/e;->h:Z

    .line 76
    .line 77
    iget-boolean v1, p1, Lnz/e;->h:Z

    .line 78
    .line 79
    if-eq v0, v1, :cond_9

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_9
    iget-boolean v0, p0, Lnz/e;->i:Z

    .line 83
    .line 84
    iget-boolean v1, p1, Lnz/e;->i:Z

    .line 85
    .line 86
    if-eq v0, v1, :cond_a

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_a
    iget-object v0, p0, Lnz/e;->j:Lnz/d;

    .line 90
    .line 91
    iget-object v1, p1, Lnz/e;->j:Lnz/d;

    .line 92
    .line 93
    if-eq v0, v1, :cond_b

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_b
    iget-object v0, p0, Lnz/e;->k:Llf0/i;

    .line 97
    .line 98
    iget-object v1, p1, Lnz/e;->k:Llf0/i;

    .line 99
    .line 100
    if-eq v0, v1, :cond_c

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_c
    iget-boolean v0, p0, Lnz/e;->l:Z

    .line 104
    .line 105
    iget-boolean v1, p1, Lnz/e;->l:Z

    .line 106
    .line 107
    if-eq v0, v1, :cond_d

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_d
    iget-boolean v0, p0, Lnz/e;->m:Z

    .line 111
    .line 112
    iget-boolean v1, p1, Lnz/e;->m:Z

    .line 113
    .line 114
    if-eq v0, v1, :cond_e

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_e
    iget-boolean p0, p0, Lnz/e;->n:Z

    .line 118
    .line 119
    iget-boolean p1, p1, Lnz/e;->n:Z

    .line 120
    .line 121
    if-eq p0, p1, :cond_f

    .line 122
    .line 123
    :goto_0
    const/4 p0, 0x0

    .line 124
    return p0

    .line 125
    :cond_f
    :goto_1
    const/4 p0, 0x1

    .line 126
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lnz/e;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lnz/e;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lnz/e;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lnz/e;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lnz/e;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lnz/e;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Lnz/e;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Lnz/e;->h:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v2, p0, Lnz/e;->i:Z

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-object v2, p0, Lnz/e;->j:Lnz/d;

    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    add-int/2addr v2, v0

    .line 65
    mul-int/2addr v2, v1

    .line 66
    iget-object v0, p0, Lnz/e;->k:Llf0/i;

    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    add-int/2addr v0, v2

    .line 73
    mul-int/2addr v0, v1

    .line 74
    iget-boolean v2, p0, Lnz/e;->l:Z

    .line 75
    .line 76
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    iget-boolean v2, p0, Lnz/e;->m:Z

    .line 81
    .line 82
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    iget-boolean p0, p0, Lnz/e;->n:Z

    .line 87
    .line 88
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    add-int/2addr p0, v0

    .line 93
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
    const-string v2, "State(title="

    .line 6
    .line 7
    iget-object v3, p0, Lnz/e;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lnz/e;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isLoading="

    .line 16
    .line 17
    const-string v2, ", isSwitchVisible="

    .line 18
    .line 19
    iget-object v3, p0, Lnz/e;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v4, p0, Lnz/e;->d:Z

    .line 22
    .line 23
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", isSwitchEnabled="

    .line 27
    .line 28
    const-string v2, ", isSwitchChecked="

    .line 29
    .line 30
    iget-boolean v3, p0, Lnz/e;->e:Z

    .line 31
    .line 32
    iget-boolean v4, p0, Lnz/e;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", isSendingRequest="

    .line 38
    .line 39
    const-string v2, ", isHeatingSelected="

    .line 40
    .line 41
    iget-boolean v3, p0, Lnz/e;->g:Z

    .line 42
    .line 43
    iget-boolean v4, p0, Lnz/e;->h:Z

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Lnz/e;->i:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", auxiliaryState="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lnz/e;->j:Lnz/d;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", viewMode="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lnz/e;->k:Llf0/i;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", isNotifySilentLoading="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-boolean v1, p0, Lnz/e;->l:Z

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", isSilentLoading="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const-string v1, ", hasOutsideTemperatureCapability="

    .line 89
    .line 90
    const-string v2, ")"

    .line 91
    .line 92
    iget-boolean v3, p0, Lnz/e;->m:Z

    .line 93
    .line 94
    iget-boolean p0, p0, Lnz/e;->n:Z

    .line 95
    .line 96
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0
.end method

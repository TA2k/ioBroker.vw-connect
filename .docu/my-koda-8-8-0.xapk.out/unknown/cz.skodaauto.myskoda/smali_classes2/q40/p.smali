.class public final Lq40/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Z

.field public final c:Lon0/w;

.field public final d:Lon0/x;

.field public final e:Ljava/lang/String;

.field public final f:Lon0/y;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Lql0/g;

.field public final j:Z

.field public final k:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZ)V
    .locals 1

    .line 1
    const-string v0, "termsConditionsUrl"

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
    iput-object p1, p0, Lq40/p;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput-boolean p2, p0, Lq40/p;->b:Z

    .line 12
    .line 13
    iput-object p3, p0, Lq40/p;->c:Lon0/w;

    .line 14
    .line 15
    iput-object p4, p0, Lq40/p;->d:Lon0/x;

    .line 16
    .line 17
    iput-object p5, p0, Lq40/p;->e:Ljava/lang/String;

    .line 18
    .line 19
    iput-object p6, p0, Lq40/p;->f:Lon0/y;

    .line 20
    .line 21
    iput-object p7, p0, Lq40/p;->g:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p8, p0, Lq40/p;->h:Ljava/lang/String;

    .line 24
    .line 25
    iput-object p9, p0, Lq40/p;->i:Lql0/g;

    .line 26
    .line 27
    iput-boolean p10, p0, Lq40/p;->j:Z

    .line 28
    .line 29
    iput-boolean p11, p0, Lq40/p;->k:Z

    .line 30
    .line 31
    return-void
.end method

.method public static a(Lq40/p;Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZI)Lq40/p;
    .locals 12

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
    iget-object p1, p0, Lq40/p;->a:Ljava/lang/String;

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
    iget-boolean p2, p0, Lq40/p;->b:Z

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
    iget-object p3, p0, Lq40/p;->c:Lon0/w;

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
    iget-object p1, p0, Lq40/p;->d:Lon0/x;

    .line 29
    .line 30
    move-object v4, p1

    .line 31
    goto :goto_0

    .line 32
    :cond_3
    move-object/from16 v4, p4

    .line 33
    .line 34
    :goto_0
    and-int/lit8 p1, v0, 0x10

    .line 35
    .line 36
    if-eqz p1, :cond_4

    .line 37
    .line 38
    iget-object p1, p0, Lq40/p;->e:Ljava/lang/String;

    .line 39
    .line 40
    move-object v5, p1

    .line 41
    goto :goto_1

    .line 42
    :cond_4
    move-object/from16 v5, p5

    .line 43
    .line 44
    :goto_1
    and-int/lit8 p1, v0, 0x20

    .line 45
    .line 46
    if-eqz p1, :cond_5

    .line 47
    .line 48
    iget-object p1, p0, Lq40/p;->f:Lon0/y;

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
    iget-object p1, p0, Lq40/p;->g:Ljava/lang/String;

    .line 59
    .line 60
    move-object v7, p1

    .line 61
    goto :goto_3

    .line 62
    :cond_6
    move-object/from16 v7, p7

    .line 63
    .line 64
    :goto_3
    and-int/lit16 p1, v0, 0x80

    .line 65
    .line 66
    if-eqz p1, :cond_7

    .line 67
    .line 68
    iget-object p1, p0, Lq40/p;->h:Ljava/lang/String;

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
    iget-object p1, p0, Lq40/p;->i:Lql0/g;

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
    iget-boolean p1, p0, Lq40/p;->j:Z

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
    iget-boolean p1, p0, Lq40/p;->k:Z

    .line 99
    .line 100
    :goto_7
    move v11, p1

    .line 101
    goto :goto_8

    .line 102
    :cond_a
    const/4 p1, 0x1

    .line 103
    goto :goto_7

    .line 104
    :goto_8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    const-string p0, "termsConditionsUrl"

    .line 108
    .line 109
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string p0, "pumpId"

    .line 113
    .line 114
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string p0, "paymentType"

    .line 118
    .line 119
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    new-instance v0, Lq40/p;

    .line 123
    .line 124
    invoke-direct/range {v0 .. v11}, Lq40/p;-><init>(Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZ)V

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
    instance-of v1, p1, Lq40/p;

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
    check-cast p1, Lq40/p;

    .line 12
    .line 13
    iget-object v1, p0, Lq40/p;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lq40/p;->a:Ljava/lang/String;

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
    iget-boolean v1, p0, Lq40/p;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lq40/p;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lq40/p;->c:Lon0/w;

    .line 32
    .line 33
    iget-object v3, p1, Lq40/p;->c:Lon0/w;

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
    iget-object v1, p0, Lq40/p;->d:Lon0/x;

    .line 43
    .line 44
    iget-object v3, p1, Lq40/p;->d:Lon0/x;

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
    iget-object v1, p0, Lq40/p;->e:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lq40/p;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lq40/p;->f:Lon0/y;

    .line 65
    .line 66
    iget-object v3, p1, Lq40/p;->f:Lon0/y;

    .line 67
    .line 68
    if-eq v1, v3, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object v1, p1, Lq40/p;->g:Ljava/lang/String;

    .line 72
    .line 73
    iget-object v3, p0, Lq40/p;->g:Ljava/lang/String;

    .line 74
    .line 75
    if-nez v3, :cond_9

    .line 76
    .line 77
    if-nez v1, :cond_8

    .line 78
    .line 79
    move v1, v0

    .line 80
    goto :goto_1

    .line 81
    :cond_8
    :goto_0
    move v1, v2

    .line 82
    goto :goto_1

    .line 83
    :cond_9
    if-nez v1, :cond_a

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_a
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    :goto_1
    if-nez v1, :cond_b

    .line 91
    .line 92
    return v2

    .line 93
    :cond_b
    iget-object v1, p0, Lq40/p;->h:Ljava/lang/String;

    .line 94
    .line 95
    iget-object v3, p1, Lq40/p;->h:Ljava/lang/String;

    .line 96
    .line 97
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-nez v1, :cond_c

    .line 102
    .line 103
    return v2

    .line 104
    :cond_c
    iget-object v1, p0, Lq40/p;->i:Lql0/g;

    .line 105
    .line 106
    iget-object v3, p1, Lq40/p;->i:Lql0/g;

    .line 107
    .line 108
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-nez v1, :cond_d

    .line 113
    .line 114
    return v2

    .line 115
    :cond_d
    iget-boolean v1, p0, Lq40/p;->j:Z

    .line 116
    .line 117
    iget-boolean v3, p1, Lq40/p;->j:Z

    .line 118
    .line 119
    if-eq v1, v3, :cond_e

    .line 120
    .line 121
    return v2

    .line 122
    :cond_e
    iget-boolean p0, p0, Lq40/p;->k:Z

    .line 123
    .line 124
    iget-boolean p1, p1, Lq40/p;->k:Z

    .line 125
    .line 126
    if-eq p0, p1, :cond_f

    .line 127
    .line 128
    return v2

    .line 129
    :cond_f
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lq40/p;->a:Ljava/lang/String;

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
    iget-boolean v2, p0, Lq40/p;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v2, 0x0

    .line 17
    iget-object v3, p0, Lq40/p;->c:Lon0/w;

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
    invoke-virtual {v3}, Lon0/w;->hashCode()I

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
    iget-object v3, p0, Lq40/p;->d:Lon0/x;

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
    invoke-virtual {v3}, Lon0/x;->hashCode()I

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
    iget-object v3, p0, Lq40/p;->e:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iget-object v3, p0, Lq40/p;->f:Lon0/y;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    add-int/2addr v3, v0

    .line 54
    mul-int/2addr v3, v1

    .line 55
    iget-object v0, p0, Lq40/p;->g:Ljava/lang/String;

    .line 56
    .line 57
    if-nez v0, :cond_2

    .line 58
    .line 59
    move v0, v2

    .line 60
    goto :goto_2

    .line 61
    :cond_2
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    :goto_2
    add-int/2addr v3, v0

    .line 66
    mul-int/2addr v3, v1

    .line 67
    iget-object v0, p0, Lq40/p;->h:Ljava/lang/String;

    .line 68
    .line 69
    if-nez v0, :cond_3

    .line 70
    .line 71
    move v0, v2

    .line 72
    goto :goto_3

    .line 73
    :cond_3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    :goto_3
    add-int/2addr v3, v0

    .line 78
    mul-int/2addr v3, v1

    .line 79
    iget-object v0, p0, Lq40/p;->i:Lql0/g;

    .line 80
    .line 81
    if-nez v0, :cond_4

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_4
    invoke-virtual {v0}, Lql0/g;->hashCode()I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    :goto_4
    add-int/2addr v3, v2

    .line 89
    mul-int/2addr v3, v1

    .line 90
    iget-boolean v0, p0, Lq40/p;->j:Z

    .line 91
    .line 92
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    iget-boolean p0, p0, Lq40/p;->k:Z

    .line 97
    .line 98
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    add-int/2addr p0, v0

    .line 103
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lq40/p;->g:Ljava/lang/String;

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
    const-string v1, ", loading="

    .line 13
    .line 14
    const-string v2, ", fuel="

    .line 15
    .line 16
    const-string v3, "State(termsConditionsUrl="

    .line 17
    .line 18
    iget-object v4, p0, Lq40/p;->a:Ljava/lang/String;

    .line 19
    .line 20
    iget-boolean v5, p0, Lq40/p;->b:Z

    .line 21
    .line 22
    invoke-static {v3, v4, v1, v2, v5}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    iget-object v2, p0, Lq40/p;->c:Lon0/w;

    .line 27
    .line 28
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v2, ", station="

    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v2, p0, Lq40/p;->d:Lon0/x;

    .line 37
    .line 38
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v2, ", pumpId="

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object v2, p0, Lq40/p;->e:Ljava/lang/String;

    .line 47
    .line 48
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v2, ", paymentType="

    .line 52
    .line 53
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v2, p0, Lq40/p;->f:Lon0/y;

    .line 57
    .line 58
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v2, ", vin="

    .line 62
    .line 63
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v2, ", licensePlate="

    .line 67
    .line 68
    const-string v3, ", error="

    .line 69
    .line 70
    iget-object v4, p0, Lq40/p;->h:Ljava/lang/String;

    .line 71
    .line 72
    invoke-static {v1, v0, v2, v4, v3}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    iget-object v0, p0, Lq40/p;->i:Lql0/g;

    .line 76
    .line 77
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string v0, ", isTransactionError="

    .line 81
    .line 82
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    iget-boolean v0, p0, Lq40/p;->j:Z

    .line 86
    .line 87
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v0, ", isGenericError="

    .line 91
    .line 92
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v0, ")"

    .line 96
    .line 97
    iget-boolean p0, p0, Lq40/p;->k:Z

    .line 98
    .line 99
    invoke-static {v1, p0, v0}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method

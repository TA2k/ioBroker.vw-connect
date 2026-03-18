.class public final Lss0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lss0/x;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Lss0/a;

.field public final d:Ljava/util/List;

.field public final e:Ljava/lang/String;

.field public final f:Lss0/t;

.field public final g:Lss0/j;

.field public final h:Ljava/lang/String;

.field public final i:I

.field public final j:Lss0/v;

.field public final k:Ljava/util/List;

.field public final l:Lss0/g;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lss0/a;Ljava/util/List;Ljava/lang/String;Lss0/t;Lss0/j;Ljava/lang/String;ILss0/v;Ljava/util/List;)V
    .locals 1

    .line 1
    const-string v0, "commissionId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "name"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lss0/u;->a:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p2, p0, Lss0/u;->b:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p3, p0, Lss0/u;->c:Lss0/a;

    .line 19
    .line 20
    iput-object p4, p0, Lss0/u;->d:Ljava/util/List;

    .line 21
    .line 22
    iput-object p5, p0, Lss0/u;->e:Ljava/lang/String;

    .line 23
    .line 24
    iput-object p6, p0, Lss0/u;->f:Lss0/t;

    .line 25
    .line 26
    iput-object p7, p0, Lss0/u;->g:Lss0/j;

    .line 27
    .line 28
    iput-object p8, p0, Lss0/u;->h:Ljava/lang/String;

    .line 29
    .line 30
    iput p9, p0, Lss0/u;->i:I

    .line 31
    .line 32
    iput-object p10, p0, Lss0/u;->j:Lss0/v;

    .line 33
    .line 34
    iput-object p11, p0, Lss0/u;->k:Ljava/util/List;

    .line 35
    .line 36
    new-instance p2, Lss0/g;

    .line 37
    .line 38
    invoke-direct {p2, p1}, Lss0/g;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iput-object p2, p0, Lss0/u;->l:Lss0/g;

    .line 42
    .line 43
    return-void
.end method

.method public static a(Lss0/u;Ljava/util/List;Lss0/t;Lss0/j;Ljava/lang/String;ILss0/v;Ljava/util/List;I)Lss0/u;
    .locals 12

    .line 1
    move/from16 v0, p8

    .line 2
    .line 3
    iget-object v1, p0, Lss0/u;->a:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lss0/u;->b:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Lss0/u;->c:Lss0/a;

    .line 8
    .line 9
    and-int/lit8 v4, v0, 0x8

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    iget-object p1, p0, Lss0/u;->d:Ljava/util/List;

    .line 14
    .line 15
    :cond_0
    move-object v4, p1

    .line 16
    iget-object v5, p0, Lss0/u;->e:Ljava/lang/String;

    .line 17
    .line 18
    and-int/lit8 p1, v0, 0x20

    .line 19
    .line 20
    if-eqz p1, :cond_1

    .line 21
    .line 22
    iget-object p2, p0, Lss0/u;->f:Lss0/t;

    .line 23
    .line 24
    :cond_1
    move-object v6, p2

    .line 25
    and-int/lit8 p1, v0, 0x40

    .line 26
    .line 27
    if-eqz p1, :cond_2

    .line 28
    .line 29
    iget-object p1, p0, Lss0/u;->g:Lss0/j;

    .line 30
    .line 31
    move-object v7, p1

    .line 32
    goto :goto_0

    .line 33
    :cond_2
    move-object v7, p3

    .line 34
    :goto_0
    and-int/lit16 p1, v0, 0x80

    .line 35
    .line 36
    if-eqz p1, :cond_3

    .line 37
    .line 38
    iget-object p1, p0, Lss0/u;->h:Ljava/lang/String;

    .line 39
    .line 40
    move-object v8, p1

    .line 41
    goto :goto_1

    .line 42
    :cond_3
    move-object/from16 v8, p4

    .line 43
    .line 44
    :goto_1
    and-int/lit16 p1, v0, 0x100

    .line 45
    .line 46
    if-eqz p1, :cond_4

    .line 47
    .line 48
    iget p1, p0, Lss0/u;->i:I

    .line 49
    .line 50
    move v9, p1

    .line 51
    goto :goto_2

    .line 52
    :cond_4
    move/from16 v9, p5

    .line 53
    .line 54
    :goto_2
    and-int/lit16 p1, v0, 0x200

    .line 55
    .line 56
    if-eqz p1, :cond_5

    .line 57
    .line 58
    iget-object p1, p0, Lss0/u;->j:Lss0/v;

    .line 59
    .line 60
    move-object v10, p1

    .line 61
    goto :goto_3

    .line 62
    :cond_5
    move-object/from16 v10, p6

    .line 63
    .line 64
    :goto_3
    and-int/lit16 p1, v0, 0x400

    .line 65
    .line 66
    if-eqz p1, :cond_6

    .line 67
    .line 68
    iget-object p1, p0, Lss0/u;->k:Ljava/util/List;

    .line 69
    .line 70
    move-object v11, p1

    .line 71
    goto :goto_4

    .line 72
    :cond_6
    move-object/from16 v11, p7

    .line 73
    .line 74
    :goto_4
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    const-string p0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-CommissionId$-commissionId$0"

    .line 78
    .line 79
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    const-string p0, "name"

    .line 83
    .line 84
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    new-instance v0, Lss0/u;

    .line 88
    .line 89
    invoke-direct/range {v0 .. v11}, Lss0/u;-><init>(Ljava/lang/String;Ljava/lang/String;Lss0/a;Ljava/util/List;Ljava/lang/String;Lss0/t;Lss0/j;Ljava/lang/String;ILss0/v;Ljava/util/List;)V

    .line 90
    .line 91
    .line 92
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
    instance-of v1, p1, Lss0/u;

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
    check-cast p1, Lss0/u;

    .line 12
    .line 13
    iget-object v1, p0, Lss0/u;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lss0/u;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lss0/u;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lss0/u;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lss0/u;->c:Lss0/a;

    .line 36
    .line 37
    iget-object v3, p1, Lss0/u;->c:Lss0/a;

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lss0/u;->d:Ljava/util/List;

    .line 43
    .line 44
    iget-object v3, p1, Lss0/u;->d:Ljava/util/List;

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
    iget-object v1, p1, Lss0/u;->e:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p0, Lss0/u;->e:Ljava/lang/String;

    .line 56
    .line 57
    if-nez v3, :cond_7

    .line 58
    .line 59
    if-nez v1, :cond_6

    .line 60
    .line 61
    move v1, v0

    .line 62
    goto :goto_1

    .line 63
    :cond_6
    :goto_0
    move v1, v2

    .line 64
    goto :goto_1

    .line 65
    :cond_7
    if-nez v1, :cond_8

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_8
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    :goto_1
    if-nez v1, :cond_9

    .line 73
    .line 74
    return v2

    .line 75
    :cond_9
    iget-object v1, p0, Lss0/u;->f:Lss0/t;

    .line 76
    .line 77
    iget-object v3, p1, Lss0/u;->f:Lss0/t;

    .line 78
    .line 79
    if-eq v1, v3, :cond_a

    .line 80
    .line 81
    return v2

    .line 82
    :cond_a
    iget-object v1, p0, Lss0/u;->g:Lss0/j;

    .line 83
    .line 84
    iget-object v3, p1, Lss0/u;->g:Lss0/j;

    .line 85
    .line 86
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-nez v1, :cond_b

    .line 91
    .line 92
    return v2

    .line 93
    :cond_b
    iget-object v1, p0, Lss0/u;->h:Ljava/lang/String;

    .line 94
    .line 95
    iget-object v3, p1, Lss0/u;->h:Ljava/lang/String;

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
    iget v1, p0, Lss0/u;->i:I

    .line 105
    .line 106
    iget v3, p1, Lss0/u;->i:I

    .line 107
    .line 108
    if-eq v1, v3, :cond_d

    .line 109
    .line 110
    return v2

    .line 111
    :cond_d
    iget-object v1, p0, Lss0/u;->j:Lss0/v;

    .line 112
    .line 113
    iget-object v3, p1, Lss0/u;->j:Lss0/v;

    .line 114
    .line 115
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    if-nez v1, :cond_e

    .line 120
    .line 121
    return v2

    .line 122
    :cond_e
    iget-object p0, p0, Lss0/u;->k:Ljava/util/List;

    .line 123
    .line 124
    iget-object p1, p1, Lss0/u;->k:Ljava/util/List;

    .line 125
    .line 126
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    if-nez p0, :cond_f

    .line 131
    .line 132
    return v2

    .line 133
    :cond_f
    return v0
.end method

.method public final getId()Lss0/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Lss0/u;->l:Lss0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lss0/u;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lss0/u;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lss0/u;->c:Lss0/a;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Lss0/u;->d:Ljava/util/List;

    .line 25
    .line 26
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v2, 0x0

    .line 31
    iget-object v3, p0, Lss0/u;->e:Ljava/lang/String;

    .line 32
    .line 33
    if-nez v3, :cond_0

    .line 34
    .line 35
    move v3, v2

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
    add-int/2addr v0, v3

    .line 42
    mul-int/2addr v0, v1

    .line 43
    iget-object v3, p0, Lss0/u;->f:Lss0/t;

    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    add-int/2addr v3, v0

    .line 50
    mul-int/2addr v3, v1

    .line 51
    iget-object v0, p0, Lss0/u;->g:Lss0/j;

    .line 52
    .line 53
    if-nez v0, :cond_1

    .line 54
    .line 55
    move v0, v2

    .line 56
    goto :goto_1

    .line 57
    :cond_1
    invoke-virtual {v0}, Lss0/j;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    :goto_1
    add-int/2addr v3, v0

    .line 62
    mul-int/2addr v3, v1

    .line 63
    iget-object v0, p0, Lss0/u;->h:Ljava/lang/String;

    .line 64
    .line 65
    if-nez v0, :cond_2

    .line 66
    .line 67
    move v0, v2

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    :goto_2
    add-int/2addr v3, v0

    .line 74
    mul-int/2addr v3, v1

    .line 75
    iget v0, p0, Lss0/u;->i:I

    .line 76
    .line 77
    invoke-static {v0, v3, v1}, Lc1/j0;->g(III)I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    iget-object v3, p0, Lss0/u;->j:Lss0/v;

    .line 82
    .line 83
    if-nez v3, :cond_3

    .line 84
    .line 85
    move v3, v2

    .line 86
    goto :goto_3

    .line 87
    :cond_3
    invoke-virtual {v3}, Lss0/v;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    :goto_3
    add-int/2addr v0, v3

    .line 92
    mul-int/2addr v0, v1

    .line 93
    iget-object p0, p0, Lss0/u;->k:Ljava/util/List;

    .line 94
    .line 95
    if-nez p0, :cond_4

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_4
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    :goto_4
    add-int/2addr v0, v2

    .line 103
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lss0/u;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {v0}, Lss0/g;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lss0/u;->e:Ljava/lang/String;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    const-string v1, "null"

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-static {v1}, Lss0/j0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    :goto_0
    const-string v2, ", name="

    .line 19
    .line 20
    const-string v3, ", activationStatus="

    .line 21
    .line 22
    const-string v4, "OrderedVehicle(commissionId="

    .line 23
    .line 24
    iget-object v5, p0, Lss0/u;->b:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {v4, v0, v2, v5, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iget-object v2, p0, Lss0/u;->c:Lss0/a;

    .line 31
    .line 32
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v2, ", renders="

    .line 36
    .line 37
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget-object v2, p0, Lss0/u;->d:Ljava/util/List;

    .line 41
    .line 42
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v2, ", vin="

    .line 46
    .line 47
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", orderStatus="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lss0/u;->f:Lss0/t;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", deliveryDate="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lss0/u;->g:Lss0/j;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", dealerId="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lss0/u;->h:Ljava/lang/String;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", priority="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget v1, p0, Lss0/u;->i:I

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", specification="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lss0/u;->j:Lss0/v;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", checkPoints="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v1, ")"

    .line 109
    .line 110
    iget-object p0, p0, Lss0/u;->k:Ljava/util/List;

    .line 111
    .line 112
    invoke-static {v0, p0, v1}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0
.end method

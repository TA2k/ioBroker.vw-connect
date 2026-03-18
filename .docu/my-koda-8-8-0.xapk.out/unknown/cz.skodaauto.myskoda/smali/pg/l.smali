.class public final Lpg/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Log/i;

.field public final b:Lug/b;

.field public final c:Z

.field public final d:Lpg/a;

.field public final e:Z

.field public final f:Z

.field public final g:Lpg/a;

.field public final h:Lmc/x;

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Z

.field public final m:Z

.field public final n:Z

.field public final o:Lug/a;

.field public final p:Ljava/lang/String;


# direct methods
.method public constructor <init>(Log/i;Lug/b;ZLpg/a;ZZLpg/a;Lmc/x;ZZZZZZLug/a;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpg/l;->a:Log/i;

    .line 5
    .line 6
    iput-object p2, p0, Lpg/l;->b:Lug/b;

    .line 7
    .line 8
    iput-boolean p3, p0, Lpg/l;->c:Z

    .line 9
    .line 10
    iput-object p4, p0, Lpg/l;->d:Lpg/a;

    .line 11
    .line 12
    iput-boolean p5, p0, Lpg/l;->e:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lpg/l;->f:Z

    .line 15
    .line 16
    iput-object p7, p0, Lpg/l;->g:Lpg/a;

    .line 17
    .line 18
    iput-object p8, p0, Lpg/l;->h:Lmc/x;

    .line 19
    .line 20
    iput-boolean p9, p0, Lpg/l;->i:Z

    .line 21
    .line 22
    iput-boolean p10, p0, Lpg/l;->j:Z

    .line 23
    .line 24
    iput-boolean p11, p0, Lpg/l;->k:Z

    .line 25
    .line 26
    iput-boolean p12, p0, Lpg/l;->l:Z

    .line 27
    .line 28
    iput-boolean p13, p0, Lpg/l;->m:Z

    .line 29
    .line 30
    iput-boolean p14, p0, Lpg/l;->n:Z

    .line 31
    .line 32
    iput-object p15, p0, Lpg/l;->o:Lug/a;

    .line 33
    .line 34
    move-object/from16 p1, p16

    .line 35
    .line 36
    iput-object p1, p0, Lpg/l;->p:Ljava/lang/String;

    .line 37
    .line 38
    return-void
.end method

.method public static a(Lpg/l;ZZLug/a;I)Lpg/l;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p4

    .line 4
    .line 5
    iget-object v2, v0, Lpg/l;->a:Log/i;

    .line 6
    .line 7
    move-object v3, v2

    .line 8
    iget-object v2, v0, Lpg/l;->b:Lug/b;

    .line 9
    .line 10
    move-object v4, v3

    .line 11
    iget-boolean v3, v0, Lpg/l;->c:Z

    .line 12
    .line 13
    move-object v5, v4

    .line 14
    iget-object v4, v0, Lpg/l;->d:Lpg/a;

    .line 15
    .line 16
    move-object v6, v5

    .line 17
    iget-boolean v5, v0, Lpg/l;->e:Z

    .line 18
    .line 19
    move-object v7, v6

    .line 20
    iget-boolean v6, v0, Lpg/l;->f:Z

    .line 21
    .line 22
    move-object v8, v7

    .line 23
    iget-object v7, v0, Lpg/l;->g:Lpg/a;

    .line 24
    .line 25
    move-object v9, v8

    .line 26
    iget-object v8, v0, Lpg/l;->h:Lmc/x;

    .line 27
    .line 28
    and-int/lit16 v10, v1, 0x100

    .line 29
    .line 30
    if-eqz v10, :cond_0

    .line 31
    .line 32
    iget-boolean v10, v0, Lpg/l;->i:Z

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move/from16 v10, p1

    .line 36
    .line 37
    :goto_0
    and-int/lit16 v11, v1, 0x200

    .line 38
    .line 39
    if-eqz v11, :cond_1

    .line 40
    .line 41
    iget-boolean v11, v0, Lpg/l;->j:Z

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move/from16 v11, p2

    .line 45
    .line 46
    :goto_1
    iget-boolean v12, v0, Lpg/l;->k:Z

    .line 47
    .line 48
    move-object v13, v9

    .line 49
    move v9, v10

    .line 50
    move v10, v11

    .line 51
    move v11, v12

    .line 52
    iget-boolean v12, v0, Lpg/l;->l:Z

    .line 53
    .line 54
    move-object v14, v13

    .line 55
    iget-boolean v13, v0, Lpg/l;->m:Z

    .line 56
    .line 57
    move-object v15, v14

    .line 58
    iget-boolean v14, v0, Lpg/l;->n:Z

    .line 59
    .line 60
    and-int/lit16 v1, v1, 0x4000

    .line 61
    .line 62
    if-eqz v1, :cond_2

    .line 63
    .line 64
    iget-object v1, v0, Lpg/l;->o:Lug/a;

    .line 65
    .line 66
    move-object/from16 p1, v1

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_2
    move-object/from16 p1, p3

    .line 70
    .line 71
    :goto_2
    iget-object v1, v0, Lpg/l;->p:Ljava/lang/String;

    .line 72
    .line 73
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    new-instance v0, Lpg/l;

    .line 77
    .line 78
    move-object/from16 v16, v1

    .line 79
    .line 80
    move-object v1, v15

    .line 81
    move-object/from16 v15, p1

    .line 82
    .line 83
    invoke-direct/range {v0 .. v16}, Lpg/l;-><init>(Log/i;Lug/b;ZLpg/a;ZZLpg/a;Lmc/x;ZZZZZZLug/a;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    return-object v0
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
    instance-of v0, p1, Lpg/l;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lpg/l;

    .line 12
    .line 13
    iget-object v0, p0, Lpg/l;->a:Log/i;

    .line 14
    .line 15
    iget-object v1, p1, Lpg/l;->a:Log/i;

    .line 16
    .line 17
    if-eq v0, v1, :cond_2

    .line 18
    .line 19
    goto/16 :goto_0

    .line 20
    .line 21
    :cond_2
    iget-object v0, p0, Lpg/l;->b:Lug/b;

    .line 22
    .line 23
    iget-object v1, p1, Lpg/l;->b:Lug/b;

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Lug/b;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-nez v0, :cond_3

    .line 30
    .line 31
    goto/16 :goto_0

    .line 32
    .line 33
    :cond_3
    iget-boolean v0, p0, Lpg/l;->c:Z

    .line 34
    .line 35
    iget-boolean v1, p1, Lpg/l;->c:Z

    .line 36
    .line 37
    if-eq v0, v1, :cond_4

    .line 38
    .line 39
    goto/16 :goto_0

    .line 40
    .line 41
    :cond_4
    iget-object v0, p0, Lpg/l;->d:Lpg/a;

    .line 42
    .line 43
    iget-object v1, p1, Lpg/l;->d:Lpg/a;

    .line 44
    .line 45
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-nez v0, :cond_5

    .line 50
    .line 51
    goto/16 :goto_0

    .line 52
    .line 53
    :cond_5
    iget-boolean v0, p0, Lpg/l;->e:Z

    .line 54
    .line 55
    iget-boolean v1, p1, Lpg/l;->e:Z

    .line 56
    .line 57
    if-eq v0, v1, :cond_6

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_6
    iget-boolean v0, p0, Lpg/l;->f:Z

    .line 61
    .line 62
    iget-boolean v1, p1, Lpg/l;->f:Z

    .line 63
    .line 64
    if-eq v0, v1, :cond_7

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_7
    iget-object v0, p0, Lpg/l;->g:Lpg/a;

    .line 68
    .line 69
    iget-object v1, p1, Lpg/l;->g:Lpg/a;

    .line 70
    .line 71
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-nez v0, :cond_8

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_8
    iget-object v0, p0, Lpg/l;->h:Lmc/x;

    .line 79
    .line 80
    iget-object v1, p1, Lpg/l;->h:Lmc/x;

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Lmc/x;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-nez v0, :cond_9

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_9
    iget-boolean v0, p0, Lpg/l;->i:Z

    .line 90
    .line 91
    iget-boolean v1, p1, Lpg/l;->i:Z

    .line 92
    .line 93
    if-eq v0, v1, :cond_a

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_a
    iget-boolean v0, p0, Lpg/l;->j:Z

    .line 97
    .line 98
    iget-boolean v1, p1, Lpg/l;->j:Z

    .line 99
    .line 100
    if-eq v0, v1, :cond_b

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_b
    iget-boolean v0, p0, Lpg/l;->k:Z

    .line 104
    .line 105
    iget-boolean v1, p1, Lpg/l;->k:Z

    .line 106
    .line 107
    if-eq v0, v1, :cond_c

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_c
    iget-boolean v0, p0, Lpg/l;->l:Z

    .line 111
    .line 112
    iget-boolean v1, p1, Lpg/l;->l:Z

    .line 113
    .line 114
    if-eq v0, v1, :cond_d

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_d
    iget-boolean v0, p0, Lpg/l;->m:Z

    .line 118
    .line 119
    iget-boolean v1, p1, Lpg/l;->m:Z

    .line 120
    .line 121
    if-eq v0, v1, :cond_e

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :cond_e
    iget-boolean v0, p0, Lpg/l;->n:Z

    .line 125
    .line 126
    iget-boolean v1, p1, Lpg/l;->n:Z

    .line 127
    .line 128
    if-eq v0, v1, :cond_f

    .line 129
    .line 130
    goto :goto_0

    .line 131
    :cond_f
    iget-object v0, p0, Lpg/l;->o:Lug/a;

    .line 132
    .line 133
    iget-object v1, p1, Lpg/l;->o:Lug/a;

    .line 134
    .line 135
    if-eq v0, v1, :cond_10

    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_10
    iget-object p0, p0, Lpg/l;->p:Ljava/lang/String;

    .line 139
    .line 140
    iget-object p1, p1, Lpg/l;->p:Ljava/lang/String;

    .line 141
    .line 142
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    if-nez p0, :cond_11

    .line 147
    .line 148
    :goto_0
    const/4 p0, 0x0

    .line 149
    return p0

    .line 150
    :cond_11
    :goto_1
    const/4 p0, 0x1

    .line 151
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lpg/l;->a:Log/i;

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
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

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
    iget-object v3, p0, Lpg/l;->b:Lug/b;

    .line 16
    .line 17
    invoke-virtual {v3}, Lug/b;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    add-int/2addr v3, v1

    .line 22
    mul-int/2addr v3, v2

    .line 23
    iget-boolean v1, p0, Lpg/l;->c:Z

    .line 24
    .line 25
    invoke-static {v3, v2, v1}, La7/g0;->e(IIZ)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    iget-object v3, p0, Lpg/l;->d:Lpg/a;

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    move v3, v0

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v3}, Lpg/a;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_1
    add-int/2addr v1, v3

    .line 40
    mul-int/2addr v1, v2

    .line 41
    iget-boolean v3, p0, Lpg/l;->e:Z

    .line 42
    .line 43
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    iget-boolean v3, p0, Lpg/l;->f:Z

    .line 48
    .line 49
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    iget-object v3, p0, Lpg/l;->g:Lpg/a;

    .line 54
    .line 55
    if-nez v3, :cond_2

    .line 56
    .line 57
    move v3, v0

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    invoke-virtual {v3}, Lpg/a;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    :goto_2
    add-int/2addr v1, v3

    .line 64
    mul-int/2addr v1, v2

    .line 65
    iget-object v3, p0, Lpg/l;->h:Lmc/x;

    .line 66
    .line 67
    invoke-virtual {v3}, Lmc/x;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    add-int/2addr v3, v1

    .line 72
    mul-int/2addr v3, v2

    .line 73
    iget-boolean v1, p0, Lpg/l;->i:Z

    .line 74
    .line 75
    invoke-static {v3, v2, v1}, La7/g0;->e(IIZ)I

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    iget-boolean v3, p0, Lpg/l;->j:Z

    .line 80
    .line 81
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    iget-boolean v3, p0, Lpg/l;->k:Z

    .line 86
    .line 87
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    iget-boolean v3, p0, Lpg/l;->l:Z

    .line 92
    .line 93
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    iget-boolean v3, p0, Lpg/l;->m:Z

    .line 98
    .line 99
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    iget-boolean v3, p0, Lpg/l;->n:Z

    .line 104
    .line 105
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    iget-object v3, p0, Lpg/l;->o:Lug/a;

    .line 110
    .line 111
    if-nez v3, :cond_3

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_3
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    :goto_3
    add-int/2addr v1, v0

    .line 119
    mul-int/2addr v1, v2

    .line 120
    iget-object p0, p0, Lpg/l;->p:Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 123
    .line 124
    .line 125
    move-result p0

    .line 126
    add-int/2addr p0, v1

    .line 127
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "TariffConfirmationUiState(selectedChargingCardDeliveryOption="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lpg/l;->a:Log/i;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", tariff="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lpg/l;->b:Lug/b;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isBillingAddressVisible="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-boolean v1, p0, Lpg/l;->c:Z

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", billingAddress="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lpg/l;->d:Lpg/a;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", isCardDeliveryVisible="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", isCardDeliveryAddressVisible="

    .line 49
    .line 50
    const-string v2, ", cardDeliveryAddress="

    .line 51
    .line 52
    iget-boolean v3, p0, Lpg/l;->e:Z

    .line 53
    .line 54
    iget-boolean v4, p0, Lpg/l;->f:Z

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Lpg/l;->g:Lpg/a;

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v1, ", paymentOption="

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Lpg/l;->h:Lmc/x;

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, ", isCheckboxEnabled="

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    const-string v1, ", isCtaEnabled="

    .line 80
    .line 81
    const-string v2, ", isNewSubscriptionCta="

    .line 82
    .line 83
    iget-boolean v3, p0, Lpg/l;->i:Z

    .line 84
    .line 85
    iget-boolean v4, p0, Lpg/l;->j:Z

    .line 86
    .line 87
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    const-string v1, ", isEligibleForUpgradeAndFollowUpCta="

    .line 91
    .line 92
    const-string v2, ", isOnlyEligibleForUpgradeCta="

    .line 93
    .line 94
    iget-boolean v3, p0, Lpg/l;->k:Z

    .line 95
    .line 96
    iget-boolean v4, p0, Lpg/l;->l:Z

    .line 97
    .line 98
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string v1, ", isOnlyEligibleForFollowUpCta="

    .line 102
    .line 103
    const-string v2, ", tariffActivationOption="

    .line 104
    .line 105
    iget-boolean v3, p0, Lpg/l;->m:Z

    .line 106
    .line 107
    iget-boolean v4, p0, Lpg/l;->n:Z

    .line 108
    .line 109
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 110
    .line 111
    .line 112
    iget-object v1, p0, Lpg/l;->o:Lug/a;

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v1, ", formattedFollowUpStartDate="

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    iget-object p0, p0, Lpg/l;->p:Ljava/lang/String;

    .line 123
    .line 124
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string p0, ")"

    .line 128
    .line 129
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    return-object p0
.end method

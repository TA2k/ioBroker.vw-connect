.class public final Lg70/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Lhp0/e;

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Lql0/g;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lhp0/e;ZZZZZZLql0/g;)V
    .locals 1

    .line 1
    const-string v0, "vehicleName"

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
    iput-object p1, p0, Lg70/i;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Lg70/i;->b:Ljava/lang/String;

    .line 12
    .line 13
    iput-object p3, p0, Lg70/i;->c:Lhp0/e;

    .line 14
    .line 15
    iput-boolean p4, p0, Lg70/i;->d:Z

    .line 16
    .line 17
    iput-boolean p5, p0, Lg70/i;->e:Z

    .line 18
    .line 19
    iput-boolean p6, p0, Lg70/i;->f:Z

    .line 20
    .line 21
    iput-boolean p7, p0, Lg70/i;->g:Z

    .line 22
    .line 23
    iput-boolean p8, p0, Lg70/i;->h:Z

    .line 24
    .line 25
    iput-boolean p9, p0, Lg70/i;->i:Z

    .line 26
    .line 27
    iput-object p10, p0, Lg70/i;->j:Lql0/g;

    .line 28
    .line 29
    return-void
.end method

.method public static a(Lg70/i;Ljava/lang/String;Ljava/lang/String;Lhp0/e;ZZZZZZLql0/g;I)Lg70/i;
    .locals 11

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
    iget-object p1, p0, Lg70/i;->a:Ljava/lang/String;

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
    iget-object p2, p0, Lg70/i;->b:Ljava/lang/String;

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
    iget-object p3, p0, Lg70/i;->c:Lhp0/e;

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
    iget-boolean p4, p0, Lg70/i;->d:Z

    .line 29
    .line 30
    :cond_3
    move v4, p4

    .line 31
    and-int/lit8 p1, v0, 0x10

    .line 32
    .line 33
    if-eqz p1, :cond_4

    .line 34
    .line 35
    iget-boolean p1, p0, Lg70/i;->e:Z

    .line 36
    .line 37
    move v5, p1

    .line 38
    goto :goto_0

    .line 39
    :cond_4
    move/from16 v5, p5

    .line 40
    .line 41
    :goto_0
    and-int/lit8 p1, v0, 0x20

    .line 42
    .line 43
    if-eqz p1, :cond_5

    .line 44
    .line 45
    iget-boolean p1, p0, Lg70/i;->f:Z

    .line 46
    .line 47
    move v6, p1

    .line 48
    goto :goto_1

    .line 49
    :cond_5
    move/from16 v6, p6

    .line 50
    .line 51
    :goto_1
    and-int/lit8 p1, v0, 0x40

    .line 52
    .line 53
    if-eqz p1, :cond_6

    .line 54
    .line 55
    iget-boolean p1, p0, Lg70/i;->g:Z

    .line 56
    .line 57
    move v7, p1

    .line 58
    goto :goto_2

    .line 59
    :cond_6
    move/from16 v7, p7

    .line 60
    .line 61
    :goto_2
    and-int/lit16 p1, v0, 0x80

    .line 62
    .line 63
    if-eqz p1, :cond_7

    .line 64
    .line 65
    iget-boolean p1, p0, Lg70/i;->h:Z

    .line 66
    .line 67
    move v8, p1

    .line 68
    goto :goto_3

    .line 69
    :cond_7
    move/from16 v8, p8

    .line 70
    .line 71
    :goto_3
    and-int/lit16 p1, v0, 0x100

    .line 72
    .line 73
    if-eqz p1, :cond_8

    .line 74
    .line 75
    iget-boolean p1, p0, Lg70/i;->i:Z

    .line 76
    .line 77
    move v9, p1

    .line 78
    goto :goto_4

    .line 79
    :cond_8
    move/from16 v9, p9

    .line 80
    .line 81
    :goto_4
    and-int/lit16 p1, v0, 0x200

    .line 82
    .line 83
    if-eqz p1, :cond_9

    .line 84
    .line 85
    iget-object p1, p0, Lg70/i;->j:Lql0/g;

    .line 86
    .line 87
    move-object v10, p1

    .line 88
    goto :goto_5

    .line 89
    :cond_9
    move-object/from16 v10, p10

    .line 90
    .line 91
    :goto_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    const-string p0, "vehicleName"

    .line 98
    .line 99
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    new-instance v0, Lg70/i;

    .line 103
    .line 104
    invoke-direct/range {v0 .. v10}, Lg70/i;-><init>(Ljava/lang/String;Ljava/lang/String;Lhp0/e;ZZZZZZLql0/g;)V

    .line 105
    .line 106
    .line 107
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
    instance-of v1, p1, Lg70/i;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    goto/16 :goto_2

    .line 11
    .line 12
    :cond_1
    check-cast p1, Lg70/i;

    .line 13
    .line 14
    iget-object v1, p0, Lg70/i;->a:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v3, p1, Lg70/i;->a:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_2

    .line 23
    .line 24
    goto :goto_2

    .line 25
    :cond_2
    iget-object v1, p1, Lg70/i;->b:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v3, p0, Lg70/i;->b:Ljava/lang/String;

    .line 28
    .line 29
    if-nez v3, :cond_4

    .line 30
    .line 31
    if-nez v1, :cond_3

    .line 32
    .line 33
    move v1, v0

    .line 34
    goto :goto_1

    .line 35
    :cond_3
    :goto_0
    move v1, v2

    .line 36
    goto :goto_1

    .line 37
    :cond_4
    if-nez v1, :cond_5

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_5
    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    :goto_1
    if-nez v1, :cond_6

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_6
    iget-object v1, p0, Lg70/i;->c:Lhp0/e;

    .line 48
    .line 49
    iget-object v3, p1, Lg70/i;->c:Lhp0/e;

    .line 50
    .line 51
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-nez v1, :cond_7

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_7
    iget-boolean v1, p0, Lg70/i;->d:Z

    .line 59
    .line 60
    iget-boolean v3, p1, Lg70/i;->d:Z

    .line 61
    .line 62
    if-eq v1, v3, :cond_8

    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_8
    iget-boolean v1, p0, Lg70/i;->e:Z

    .line 66
    .line 67
    iget-boolean v3, p1, Lg70/i;->e:Z

    .line 68
    .line 69
    if-eq v1, v3, :cond_9

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_9
    iget-boolean v1, p0, Lg70/i;->f:Z

    .line 73
    .line 74
    iget-boolean v3, p1, Lg70/i;->f:Z

    .line 75
    .line 76
    if-eq v1, v3, :cond_a

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_a
    iget-boolean v1, p0, Lg70/i;->g:Z

    .line 80
    .line 81
    iget-boolean v3, p1, Lg70/i;->g:Z

    .line 82
    .line 83
    if-eq v1, v3, :cond_b

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_b
    iget-boolean v1, p0, Lg70/i;->h:Z

    .line 87
    .line 88
    iget-boolean v3, p1, Lg70/i;->h:Z

    .line 89
    .line 90
    if-eq v1, v3, :cond_c

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_c
    iget-boolean v1, p0, Lg70/i;->i:Z

    .line 94
    .line 95
    iget-boolean v3, p1, Lg70/i;->i:Z

    .line 96
    .line 97
    if-eq v1, v3, :cond_d

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_d
    iget-object p0, p0, Lg70/i;->j:Lql0/g;

    .line 101
    .line 102
    iget-object p1, p1, Lg70/i;->j:Lql0/g;

    .line 103
    .line 104
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    if-nez p0, :cond_e

    .line 109
    .line 110
    :goto_2
    return v2

    .line 111
    :cond_e
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lg70/i;->a:Ljava/lang/String;

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
    iget-object v3, p0, Lg70/i;->b:Ljava/lang/String;

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
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

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
    iget-object v3, p0, Lg70/i;->c:Lhp0/e;

    .line 24
    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    move v3, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v3}, Lhp0/e;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    :goto_1
    add-int/2addr v0, v3

    .line 34
    mul-int/2addr v0, v1

    .line 35
    iget-boolean v3, p0, Lg70/i;->d:Z

    .line 36
    .line 37
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    iget-boolean v3, p0, Lg70/i;->e:Z

    .line 42
    .line 43
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iget-boolean v3, p0, Lg70/i;->f:Z

    .line 48
    .line 49
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-boolean v3, p0, Lg70/i;->g:Z

    .line 54
    .line 55
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    iget-boolean v3, p0, Lg70/i;->h:Z

    .line 60
    .line 61
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    iget-boolean v3, p0, Lg70/i;->i:Z

    .line 66
    .line 67
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    iget-object p0, p0, Lg70/i;->j:Lql0/g;

    .line 72
    .line 73
    if-nez p0, :cond_2

    .line 74
    .line 75
    move p0, v2

    .line 76
    goto :goto_2

    .line 77
    :cond_2
    invoke-virtual {p0}, Lql0/g;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    :goto_2
    add-int/2addr v0, p0

    .line 82
    mul-int/2addr v0, v1

    .line 83
    invoke-static {v2}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    add-int/2addr p0, v0

    .line 88
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lg70/i;->b:Ljava/lang/String;

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
    const-string v1, ", vehicleVin="

    .line 13
    .line 14
    const-string v2, ", render="

    .line 15
    .line 16
    const-string v3, "State(vehicleName="

    .line 17
    .line 18
    iget-object v4, p0, Lg70/i;->a:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {v3, v4, v1, v0, v2}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-object v1, p0, Lg70/i;->c:Lhp0/e;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v1, ", vehicleLoading="

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    iget-boolean v1, p0, Lg70/i;->d:Z

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v1, ", scanning="

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", pairingInProgress="

    .line 45
    .line 46
    const-string v2, ", showLocationPermissionDialog="

    .line 47
    .line 48
    iget-boolean v3, p0, Lg70/i;->e:Z

    .line 49
    .line 50
    iget-boolean v4, p0, Lg70/i;->f:Z

    .line 51
    .line 52
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 53
    .line 54
    .line 55
    const-string v1, ", showBluetoothPermissionDialog="

    .line 56
    .line 57
    const-string v2, ", removePairingDialogVisible="

    .line 58
    .line 59
    iget-boolean v3, p0, Lg70/i;->g:Z

    .line 60
    .line 61
    iget-boolean v4, p0, Lg70/i;->h:Z

    .line 62
    .line 63
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget-boolean v1, p0, Lg70/i;->i:Z

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v1, ", error="

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    iget-object p0, p0, Lg70/i;->j:Lql0/g;

    .line 77
    .line 78
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string p0, ", isVehiclePaired=false)"

    .line 82
    .line 83
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0
.end method

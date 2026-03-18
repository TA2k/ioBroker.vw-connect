.class public final Lhl0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Integer;

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Lhl0/a;

.field public final m:Z


# direct methods
.method public constructor <init>(ZLhl0/a;I)V
    .locals 11

    .line 1
    const v0, 0x7f120707

    .line 2
    .line 3
    .line 4
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    and-int/lit8 v1, p3, 0x1

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    :cond_0
    and-int/lit8 v1, p3, 0x2

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const/4 v3, 0x0

    .line 17
    if-eqz v1, :cond_1

    .line 18
    .line 19
    move v1, v3

    .line 20
    goto :goto_0

    .line 21
    :cond_1
    move v1, v2

    .line 22
    :goto_0
    and-int/lit8 v4, p3, 0x4

    .line 23
    .line 24
    if-eqz v4, :cond_2

    .line 25
    .line 26
    move v4, v3

    .line 27
    goto :goto_1

    .line 28
    :cond_2
    move v4, v2

    .line 29
    :goto_1
    and-int/lit8 v5, p3, 0x8

    .line 30
    .line 31
    if-eqz v5, :cond_3

    .line 32
    .line 33
    move v5, v2

    .line 34
    goto :goto_2

    .line 35
    :cond_3
    move v5, v3

    .line 36
    :goto_2
    and-int/lit8 v6, p3, 0x10

    .line 37
    .line 38
    if-eqz v6, :cond_4

    .line 39
    .line 40
    move v6, v2

    .line 41
    goto :goto_3

    .line 42
    :cond_4
    move v6, v3

    .line 43
    :goto_3
    and-int/lit8 v7, p3, 0x20

    .line 44
    .line 45
    if-eqz v7, :cond_5

    .line 46
    .line 47
    move v7, v3

    .line 48
    goto :goto_4

    .line 49
    :cond_5
    move v7, v2

    .line 50
    :goto_4
    and-int/lit8 v8, p3, 0x40

    .line 51
    .line 52
    if-eqz v8, :cond_6

    .line 53
    .line 54
    move v8, v3

    .line 55
    goto :goto_5

    .line 56
    :cond_6
    move v8, v2

    .line 57
    :goto_5
    and-int/lit16 v9, p3, 0x80

    .line 58
    .line 59
    if-eqz v9, :cond_7

    .line 60
    .line 61
    move p1, v3

    .line 62
    :cond_7
    and-int/lit16 v9, p3, 0x100

    .line 63
    .line 64
    if-eqz v9, :cond_8

    .line 65
    .line 66
    move v9, v3

    .line 67
    goto :goto_6

    .line 68
    :cond_8
    move v9, v2

    .line 69
    :goto_6
    and-int/lit16 v10, p3, 0x200

    .line 70
    .line 71
    if-eqz v10, :cond_9

    .line 72
    .line 73
    move v10, v3

    .line 74
    goto :goto_7

    .line 75
    :cond_9
    move v10, v2

    .line 76
    :goto_7
    and-int/lit16 p3, p3, 0x400

    .line 77
    .line 78
    if-eqz p3, :cond_a

    .line 79
    .line 80
    move p3, v3

    .line 81
    goto :goto_8

    .line 82
    :cond_a
    move p3, v2

    .line 83
    :goto_8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 84
    .line 85
    .line 86
    iput-object v0, p0, Lhl0/b;->a:Ljava/lang/Integer;

    .line 87
    .line 88
    iput-boolean v1, p0, Lhl0/b;->b:Z

    .line 89
    .line 90
    iput-boolean v4, p0, Lhl0/b;->c:Z

    .line 91
    .line 92
    iput-boolean v5, p0, Lhl0/b;->d:Z

    .line 93
    .line 94
    iput-boolean v6, p0, Lhl0/b;->e:Z

    .line 95
    .line 96
    iput-boolean v7, p0, Lhl0/b;->f:Z

    .line 97
    .line 98
    iput-boolean v8, p0, Lhl0/b;->g:Z

    .line 99
    .line 100
    iput-boolean p1, p0, Lhl0/b;->h:Z

    .line 101
    .line 102
    iput-boolean v9, p0, Lhl0/b;->i:Z

    .line 103
    .line 104
    iput-boolean v10, p0, Lhl0/b;->j:Z

    .line 105
    .line 106
    iput-boolean p3, p0, Lhl0/b;->k:Z

    .line 107
    .line 108
    iput-object p2, p0, Lhl0/b;->l:Lhl0/a;

    .line 109
    .line 110
    if-nez v1, :cond_c

    .line 111
    .line 112
    if-eqz v4, :cond_b

    .line 113
    .line 114
    goto :goto_9

    .line 115
    :cond_b
    move v2, v3

    .line 116
    :cond_c
    :goto_9
    iput-boolean v2, p0, Lhl0/b;->m:Z

    .line 117
    .line 118
    return-void
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
    instance-of v1, p1, Lhl0/b;

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
    check-cast p1, Lhl0/b;

    .line 12
    .line 13
    iget-object v1, p0, Lhl0/b;->a:Ljava/lang/Integer;

    .line 14
    .line 15
    iget-object v3, p1, Lhl0/b;->a:Ljava/lang/Integer;

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
    iget-boolean v1, p0, Lhl0/b;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lhl0/b;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lhl0/b;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lhl0/b;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Lhl0/b;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Lhl0/b;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Lhl0/b;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Lhl0/b;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-boolean v1, p0, Lhl0/b;->f:Z

    .line 53
    .line 54
    iget-boolean v3, p1, Lhl0/b;->f:Z

    .line 55
    .line 56
    if-eq v1, v3, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-boolean v1, p0, Lhl0/b;->g:Z

    .line 60
    .line 61
    iget-boolean v3, p1, Lhl0/b;->g:Z

    .line 62
    .line 63
    if-eq v1, v3, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-boolean v1, p0, Lhl0/b;->h:Z

    .line 67
    .line 68
    iget-boolean v3, p1, Lhl0/b;->h:Z

    .line 69
    .line 70
    if-eq v1, v3, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-boolean v1, p0, Lhl0/b;->i:Z

    .line 74
    .line 75
    iget-boolean v3, p1, Lhl0/b;->i:Z

    .line 76
    .line 77
    if-eq v1, v3, :cond_a

    .line 78
    .line 79
    return v2

    .line 80
    :cond_a
    iget-boolean v1, p0, Lhl0/b;->j:Z

    .line 81
    .line 82
    iget-boolean v3, p1, Lhl0/b;->j:Z

    .line 83
    .line 84
    if-eq v1, v3, :cond_b

    .line 85
    .line 86
    return v2

    .line 87
    :cond_b
    iget-boolean v1, p0, Lhl0/b;->k:Z

    .line 88
    .line 89
    iget-boolean v3, p1, Lhl0/b;->k:Z

    .line 90
    .line 91
    if-eq v1, v3, :cond_c

    .line 92
    .line 93
    return v2

    .line 94
    :cond_c
    iget-object p0, p0, Lhl0/b;->l:Lhl0/a;

    .line 95
    .line 96
    iget-object p1, p1, Lhl0/b;->l:Lhl0/a;

    .line 97
    .line 98
    if-eq p0, p1, :cond_d

    .line 99
    .line 100
    return v2

    .line 101
    :cond_d
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lhl0/b;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :goto_0
    const/16 v1, 0x1f

    .line 12
    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-boolean v2, p0, Lhl0/b;->b:Z

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-boolean v2, p0, Lhl0/b;->c:Z

    .line 21
    .line 22
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-boolean v2, p0, Lhl0/b;->d:Z

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-boolean v2, p0, Lhl0/b;->e:Z

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-boolean v2, p0, Lhl0/b;->f:Z

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget-boolean v2, p0, Lhl0/b;->g:Z

    .line 45
    .line 46
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget-boolean v2, p0, Lhl0/b;->h:Z

    .line 51
    .line 52
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget-boolean v2, p0, Lhl0/b;->i:Z

    .line 57
    .line 58
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget-boolean v2, p0, Lhl0/b;->j:Z

    .line 63
    .line 64
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget-boolean v2, p0, Lhl0/b;->k:Z

    .line 69
    .line 70
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget-object p0, p0, Lhl0/b;->l:Lhl0/a;

    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    add-int/2addr p0, v0

    .line 81
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MapSearchInput(searchPlaceholderResId="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lhl0/b;->a:Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", showFavouritesChips="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lhl0/b;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", showPoiCategoriesChips="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", showServicePartner="

    .line 29
    .line 30
    const-string v2, ", allowAddFavouritePlace="

    .line 31
    .line 32
    iget-boolean v3, p0, Lhl0/b;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lhl0/b;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v1, ", isVehicleLocationAvailable="

    .line 40
    .line 41
    const-string v2, ", isDeviceLocationAvailable="

    .line 42
    .line 43
    iget-boolean v3, p0, Lhl0/b;->e:Z

    .line 44
    .line 45
    iget-boolean v4, p0, Lhl0/b;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v1, ", isSelectOnMapAvailable="

    .line 51
    .line 52
    const-string v2, ", saveSearchedPlace="

    .line 53
    .line 54
    iget-boolean v3, p0, Lhl0/b;->g:Z

    .line 55
    .line 56
    iget-boolean v4, p0, Lhl0/b;->h:Z

    .line 57
    .line 58
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string v1, ", checkRouteWaypoints="

    .line 62
    .line 63
    const-string v2, ", editFavourites="

    .line 64
    .line 65
    iget-boolean v3, p0, Lhl0/b;->i:Z

    .line 66
    .line 67
    iget-boolean v4, p0, Lhl0/b;->j:Z

    .line 68
    .line 69
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-boolean v1, p0, Lhl0/b;->k:Z

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v1, ", mapSearchContext="

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Lhl0/b;->l:Lhl0/a;

    .line 83
    .line 84
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string p0, ")"

    .line 88
    .line 89
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method

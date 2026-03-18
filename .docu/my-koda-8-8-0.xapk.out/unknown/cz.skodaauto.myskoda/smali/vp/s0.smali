.class public final Lvp/s0;
.super Lvp/u3;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lvp/z3;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvp/s0;->h:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lvp/u3;-><init>(Lvp/z3;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static G0(Ljava/lang/String;)Z
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    const-string v0, "([+-])?([0-9]+\\.?[0-9]*|[0-9]*\\.?[0-9]+)"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/lang/String;->matches(Ljava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    const/16 v0, 0x136

    .line 16
    .line 17
    if-gt p0, v0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public static H0(Lcom/google/android/gms/internal/measurement/q5;I)Z
    .locals 4

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    mul-int/lit8 v0, v0, 0x40

    .line 6
    .line 7
    if-ge p1, v0, :cond_0

    .line 8
    .line 9
    div-int/lit8 v0, p1, 0x40

    .line 10
    .line 11
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/Long;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    const-wide/16 v2, 0x1

    .line 22
    .line 23
    rem-int/lit8 p1, p1, 0x40

    .line 24
    .line 25
    shl-long p0, v2, p1

    .line 26
    .line 27
    and-long/2addr p0, v0

    .line 28
    const-wide/16 v0, 0x0

    .line 29
    .line 30
    cmp-long p0, p0, v0

    .line 31
    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    const/4 p0, 0x1

    .line 35
    return p0

    .line 36
    :cond_0
    const/4 p0, 0x0

    .line 37
    return p0
.end method

.method public static I0(Ljava/util/BitSet;)Ljava/util/ArrayList;
    .locals 10

    .line 1
    invoke-virtual {p0}, Ljava/util/BitSet;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    add-int/lit8 v0, v0, 0x3f

    .line 6
    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    const/16 v2, 0x40

    .line 10
    .line 11
    div-int/2addr v0, v2

    .line 12
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 13
    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    move v4, v3

    .line 17
    :goto_0
    if-ge v4, v0, :cond_3

    .line 18
    .line 19
    const-wide/16 v5, 0x0

    .line 20
    .line 21
    move v7, v3

    .line 22
    :goto_1
    if-ge v7, v2, :cond_2

    .line 23
    .line 24
    mul-int/lit8 v8, v4, 0x40

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/util/BitSet;->length()I

    .line 27
    .line 28
    .line 29
    move-result v9

    .line 30
    add-int/2addr v8, v7

    .line 31
    if-lt v8, v9, :cond_0

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_0
    invoke-virtual {p0, v8}, Ljava/util/BitSet;->get(I)Z

    .line 35
    .line 36
    .line 37
    move-result v8

    .line 38
    if-eqz v8, :cond_1

    .line 39
    .line 40
    const-wide/16 v8, 0x1

    .line 41
    .line 42
    shl-long/2addr v8, v7

    .line 43
    or-long/2addr v5, v8

    .line 44
    :cond_1
    add-int/lit8 v7, v7, 0x1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    :goto_2
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    add-int/lit8 v4, v4, 0x1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_3
    return-object v1
.end method

.method public static N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;
    .locals 2

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/d5;->a:Lcom/google/android/gms/internal/measurement/d5;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto :goto_1

    .line 6
    :cond_0
    const-class v0, Lcom/google/android/gms/internal/measurement/d5;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    sget-object v1, Lcom/google/android/gms/internal/measurement/d5;->a:Lcom/google/android/gms/internal/measurement/d5;

    .line 10
    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    monitor-exit v0

    .line 14
    :goto_0
    move-object v0, v1

    .line 15
    goto :goto_1

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_2

    .line 18
    :cond_1
    sget-object v1, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    .line 19
    .line 20
    invoke-static {}, Lcom/google/android/gms/internal/measurement/i5;->e()Lcom/google/android/gms/internal/measurement/d5;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    sput-object v1, Lcom/google/android/gms/internal/measurement/d5;->a:Lcom/google/android/gms/internal/measurement/d5;

    .line 25
    .line 26
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    goto :goto_0

    .line 28
    :goto_1
    if-eqz v0, :cond_2

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    array-length v1, p1

    .line 34
    invoke-virtual {p0, p1, v1, v0}, Lcom/google/android/gms/internal/measurement/k5;->h([BILcom/google/android/gms/internal/measurement/d5;)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    array-length v0, p1

    .line 42
    sget-object v1, Lcom/google/android/gms/internal/measurement/d5;->a:Lcom/google/android/gms/internal/measurement/d5;

    .line 43
    .line 44
    sget-object v1, Lcom/google/android/gms/internal/measurement/k6;->c:Lcom/google/android/gms/internal/measurement/k6;

    .line 45
    .line 46
    sget-object v1, Lcom/google/android/gms/internal/measurement/d5;->b:Lcom/google/android/gms/internal/measurement/d5;

    .line 47
    .line 48
    invoke-virtual {p0, p1, v0, v1}, Lcom/google/android/gms/internal/measurement/k5;->h([BILcom/google/android/gms/internal/measurement/d5;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :goto_2
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 53
    throw p0
.end method

.method public static O0(Lcom/google/android/gms/internal/measurement/i3;Ljava/lang/String;)I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 3
    .line 4
    check-cast v1, Lcom/google/android/gms/internal/measurement/j3;

    .line 5
    .line 6
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->V1()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-ge v0, v1, :cond_1

    .line 11
    .line 12
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 13
    .line 14
    check-cast v1, Lcom/google/android/gms/internal/measurement/j3;

    .line 15
    .line 16
    invoke-virtual {v1, v0}, Lcom/google/android/gms/internal/measurement/j3;->W1(I)Lcom/google/android/gms/internal/measurement/s3;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    return v0

    .line 31
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    const/4 p0, -0x1

    .line 35
    return p0
.end method

.method public static P0(Lcom/google/android/gms/internal/measurement/r5;)[Landroid/os/Bundle;
    .locals 7

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_5

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lcom/google/android/gms/internal/measurement/e3;

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    new-instance v2, Landroid/os/Bundle;

    .line 25
    .line 26
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->z()Ljava/util/List;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    :cond_1
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_4

    .line 42
    .line 43
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    check-cast v3, Lcom/google/android/gms/internal/measurement/e3;

    .line 48
    .line 49
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->r()Z

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-eqz v4, :cond_2

    .line 54
    .line 55
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->s()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    invoke-virtual {v2, v4, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->t()Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-eqz v4, :cond_3

    .line 72
    .line 73
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->u()J

    .line 78
    .line 79
    .line 80
    move-result-wide v5

    .line 81
    invoke-virtual {v2, v4, v5, v6}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_3
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->x()Z

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    if-eqz v4, :cond_1

    .line 90
    .line 91
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/e3;->y()D

    .line 96
    .line 97
    .line 98
    move-result-wide v5

    .line 99
    invoke-virtual {v2, v4, v5, v6}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_4
    invoke-virtual {v2}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    if-nez v1, :cond_0

    .line 108
    .line 109
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    new-array p0, p0, [Landroid/os/Bundle;

    .line 118
    .line 119
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    check-cast p0, [Landroid/os/Bundle;

    .line 124
    .line 125
    return-object p0
.end method

.method public static Q0(Landroid/os/Bundle;Z)Ljava/util/HashMap;
    .locals 10

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_8

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p0, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    instance-of v4, v3, [Landroid/os/Parcelable;

    .line 31
    .line 32
    if-nez v4, :cond_2

    .line 33
    .line 34
    instance-of v5, v3, Ljava/util/ArrayList;

    .line 35
    .line 36
    if-nez v5, :cond_2

    .line 37
    .line 38
    instance-of v5, v3, Landroid/os/Bundle;

    .line 39
    .line 40
    if-eqz v5, :cond_1

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    if-eqz v3, :cond_0

    .line 44
    .line 45
    invoke-virtual {v0, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    :goto_1
    if-eqz p1, :cond_0

    .line 50
    .line 51
    new-instance v5, Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 54
    .line 55
    .line 56
    const/4 v6, 0x0

    .line 57
    if-eqz v4, :cond_4

    .line 58
    .line 59
    check-cast v3, [Landroid/os/Parcelable;

    .line 60
    .line 61
    array-length v4, v3

    .line 62
    move v7, v6

    .line 63
    :goto_2
    if-ge v7, v4, :cond_7

    .line 64
    .line 65
    aget-object v8, v3, v7

    .line 66
    .line 67
    instance-of v9, v8, Landroid/os/Bundle;

    .line 68
    .line 69
    if-eqz v9, :cond_3

    .line 70
    .line 71
    check-cast v8, Landroid/os/Bundle;

    .line 72
    .line 73
    invoke-static {v8, v6}, Lvp/s0;->Q0(Landroid/os/Bundle;Z)Ljava/util/HashMap;

    .line 74
    .line 75
    .line 76
    move-result-object v8

    .line 77
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    :cond_3
    add-int/lit8 v7, v7, 0x1

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_4
    instance-of v4, v3, Ljava/util/ArrayList;

    .line 84
    .line 85
    if-eqz v4, :cond_6

    .line 86
    .line 87
    check-cast v3, Ljava/util/ArrayList;

    .line 88
    .line 89
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    move v7, v6

    .line 94
    :goto_3
    if-ge v7, v4, :cond_7

    .line 95
    .line 96
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    instance-of v9, v8, Landroid/os/Bundle;

    .line 101
    .line 102
    if-eqz v9, :cond_5

    .line 103
    .line 104
    check-cast v8, Landroid/os/Bundle;

    .line 105
    .line 106
    invoke-static {v8, v6}, Lvp/s0;->Q0(Landroid/os/Bundle;Z)Ljava/util/HashMap;

    .line 107
    .line 108
    .line 109
    move-result-object v8

    .line 110
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    :cond_5
    add-int/lit8 v7, v7, 0x1

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_6
    instance-of v4, v3, Landroid/os/Bundle;

    .line 117
    .line 118
    if-eqz v4, :cond_7

    .line 119
    .line 120
    check-cast v3, Landroid/os/Bundle;

    .line 121
    .line 122
    invoke-static {v3, v6}, Lvp/s0;->Q0(Landroid/os/Bundle;Z)Ljava/util/HashMap;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    :cond_7
    invoke-virtual {v0, v2, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    goto :goto_0

    .line 133
    :cond_8
    return-object v0
.end method

.method public static e0(Lcom/google/android/gms/internal/measurement/b;)Lvp/t;
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/b;->c:Ljava/util/HashMap;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-static {v0, v1}, Lvp/s0;->f0(Ljava/util/Map;Z)Landroid/os/Bundle;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    const-string v1, "_o"

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    :goto_0
    move-object v5, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    const-string v1, "app"

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :goto_1
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/b;->a:Ljava/lang/String;

    .line 32
    .line 33
    sget-object v2, Lvp/t1;->a:[Ljava/lang/String;

    .line 34
    .line 35
    sget-object v3, Lvp/t1;->c:[Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {v2, v1, v3}, Lvp/t1;->g([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    if-nez v1, :cond_1

    .line 42
    .line 43
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/b;->a:Ljava/lang/String;

    .line 44
    .line 45
    :cond_1
    move-object v3, v1

    .line 46
    new-instance v2, Lvp/t;

    .line 47
    .line 48
    new-instance v4, Lvp/s;

    .line 49
    .line 50
    invoke-direct {v4, v0}, Lvp/s;-><init>(Landroid/os/Bundle;)V

    .line 51
    .line 52
    .line 53
    iget-wide v6, p0, Lcom/google/android/gms/internal/measurement/b;->b:J

    .line 54
    .line 55
    invoke-direct/range {v2 .. v7}, Lvp/t;-><init>(Ljava/lang/String;Lvp/s;Ljava/lang/String;J)V

    .line 56
    .line 57
    .line 58
    return-object v2
.end method

.method public static f0(Ljava/util/Map;Z)Landroid/os/Bundle;
    .locals 9

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_6

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ljava/lang/String;

    .line 25
    .line 26
    invoke-interface {p0, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    if-nez v3, :cond_1

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    invoke-virtual {v0, v2, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    instance-of v4, v3, Ljava/lang/Long;

    .line 38
    .line 39
    if-eqz v4, :cond_2

    .line 40
    .line 41
    check-cast v3, Ljava/lang/Long;

    .line 42
    .line 43
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 44
    .line 45
    .line 46
    move-result-wide v3

    .line 47
    invoke-virtual {v0, v2, v3, v4}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    instance-of v4, v3, Ljava/lang/Double;

    .line 52
    .line 53
    if-eqz v4, :cond_3

    .line 54
    .line 55
    check-cast v3, Ljava/lang/Double;

    .line 56
    .line 57
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 58
    .line 59
    .line 60
    move-result-wide v3

    .line 61
    invoke-virtual {v0, v2, v3, v4}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_3
    instance-of v4, v3, Ljava/util/ArrayList;

    .line 66
    .line 67
    if-eqz v4, :cond_5

    .line 68
    .line 69
    if-eqz p1, :cond_0

    .line 70
    .line 71
    check-cast v3, Ljava/util/ArrayList;

    .line 72
    .line 73
    new-instance v4, Ljava/util/ArrayList;

    .line 74
    .line 75
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 76
    .line 77
    .line 78
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    const/4 v6, 0x0

    .line 83
    move v7, v6

    .line 84
    :goto_1
    if-ge v7, v5, :cond_4

    .line 85
    .line 86
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v8

    .line 90
    check-cast v8, Ljava/util/Map;

    .line 91
    .line 92
    invoke-static {v8, v6}, Lvp/s0;->f0(Ljava/util/Map;Z)Landroid/os/Bundle;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    add-int/lit8 v7, v7, 0x1

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_4
    new-array v3, v6, [Landroid/os/Parcelable;

    .line 103
    .line 104
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    check-cast v3, [Landroid/os/Parcelable;

    .line 109
    .line 110
    invoke-virtual {v0, v2, v3}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 111
    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_5
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    invoke-virtual {v0, v2, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_6
    return-object v0
.end method

.method public static final g0(Lcom/google/android/gms/internal/measurement/a3;Ljava/lang/String;Ljava/lang/Long;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/a3;->i()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    if-ge v1, v2, :cond_1

    .line 11
    .line 12
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    check-cast v2, Lcom/google/android/gms/internal/measurement/e3;

    .line 17
    .line 18
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-virtual {p1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    const/4 v1, -0x1

    .line 33
    :goto_1
    invoke-static {}, Lcom/google/android/gms/internal/measurement/e3;->B()Lcom/google/android/gms/internal/measurement/d3;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-virtual {v0, p1}, Lcom/google/android/gms/internal/measurement/d3;->i(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 41
    .line 42
    .line 43
    move-result-wide p1

    .line 44
    invoke-virtual {v0, p1, p2}, Lcom/google/android/gms/internal/measurement/d3;->k(J)V

    .line 45
    .line 46
    .line 47
    if-ltz v1, :cond_2

    .line 48
    .line 49
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 50
    .line 51
    .line 52
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 53
    .line 54
    check-cast p0, Lcom/google/android/gms/internal/measurement/b3;

    .line 55
    .line 56
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    check-cast p1, Lcom/google/android/gms/internal/measurement/e3;

    .line 61
    .line 62
    invoke-virtual {p0, v1, p1}, Lcom/google/android/gms/internal/measurement/b3;->A(ILcom/google/android/gms/internal/measurement/e3;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_2
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/a3;->m(Lcom/google/android/gms/internal/measurement/d3;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public static final h0(Ljava/util/List;)Landroid/os/Bundle;
    .locals 5

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_4

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lcom/google/android/gms/internal/measurement/e3;

    .line 21
    .line 22
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->x()Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_1

    .line 31
    .line 32
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->y()D

    .line 33
    .line 34
    .line 35
    move-result-wide v3

    .line 36
    invoke-virtual {v0, v2, v3, v4}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->v()Z

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    if-eqz v3, :cond_2

    .line 45
    .line 46
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->w()F

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    invoke-virtual {v0, v2, v1}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->r()Z

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    if-eqz v3, :cond_3

    .line 59
    .line 60
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->s()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_3
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->t()Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    if-eqz v3, :cond_0

    .line 73
    .line 74
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/e3;->u()J

    .line 75
    .line 76
    .line 77
    move-result-wide v3

    .line 78
    invoke-virtual {v0, v2, v3, v4}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_4
    return-object v0
.end method

.method public static final i0(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/e3;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/b3;->p()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lcom/google/android/gms/internal/measurement/e3;

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v1, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    return-object v0

    .line 32
    :cond_1
    const/4 p0, 0x0

    .line 33
    return-object p0
.end method

.method public static final j0(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Ljava/io/Serializable;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lvp/s0;->i0(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/e3;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-static {p0}, Lvp/s0;->p0(Lcom/google/android/gms/internal/measurement/e3;)Ljava/io/Serializable;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/io/Serializable;

    .line 14
    .line 15
    return-object p0
.end method

.method public static final m0(ILjava/lang/StringBuilder;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    if-ge v0, p0, :cond_0

    .line 3
    .line 4
    const-string v1, "  "

    .line 5
    .line 6
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 7
    .line 8
    .line 9
    add-int/lit8 v0, v0, 0x1

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-void
.end method

.method public static final n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V
    .locals 0

    .line 1
    invoke-interface {p3, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    if-nez p3, :cond_1

    .line 6
    .line 7
    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 8
    .line 9
    .line 10
    move-result p3

    .line 11
    if-eqz p3, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p0, p1, p2}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 15
    .line 16
    .line 17
    :cond_1
    :goto_0
    return-void
.end method

.method public static final o0(ZZZ)Ljava/lang/String;
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    const-string p0, "Dynamic "

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    :cond_0
    if-eqz p1, :cond_1

    .line 14
    .line 15
    const-string p0, "Sequence "

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    :cond_1
    if-eqz p2, :cond_2

    .line 21
    .line 22
    const-string p0, "Session-Scoped "

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    :cond_2
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

.method public static final p0(Lcom/google/android/gms/internal/measurement/e3;)Ljava/io/Serializable;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e3;->r()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e3;->s()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e3;->t()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e3;->u()J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e3;->x()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e3;->y()D

    .line 34
    .line 35
    .line 36
    move-result-wide v0

    .line 37
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :cond_2
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e3;->A()I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-lez v0, :cond_3

    .line 47
    .line 48
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/e3;->z()Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    check-cast p0, Lcom/google/android/gms/internal/measurement/r5;

    .line 53
    .line 54
    invoke-static {p0}, Lvp/s0;->P0(Lcom/google/android/gms/internal/measurement/r5;)[Landroid/os/Bundle;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :cond_3
    const/4 p0, 0x0

    .line 60
    return-object p0
.end method

.method public static final q0(Landroid/net/Uri$Builder;[Ljava/lang/String;Landroid/os/Bundle;Ljava/util/Set;)V
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    array-length v2, p1

    .line 4
    if-ge v1, v2, :cond_1

    .line 5
    .line 6
    aget-object v2, p1, v1

    .line 7
    .line 8
    const-string v3, ","

    .line 9
    .line 10
    invoke-virtual {v2, v3}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    aget-object v3, v2, v0

    .line 15
    .line 16
    array-length v4, v2

    .line 17
    add-int/lit8 v4, v4, -0x1

    .line 18
    .line 19
    aget-object v2, v2, v4

    .line 20
    .line 21
    invoke-virtual {p2, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    if-eqz v3, :cond_0

    .line 26
    .line 27
    invoke-static {p0, v2, v3, p3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    return-void
.end method

.method public static final r0(Ljava/lang/StringBuilder;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m3;)V
    .locals 10

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    const/4 v0, 0x3

    .line 5
    invoke-static {v0, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p1, " {\n"

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/m3;->s()I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    const/16 v1, 0xa

    .line 21
    .line 22
    const/4 v2, 0x4

    .line 23
    const-string v3, ", "

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    if-eqz p1, :cond_3

    .line 27
    .line 28
    invoke-static {v2, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 29
    .line 30
    .line 31
    const-string p1, "results: "

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/m3;->r()Ljava/util/List;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    move v5, v4

    .line 45
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    if-eqz v6, :cond_2

    .line 50
    .line 51
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    check-cast v6, Ljava/lang/Long;

    .line 56
    .line 57
    add-int/lit8 v7, v5, 0x1

    .line 58
    .line 59
    if-eqz v5, :cond_1

    .line 60
    .line 61
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    :cond_1
    invoke-virtual {p0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    move v5, v7

    .line 68
    goto :goto_0

    .line 69
    :cond_2
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    :cond_3
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/m3;->q()I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-eqz p1, :cond_6

    .line 77
    .line 78
    invoke-static {v2, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 79
    .line 80
    .line 81
    const-string p1, "status: "

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/m3;->p()Ljava/util/List;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    move v5, v4

    .line 95
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v6

    .line 99
    if-eqz v6, :cond_5

    .line 100
    .line 101
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    check-cast v6, Ljava/lang/Long;

    .line 106
    .line 107
    add-int/lit8 v7, v5, 0x1

    .line 108
    .line 109
    if-eqz v5, :cond_4

    .line 110
    .line 111
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    :cond_4
    invoke-virtual {p0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    move v5, v7

    .line 118
    goto :goto_1

    .line 119
    :cond_5
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    :cond_6
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/m3;->u()I

    .line 123
    .line 124
    .line 125
    move-result p1

    .line 126
    const-string v1, "}\n"

    .line 127
    .line 128
    const/4 v5, 0x0

    .line 129
    if-eqz p1, :cond_b

    .line 130
    .line 131
    invoke-static {v2, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 132
    .line 133
    .line 134
    const-string p1, "dynamic_filter_timestamps: {"

    .line 135
    .line 136
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/m3;->t()Lcom/google/android/gms/internal/measurement/r5;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    move v6, v4

    .line 148
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 149
    .line 150
    .line 151
    move-result v7

    .line 152
    if-eqz v7, :cond_a

    .line 153
    .line 154
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    check-cast v7, Lcom/google/android/gms/internal/measurement/z2;

    .line 159
    .line 160
    add-int/lit8 v8, v6, 0x1

    .line 161
    .line 162
    if-eqz v6, :cond_7

    .line 163
    .line 164
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    :cond_7
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/z2;->p()Z

    .line 168
    .line 169
    .line 170
    move-result v6

    .line 171
    if-eqz v6, :cond_8

    .line 172
    .line 173
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/z2;->q()I

    .line 174
    .line 175
    .line 176
    move-result v6

    .line 177
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 178
    .line 179
    .line 180
    move-result-object v6

    .line 181
    goto :goto_3

    .line 182
    :cond_8
    move-object v6, v5

    .line 183
    :goto_3
    invoke-virtual {p0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    const-string v6, ":"

    .line 187
    .line 188
    invoke-virtual {p0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/z2;->r()Z

    .line 192
    .line 193
    .line 194
    move-result v6

    .line 195
    if-eqz v6, :cond_9

    .line 196
    .line 197
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/z2;->s()J

    .line 198
    .line 199
    .line 200
    move-result-wide v6

    .line 201
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 202
    .line 203
    .line 204
    move-result-object v6

    .line 205
    goto :goto_4

    .line 206
    :cond_9
    move-object v6, v5

    .line 207
    :goto_4
    invoke-virtual {p0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    move v6, v8

    .line 211
    goto :goto_2

    .line 212
    :cond_a
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    :cond_b
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/m3;->w()I

    .line 216
    .line 217
    .line 218
    move-result p1

    .line 219
    if-eqz p1, :cond_11

    .line 220
    .line 221
    invoke-static {v2, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 222
    .line 223
    .line 224
    const-string p1, "sequence_filter_timestamps: {"

    .line 225
    .line 226
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 227
    .line 228
    .line 229
    invoke-virtual {p2}, Lcom/google/android/gms/internal/measurement/m3;->v()Ljava/util/List;

    .line 230
    .line 231
    .line 232
    move-result-object p1

    .line 233
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    move p2, v4

    .line 238
    :goto_5
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 239
    .line 240
    .line 241
    move-result v2

    .line 242
    if-eqz v2, :cond_10

    .line 243
    .line 244
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v2

    .line 248
    check-cast v2, Lcom/google/android/gms/internal/measurement/o3;

    .line 249
    .line 250
    add-int/lit8 v6, p2, 0x1

    .line 251
    .line 252
    if-eqz p2, :cond_c

    .line 253
    .line 254
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    :cond_c
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/o3;->p()Z

    .line 258
    .line 259
    .line 260
    move-result p2

    .line 261
    if-eqz p2, :cond_d

    .line 262
    .line 263
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/o3;->q()I

    .line 264
    .line 265
    .line 266
    move-result p2

    .line 267
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 268
    .line 269
    .line 270
    move-result-object p2

    .line 271
    goto :goto_6

    .line 272
    :cond_d
    move-object p2, v5

    .line 273
    :goto_6
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 274
    .line 275
    .line 276
    const-string p2, ": ["

    .line 277
    .line 278
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 279
    .line 280
    .line 281
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/o3;->r()Ljava/util/List;

    .line 282
    .line 283
    .line 284
    move-result-object p2

    .line 285
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 286
    .line 287
    .line 288
    move-result-object p2

    .line 289
    move v2, v4

    .line 290
    :goto_7
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 291
    .line 292
    .line 293
    move-result v7

    .line 294
    if-eqz v7, :cond_f

    .line 295
    .line 296
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v7

    .line 300
    check-cast v7, Ljava/lang/Long;

    .line 301
    .line 302
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 303
    .line 304
    .line 305
    move-result-wide v7

    .line 306
    add-int/lit8 v9, v2, 0x1

    .line 307
    .line 308
    if-eqz v2, :cond_e

    .line 309
    .line 310
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 311
    .line 312
    .line 313
    :cond_e
    invoke-virtual {p0, v7, v8}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 314
    .line 315
    .line 316
    move v2, v9

    .line 317
    goto :goto_7

    .line 318
    :cond_f
    const-string p2, "]"

    .line 319
    .line 320
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 321
    .line 322
    .line 323
    move p2, v6

    .line 324
    goto :goto_5

    .line 325
    :cond_10
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 326
    .line 327
    .line 328
    :cond_11
    invoke-static {v0, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 332
    .line 333
    .line 334
    return-void
.end method

.method public static final s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V
    .locals 0

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    add-int/lit8 p1, p1, 0x1

    .line 5
    .line 6
    invoke-static {p1, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    const-string p1, ": "

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const/16 p1, 0xa

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public static final t0(Ljava/lang/StringBuilder;ILjava/lang/String;Lcom/google/android/gms/internal/measurement/t1;)V
    .locals 1

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p1, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 8
    .line 9
    .line 10
    const-string p2, " {\n"

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->p()Z

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    if-eqz p2, :cond_5

    .line 20
    .line 21
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->z()I

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    const/4 v0, 0x1

    .line 26
    if-eq p2, v0, :cond_4

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    if-eq p2, v0, :cond_3

    .line 30
    .line 31
    const/4 v0, 0x3

    .line 32
    if-eq p2, v0, :cond_2

    .line 33
    .line 34
    const/4 v0, 0x4

    .line 35
    if-eq p2, v0, :cond_1

    .line 36
    .line 37
    const-string p2, "BETWEEN"

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const-string p2, "EQUAL"

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    const-string p2, "GREATER_THAN"

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_3
    const-string p2, "LESS_THAN"

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_4
    const-string p2, "UNKNOWN_COMPARISON_TYPE"

    .line 50
    .line 51
    :goto_0
    const-string v0, "comparison_type"

    .line 52
    .line 53
    invoke-static {p0, p1, v0, p2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_5
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->q()Z

    .line 57
    .line 58
    .line 59
    move-result p2

    .line 60
    if-eqz p2, :cond_6

    .line 61
    .line 62
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->r()Z

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    const-string v0, "match_as_float"

    .line 71
    .line 72
    invoke-static {p0, p1, v0, p2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    :cond_6
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->s()Z

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    if-eqz p2, :cond_7

    .line 80
    .line 81
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->t()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    const-string v0, "comparison_value"

    .line 86
    .line 87
    invoke-static {p0, p1, v0, p2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_7
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->u()Z

    .line 91
    .line 92
    .line 93
    move-result p2

    .line 94
    if-eqz p2, :cond_8

    .line 95
    .line 96
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->v()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    const-string v0, "min_comparison_value"

    .line 101
    .line 102
    invoke-static {p0, p1, v0, p2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    :cond_8
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->w()Z

    .line 106
    .line 107
    .line 108
    move-result p2

    .line 109
    if-eqz p2, :cond_9

    .line 110
    .line 111
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t1;->x()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    const-string p3, "max_comparison_value"

    .line 116
    .line 117
    invoke-static {p0, p1, p3, p2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_9
    invoke-static {p1, p0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 121
    .line 122
    .line 123
    const-string p1, "}\n"

    .line 124
    .line 125
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    return-void
.end method

.method private final v0()V
    .locals 0

    .line 1
    return-void
.end method

.method private final w0()V
    .locals 0

    .line 1
    return-void
.end method

.method private final x0()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public A0(Lcom/google/android/gms/internal/measurement/d3;Ljava/lang/Object;)V
    .locals 9

    .line 1
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 5
    .line 6
    check-cast v0, Lcom/google/android/gms/internal/measurement/e3;

    .line 7
    .line 8
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->E()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 15
    .line 16
    check-cast v0, Lcom/google/android/gms/internal/measurement/e3;

    .line 17
    .line 18
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->G()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 22
    .line 23
    .line 24
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 25
    .line 26
    check-cast v0, Lcom/google/android/gms/internal/measurement/e3;

    .line 27
    .line 28
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->I()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 32
    .line 33
    .line 34
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 35
    .line 36
    check-cast v0, Lcom/google/android/gms/internal/measurement/e3;

    .line 37
    .line 38
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->L()V

    .line 39
    .line 40
    .line 41
    instance-of v0, p2, Ljava/lang/String;

    .line 42
    .line 43
    if-eqz v0, :cond_0

    .line 44
    .line 45
    check-cast p2, Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {p1, p2}, Lcom/google/android/gms/internal/measurement/d3;->j(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_0
    instance-of v0, p2, Ljava/lang/Long;

    .line 52
    .line 53
    if-eqz v0, :cond_1

    .line 54
    .line 55
    check-cast p2, Ljava/lang/Long;

    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 58
    .line 59
    .line 60
    move-result-wide v0

    .line 61
    invoke-virtual {p1, v0, v1}, Lcom/google/android/gms/internal/measurement/d3;->k(J)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_1
    instance-of v0, p2, Ljava/lang/Double;

    .line 66
    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    check-cast p2, Ljava/lang/Double;

    .line 70
    .line 71
    invoke-virtual {p2}, Ljava/lang/Double;->doubleValue()D

    .line 72
    .line 73
    .line 74
    move-result-wide v0

    .line 75
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 76
    .line 77
    .line 78
    iget-object p0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 79
    .line 80
    check-cast p0, Lcom/google/android/gms/internal/measurement/e3;

    .line 81
    .line 82
    invoke-virtual {p0, v0, v1}, Lcom/google/android/gms/internal/measurement/e3;->H(D)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_2
    instance-of v0, p2, [Landroid/os/Bundle;

    .line 87
    .line 88
    if-eqz v0, :cond_a

    .line 89
    .line 90
    check-cast p2, [Landroid/os/Bundle;

    .line 91
    .line 92
    new-instance p0, Ljava/util/ArrayList;

    .line 93
    .line 94
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 95
    .line 96
    .line 97
    array-length v0, p2

    .line 98
    const/4 v1, 0x0

    .line 99
    :goto_0
    if-ge v1, v0, :cond_9

    .line 100
    .line 101
    aget-object v2, p2, v1

    .line 102
    .line 103
    if-nez v2, :cond_3

    .line 104
    .line 105
    goto/16 :goto_3

    .line 106
    .line 107
    :cond_3
    invoke-static {}, Lcom/google/android/gms/internal/measurement/e3;->B()Lcom/google/android/gms/internal/measurement/d3;

    .line 108
    .line 109
    .line 110
    move-result-object v3

    .line 111
    invoke-virtual {v2}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    :cond_4
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 120
    .line 121
    .line 122
    move-result v5

    .line 123
    if-eqz v5, :cond_7

    .line 124
    .line 125
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v5

    .line 129
    check-cast v5, Ljava/lang/String;

    .line 130
    .line 131
    invoke-static {}, Lcom/google/android/gms/internal/measurement/e3;->B()Lcom/google/android/gms/internal/measurement/d3;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    invoke-virtual {v6, v5}, Lcom/google/android/gms/internal/measurement/d3;->i(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v2, v5}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v5

    .line 142
    instance-of v7, v5, Ljava/lang/Long;

    .line 143
    .line 144
    if-eqz v7, :cond_5

    .line 145
    .line 146
    check-cast v5, Ljava/lang/Long;

    .line 147
    .line 148
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 149
    .line 150
    .line 151
    move-result-wide v7

    .line 152
    invoke-virtual {v6, v7, v8}, Lcom/google/android/gms/internal/measurement/d3;->k(J)V

    .line 153
    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_5
    instance-of v7, v5, Ljava/lang/String;

    .line 157
    .line 158
    if-eqz v7, :cond_6

    .line 159
    .line 160
    check-cast v5, Ljava/lang/String;

    .line 161
    .line 162
    invoke-virtual {v6, v5}, Lcom/google/android/gms/internal/measurement/d3;->j(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    goto :goto_2

    .line 166
    :cond_6
    instance-of v7, v5, Ljava/lang/Double;

    .line 167
    .line 168
    if-eqz v7, :cond_4

    .line 169
    .line 170
    check-cast v5, Ljava/lang/Double;

    .line 171
    .line 172
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 173
    .line 174
    .line 175
    move-result-wide v7

    .line 176
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 177
    .line 178
    .line 179
    iget-object v5, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 180
    .line 181
    check-cast v5, Lcom/google/android/gms/internal/measurement/e3;

    .line 182
    .line 183
    invoke-virtual {v5, v7, v8}, Lcom/google/android/gms/internal/measurement/e3;->H(D)V

    .line 184
    .line 185
    .line 186
    :goto_2
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 187
    .line 188
    .line 189
    iget-object v5, v3, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 190
    .line 191
    check-cast v5, Lcom/google/android/gms/internal/measurement/e3;

    .line 192
    .line 193
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 194
    .line 195
    .line 196
    move-result-object v6

    .line 197
    check-cast v6, Lcom/google/android/gms/internal/measurement/e3;

    .line 198
    .line 199
    invoke-virtual {v5, v6}, Lcom/google/android/gms/internal/measurement/e3;->J(Lcom/google/android/gms/internal/measurement/e3;)V

    .line 200
    .line 201
    .line 202
    goto :goto_1

    .line 203
    :cond_7
    iget-object v2, v3, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 204
    .line 205
    check-cast v2, Lcom/google/android/gms/internal/measurement/e3;

    .line 206
    .line 207
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/e3;->A()I

    .line 208
    .line 209
    .line 210
    move-result v2

    .line 211
    if-lez v2, :cond_8

    .line 212
    .line 213
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 214
    .line 215
    .line 216
    move-result-object v2

    .line 217
    check-cast v2, Lcom/google/android/gms/internal/measurement/e3;

    .line 218
    .line 219
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    :cond_8
    :goto_3
    add-int/lit8 v1, v1, 0x1

    .line 223
    .line 224
    goto :goto_0

    .line 225
    :cond_9
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 226
    .line 227
    .line 228
    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 229
    .line 230
    check-cast p1, Lcom/google/android/gms/internal/measurement/e3;

    .line 231
    .line 232
    invoke-virtual {p1, p0}, Lcom/google/android/gms/internal/measurement/e3;->K(Ljava/util/ArrayList;)V

    .line 233
    .line 234
    .line 235
    return-void

    .line 236
    :cond_a
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 237
    .line 238
    check-cast p0, Lvp/g1;

    .line 239
    .line 240
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 241
    .line 242
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 243
    .line 244
    .line 245
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 246
    .line 247
    const-string p1, "Ignoring invalid (type) event param value"

    .line 248
    .line 249
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    return-void
.end method

.method public B0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/i3;Lcom/google/android/gms/internal/measurement/a3;Ljava/lang/String;)Lvp/o3;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 8
    .line 9
    .line 10
    iget-object v3, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v3, Lvp/g1;

    .line 13
    .line 14
    iget-object v4, v3, Lvp/g1;->g:Lvp/h;

    .line 15
    .line 16
    sget-object v5, Lvp/z;->P0:Lvp/y;

    .line 17
    .line 18
    invoke-virtual {v4, v1, v5}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    if-eqz v5, :cond_1b

    .line 23
    .line 24
    iget-object v3, v3, Lvp/g1;->n:Lto/a;

    .line 25
    .line 26
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 30
    .line 31
    .line 32
    move-result-wide v5

    .line 33
    sget-object v3, Lvp/z;->u0:Lvp/y;

    .line 34
    .line 35
    invoke-virtual {v4, v1, v3}, Lvp/h;->g0(Ljava/lang/String;Lvp/y;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    const-string v7, ","

    .line 40
    .line 41
    invoke-virtual {v3, v7}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    new-instance v7, Ljava/util/HashSet;

    .line 46
    .line 47
    array-length v8, v3

    .line 48
    invoke-direct {v7, v8}, Ljava/util/HashSet;-><init>(I)V

    .line 49
    .line 50
    .line 51
    array-length v8, v3

    .line 52
    const/4 v10, 0x0

    .line 53
    :goto_0
    if-ge v10, v8, :cond_1

    .line 54
    .line 55
    aget-object v11, v3, v10

    .line 56
    .line 57
    invoke-static {v11}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v7, v11}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v12

    .line 64
    if-eqz v12, :cond_0

    .line 65
    .line 66
    add-int/lit8 v10, v10, 0x1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 70
    .line 71
    new-instance v1, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    const-string v2, "duplicate element: "

    .line 74
    .line 75
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw v0

    .line 89
    :cond_1
    invoke-static {v7}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    iget-object v0, v0, Lvp/q3;->f:Lvp/z3;

    .line 94
    .line 95
    iget-object v7, v0, Lvp/z3;->m:Lvp/w3;

    .line 96
    .line 97
    iget-object v0, v0, Lvp/z3;->d:Lvp/a1;

    .line 98
    .line 99
    iget-object v8, v7, Lvp/q3;->f:Lvp/z3;

    .line 100
    .line 101
    iget-object v8, v8, Lvp/z3;->d:Lvp/a1;

    .line 102
    .line 103
    invoke-static {v8}, Lvp/z3;->T(Lvp/u3;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v8, v1}, Lvp/a1;->n0(Ljava/lang/String;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v8

    .line 110
    new-instance v10, Landroid/net/Uri$Builder;

    .line 111
    .line 112
    invoke-direct {v10}, Landroid/net/Uri$Builder;-><init>()V

    .line 113
    .line 114
    .line 115
    iget-object v7, v7, Lap0/o;->e:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v7, Lvp/g1;

    .line 118
    .line 119
    iget-object v7, v7, Lvp/g1;->g:Lvp/h;

    .line 120
    .line 121
    sget-object v11, Lvp/z;->n0:Lvp/y;

    .line 122
    .line 123
    invoke-virtual {v7, v1, v11}, Lvp/h;->g0(Ljava/lang/String;Lvp/y;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v11

    .line 127
    invoke-virtual {v10, v11}, Landroid/net/Uri$Builder;->scheme(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 128
    .line 129
    .line 130
    invoke-static {v8}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 131
    .line 132
    .line 133
    move-result v11

    .line 134
    const-string v12, "."

    .line 135
    .line 136
    const/4 v13, 0x1

    .line 137
    if-nez v11, :cond_2

    .line 138
    .line 139
    sget-object v11, Lvp/z;->o0:Lvp/y;

    .line 140
    .line 141
    invoke-virtual {v7, v1, v11}, Lvp/h;->g0(Ljava/lang/String;Lvp/y;)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v11

    .line 145
    invoke-static {v8}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v14

    .line 149
    invoke-virtual {v14}, Ljava/lang/String;->length()I

    .line 150
    .line 151
    .line 152
    move-result v14

    .line 153
    add-int/2addr v14, v13

    .line 154
    invoke-static {v11}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v15

    .line 158
    invoke-virtual {v15}, Ljava/lang/String;->length()I

    .line 159
    .line 160
    .line 161
    move-result v15

    .line 162
    new-instance v9, Ljava/lang/StringBuilder;

    .line 163
    .line 164
    add-int/2addr v14, v15

    .line 165
    invoke-direct {v9, v14}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v9, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    invoke-virtual {v9, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v8

    .line 181
    invoke-virtual {v10, v8}, Landroid/net/Uri$Builder;->authority(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 182
    .line 183
    .line 184
    goto :goto_1

    .line 185
    :cond_2
    sget-object v8, Lvp/z;->o0:Lvp/y;

    .line 186
    .line 187
    invoke-virtual {v7, v1, v8}, Lvp/h;->g0(Ljava/lang/String;Lvp/y;)Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v8

    .line 191
    invoke-virtual {v10, v8}, Landroid/net/Uri$Builder;->authority(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 192
    .line 193
    .line 194
    :goto_1
    sget-object v8, Lvp/z;->p0:Lvp/y;

    .line 195
    .line 196
    invoke-virtual {v7, v1, v8}, Lvp/h;->g0(Ljava/lang/String;Lvp/y;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v7

    .line 200
    invoke-virtual {v10, v7}, Landroid/net/Uri$Builder;->path(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 201
    .line 202
    .line 203
    iget-object v7, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 204
    .line 205
    check-cast v7, Lcom/google/android/gms/internal/measurement/j3;

    .line 206
    .line 207
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/j3;->E()Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v7

    .line 211
    const-string v8, "gmp_app_id"

    .line 212
    .line 213
    invoke-static {v10, v8, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v4}, Lvp/h;->f0()V

    .line 217
    .line 218
    .line 219
    const-wide/32 v7, 0x2078d

    .line 220
    .line 221
    .line 222
    invoke-static {v7, v8}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v7

    .line 226
    const-string v8, "gmp_version"

    .line 227
    .line 228
    invoke-static {v10, v8, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 229
    .line 230
    .line 231
    iget-object v7, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 232
    .line 233
    check-cast v7, Lcom/google/android/gms/internal/measurement/j3;

    .line 234
    .line 235
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/j3;->y()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v7

    .line 239
    sget-object v8, Lvp/z;->S0:Lvp/y;

    .line 240
    .line 241
    invoke-virtual {v4, v1, v8}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 242
    .line 243
    .line 244
    move-result v9

    .line 245
    if-eqz v9, :cond_3

    .line 246
    .line 247
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v0, v1}, Lvp/a1;->t0(Ljava/lang/String;)Z

    .line 251
    .line 252
    .line 253
    move-result v9

    .line 254
    if-eqz v9, :cond_3

    .line 255
    .line 256
    const-string v7, ""

    .line 257
    .line 258
    :cond_3
    const-string v9, "app_instance_id"

    .line 259
    .line 260
    invoke-static {v10, v9, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 261
    .line 262
    .line 263
    iget-object v7, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 264
    .line 265
    check-cast v7, Lcom/google/android/gms/internal/measurement/j3;

    .line 266
    .line 267
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/j3;->v()Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object v7

    .line 271
    const-string v9, "rdid"

    .line 272
    .line 273
    invoke-static {v10, v9, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/i3;->p()Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v7

    .line 280
    const-string v9, "bundle_id"

    .line 281
    .line 282
    invoke-static {v10, v9, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 283
    .line 284
    .line 285
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/a3;->o()Ljava/lang/String;

    .line 286
    .line 287
    .line 288
    move-result-object v7

    .line 289
    sget-object v9, Lvp/t1;->c:[Ljava/lang/String;

    .line 290
    .line 291
    sget-object v11, Lvp/t1;->a:[Ljava/lang/String;

    .line 292
    .line 293
    invoke-static {v9, v7, v11}, Lvp/t1;->g([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object v9

    .line 297
    invoke-static {v9}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 298
    .line 299
    .line 300
    move-result v11

    .line 301
    if-eq v13, v11, :cond_4

    .line 302
    .line 303
    move-object v7, v9

    .line 304
    :cond_4
    const-string v9, "app_event_name"

    .line 305
    .line 306
    invoke-static {v10, v9, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 307
    .line 308
    .line 309
    iget-object v7, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 310
    .line 311
    check-cast v7, Lcom/google/android/gms/internal/measurement/j3;

    .line 312
    .line 313
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/j3;->K()I

    .line 314
    .line 315
    .line 316
    move-result v7

    .line 317
    invoke-static {v7}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 318
    .line 319
    .line 320
    move-result-object v7

    .line 321
    const-string v9, "app_version"

    .line 322
    .line 323
    invoke-static {v10, v9, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 324
    .line 325
    .line 326
    iget-object v7, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 327
    .line 328
    check-cast v7, Lcom/google/android/gms/internal/measurement/j3;

    .line 329
    .line 330
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/j3;->i2()Ljava/lang/String;

    .line 331
    .line 332
    .line 333
    move-result-object v7

    .line 334
    invoke-virtual {v4, v1, v8}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 335
    .line 336
    .line 337
    move-result v8

    .line 338
    if-eqz v8, :cond_5

    .line 339
    .line 340
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 341
    .line 342
    .line 343
    invoke-virtual {v0, v1}, Lvp/a1;->s0(Ljava/lang/String;)Z

    .line 344
    .line 345
    .line 346
    move-result v0

    .line 347
    if-eqz v0, :cond_5

    .line 348
    .line 349
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 350
    .line 351
    .line 352
    move-result v0

    .line 353
    if-nez v0, :cond_5

    .line 354
    .line 355
    invoke-virtual {v7, v12}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    .line 356
    .line 357
    .line 358
    move-result v0

    .line 359
    const/4 v8, -0x1

    .line 360
    if-eq v0, v8, :cond_5

    .line 361
    .line 362
    const/4 v8, 0x0

    .line 363
    invoke-virtual {v7, v8, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v7

    .line 367
    :cond_5
    const-string v0, "os_version"

    .line 368
    .line 369
    invoke-static {v10, v0, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 370
    .line 371
    .line 372
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/a3;->p()J

    .line 373
    .line 374
    .line 375
    move-result-wide v7

    .line 376
    invoke-static {v7, v8}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    const-string v7, "timestamp"

    .line 381
    .line 382
    invoke-static {v10, v7, v0, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 383
    .line 384
    .line 385
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 386
    .line 387
    check-cast v0, Lcom/google/android/gms/internal/measurement/j3;

    .line 388
    .line 389
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/j3;->x()Z

    .line 390
    .line 391
    .line 392
    move-result v0

    .line 393
    const-string v7, "1"

    .line 394
    .line 395
    if-eqz v0, :cond_6

    .line 396
    .line 397
    const-string v0, "lat"

    .line 398
    .line 399
    invoke-static {v10, v0, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 400
    .line 401
    .line 402
    :cond_6
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 403
    .line 404
    check-cast v0, Lcom/google/android/gms/internal/measurement/j3;

    .line 405
    .line 406
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/j3;->G0()I

    .line 407
    .line 408
    .line 409
    move-result v0

    .line 410
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    const-string v8, "privacy_sandbox_version"

    .line 415
    .line 416
    invoke-static {v10, v8, v0, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 417
    .line 418
    .line 419
    const-string v0, "trigger_uri_source"

    .line 420
    .line 421
    invoke-static {v10, v0, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 422
    .line 423
    .line 424
    invoke-static {v5, v6}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 425
    .line 426
    .line 427
    move-result-object v0

    .line 428
    const-string v8, "trigger_uri_timestamp"

    .line 429
    .line 430
    invoke-static {v10, v8, v0, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 431
    .line 432
    .line 433
    const-string v0, "request_uuid"

    .line 434
    .line 435
    move-object/from16 v8, p4

    .line 436
    .line 437
    invoke-static {v10, v0, v8, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 438
    .line 439
    .line 440
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/a3;->i()Ljava/util/List;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    new-instance v8, Landroid/os/Bundle;

    .line 445
    .line 446
    invoke-direct {v8}, Landroid/os/Bundle;-><init>()V

    .line 447
    .line 448
    .line 449
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 450
    .line 451
    .line 452
    move-result-object v0

    .line 453
    :cond_7
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 454
    .line 455
    .line 456
    move-result v9

    .line 457
    if-eqz v9, :cond_b

    .line 458
    .line 459
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v9

    .line 463
    check-cast v9, Lcom/google/android/gms/internal/measurement/e3;

    .line 464
    .line 465
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 466
    .line 467
    .line 468
    move-result-object v11

    .line 469
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->x()Z

    .line 470
    .line 471
    .line 472
    move-result v12

    .line 473
    if-eqz v12, :cond_8

    .line 474
    .line 475
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->y()D

    .line 476
    .line 477
    .line 478
    move-result-wide v14

    .line 479
    invoke-static {v14, v15}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 480
    .line 481
    .line 482
    move-result-object v9

    .line 483
    invoke-virtual {v8, v11, v9}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    goto :goto_2

    .line 487
    :cond_8
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->v()Z

    .line 488
    .line 489
    .line 490
    move-result v12

    .line 491
    if-eqz v12, :cond_9

    .line 492
    .line 493
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->w()F

    .line 494
    .line 495
    .line 496
    move-result v9

    .line 497
    invoke-static {v9}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 498
    .line 499
    .line 500
    move-result-object v9

    .line 501
    invoke-virtual {v8, v11, v9}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 502
    .line 503
    .line 504
    goto :goto_2

    .line 505
    :cond_9
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->r()Z

    .line 506
    .line 507
    .line 508
    move-result v12

    .line 509
    if-eqz v12, :cond_a

    .line 510
    .line 511
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->s()Ljava/lang/String;

    .line 512
    .line 513
    .line 514
    move-result-object v9

    .line 515
    invoke-virtual {v8, v11, v9}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 516
    .line 517
    .line 518
    goto :goto_2

    .line 519
    :cond_a
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->t()Z

    .line 520
    .line 521
    .line 522
    move-result v12

    .line 523
    if-eqz v12, :cond_7

    .line 524
    .line 525
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/e3;->u()J

    .line 526
    .line 527
    .line 528
    move-result-wide v14

    .line 529
    invoke-static {v14, v15}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 530
    .line 531
    .line 532
    move-result-object v9

    .line 533
    invoke-virtual {v8, v11, v9}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 534
    .line 535
    .line 536
    goto :goto_2

    .line 537
    :cond_b
    sget-object v0, Lvp/z;->t0:Lvp/y;

    .line 538
    .line 539
    invoke-virtual {v4, v1, v0}, Lvp/h;->g0(Ljava/lang/String;Lvp/y;)Ljava/lang/String;

    .line 540
    .line 541
    .line 542
    move-result-object v0

    .line 543
    const-string v9, "\\|"

    .line 544
    .line 545
    invoke-virtual {v0, v9}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 546
    .line 547
    .line 548
    move-result-object v0

    .line 549
    invoke-static {v10, v0, v8, v3}, Lvp/s0;->q0(Landroid/net/Uri$Builder;[Ljava/lang/String;Landroid/os/Bundle;Ljava/util/Set;)V

    .line 550
    .line 551
    .line 552
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 553
    .line 554
    check-cast v0, Lcom/google/android/gms/internal/measurement/j3;

    .line 555
    .line 556
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/j3;->U1()Lcom/google/android/gms/internal/measurement/r5;

    .line 557
    .line 558
    .line 559
    move-result-object v0

    .line 560
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 561
    .line 562
    .line 563
    move-result-object v0

    .line 564
    new-instance v8, Landroid/os/Bundle;

    .line 565
    .line 566
    invoke-direct {v8}, Landroid/os/Bundle;-><init>()V

    .line 567
    .line 568
    .line 569
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 570
    .line 571
    .line 572
    move-result-object v0

    .line 573
    :cond_c
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 574
    .line 575
    .line 576
    move-result v11

    .line 577
    if-eqz v11, :cond_10

    .line 578
    .line 579
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    move-result-object v11

    .line 583
    check-cast v11, Lcom/google/android/gms/internal/measurement/s3;

    .line 584
    .line 585
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 586
    .line 587
    .line 588
    move-result-object v12

    .line 589
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->y()Z

    .line 590
    .line 591
    .line 592
    move-result v14

    .line 593
    if-eqz v14, :cond_d

    .line 594
    .line 595
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->z()D

    .line 596
    .line 597
    .line 598
    move-result-wide v14

    .line 599
    invoke-static {v14, v15}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 600
    .line 601
    .line 602
    move-result-object v11

    .line 603
    invoke-virtual {v8, v12, v11}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    goto :goto_3

    .line 607
    :cond_d
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->w()Z

    .line 608
    .line 609
    .line 610
    move-result v14

    .line 611
    if-eqz v14, :cond_e

    .line 612
    .line 613
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->x()F

    .line 614
    .line 615
    .line 616
    move-result v11

    .line 617
    invoke-static {v11}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 618
    .line 619
    .line 620
    move-result-object v11

    .line 621
    invoke-virtual {v8, v12, v11}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 622
    .line 623
    .line 624
    goto :goto_3

    .line 625
    :cond_e
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->s()Z

    .line 626
    .line 627
    .line 628
    move-result v14

    .line 629
    if-eqz v14, :cond_f

    .line 630
    .line 631
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->t()Ljava/lang/String;

    .line 632
    .line 633
    .line 634
    move-result-object v11

    .line 635
    invoke-virtual {v8, v12, v11}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 636
    .line 637
    .line 638
    goto :goto_3

    .line 639
    :cond_f
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->u()Z

    .line 640
    .line 641
    .line 642
    move-result v14

    .line 643
    if-eqz v14, :cond_c

    .line 644
    .line 645
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/s3;->v()J

    .line 646
    .line 647
    .line 648
    move-result-wide v14

    .line 649
    invoke-static {v14, v15}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 650
    .line 651
    .line 652
    move-result-object v11

    .line 653
    invoke-virtual {v8, v12, v11}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 654
    .line 655
    .line 656
    goto :goto_3

    .line 657
    :cond_10
    sget-object v0, Lvp/z;->s0:Lvp/y;

    .line 658
    .line 659
    invoke-virtual {v4, v1, v0}, Lvp/h;->g0(Ljava/lang/String;Lvp/y;)Ljava/lang/String;

    .line 660
    .line 661
    .line 662
    move-result-object v0

    .line 663
    invoke-virtual {v0, v9}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 664
    .line 665
    .line 666
    move-result-object v0

    .line 667
    invoke-static {v10, v0, v8, v3}, Lvp/s0;->q0(Landroid/net/Uri$Builder;[Ljava/lang/String;Landroid/os/Bundle;Ljava/util/Set;)V

    .line 668
    .line 669
    .line 670
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 671
    .line 672
    check-cast v0, Lcom/google/android/gms/internal/measurement/j3;

    .line 673
    .line 674
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/j3;->D0()Z

    .line 675
    .line 676
    .line 677
    move-result v0

    .line 678
    if-eq v13, v0, :cond_11

    .line 679
    .line 680
    const-string v7, "0"

    .line 681
    .line 682
    :cond_11
    const-string v0, "dma"

    .line 683
    .line 684
    invoke-static {v10, v0, v7, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 685
    .line 686
    .line 687
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 688
    .line 689
    check-cast v0, Lcom/google/android/gms/internal/measurement/j3;

    .line 690
    .line 691
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/j3;->F0()Ljava/lang/String;

    .line 692
    .line 693
    .line 694
    move-result-object v0

    .line 695
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 696
    .line 697
    .line 698
    move-result v0

    .line 699
    if-nez v0, :cond_12

    .line 700
    .line 701
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 702
    .line 703
    check-cast v0, Lcom/google/android/gms/internal/measurement/j3;

    .line 704
    .line 705
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/j3;->F0()Ljava/lang/String;

    .line 706
    .line 707
    .line 708
    move-result-object v0

    .line 709
    const-string v1, "dma_cps"

    .line 710
    .line 711
    invoke-static {v10, v1, v0, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 712
    .line 713
    .line 714
    :cond_12
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 715
    .line 716
    check-cast v0, Lcom/google/android/gms/internal/measurement/j3;

    .line 717
    .line 718
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/j3;->L0()Z

    .line 719
    .line 720
    .line 721
    move-result v0

    .line 722
    if-eqz v0, :cond_1a

    .line 723
    .line 724
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 725
    .line 726
    check-cast v0, Lcom/google/android/gms/internal/measurement/j3;

    .line 727
    .line 728
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/j3;->M0()Lcom/google/android/gms/internal/measurement/o2;

    .line 729
    .line 730
    .line 731
    move-result-object v0

    .line 732
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->z()Ljava/lang/String;

    .line 733
    .line 734
    .line 735
    move-result-object v1

    .line 736
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 737
    .line 738
    .line 739
    move-result v1

    .line 740
    if-nez v1, :cond_13

    .line 741
    .line 742
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->z()Ljava/lang/String;

    .line 743
    .line 744
    .line 745
    move-result-object v1

    .line 746
    const-string v2, "dl_gclid"

    .line 747
    .line 748
    invoke-static {v10, v2, v1, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 749
    .line 750
    .line 751
    :cond_13
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->B()Ljava/lang/String;

    .line 752
    .line 753
    .line 754
    move-result-object v1

    .line 755
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 756
    .line 757
    .line 758
    move-result v1

    .line 759
    if-nez v1, :cond_14

    .line 760
    .line 761
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->B()Ljava/lang/String;

    .line 762
    .line 763
    .line 764
    move-result-object v1

    .line 765
    const-string v2, "dl_gbraid"

    .line 766
    .line 767
    invoke-static {v10, v2, v1, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 768
    .line 769
    .line 770
    :cond_14
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->D()Ljava/lang/String;

    .line 771
    .line 772
    .line 773
    move-result-object v1

    .line 774
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 775
    .line 776
    .line 777
    move-result v1

    .line 778
    if-nez v1, :cond_15

    .line 779
    .line 780
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->D()Ljava/lang/String;

    .line 781
    .line 782
    .line 783
    move-result-object v1

    .line 784
    const-string v2, "dl_gs"

    .line 785
    .line 786
    invoke-static {v10, v2, v1, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 787
    .line 788
    .line 789
    :cond_15
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->F()J

    .line 790
    .line 791
    .line 792
    move-result-wide v1

    .line 793
    const-wide/16 v7, 0x0

    .line 794
    .line 795
    cmp-long v1, v1, v7

    .line 796
    .line 797
    if-lez v1, :cond_16

    .line 798
    .line 799
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->F()J

    .line 800
    .line 801
    .line 802
    move-result-wide v1

    .line 803
    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 804
    .line 805
    .line 806
    move-result-object v1

    .line 807
    const-string v2, "dl_ss_ts"

    .line 808
    .line 809
    invoke-static {v10, v2, v1, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 810
    .line 811
    .line 812
    :cond_16
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->H()Ljava/lang/String;

    .line 813
    .line 814
    .line 815
    move-result-object v1

    .line 816
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 817
    .line 818
    .line 819
    move-result v1

    .line 820
    if-nez v1, :cond_17

    .line 821
    .line 822
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->H()Ljava/lang/String;

    .line 823
    .line 824
    .line 825
    move-result-object v1

    .line 826
    const-string v2, "mr_gclid"

    .line 827
    .line 828
    invoke-static {v10, v2, v1, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 829
    .line 830
    .line 831
    :cond_17
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->J()Ljava/lang/String;

    .line 832
    .line 833
    .line 834
    move-result-object v1

    .line 835
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 836
    .line 837
    .line 838
    move-result v1

    .line 839
    if-nez v1, :cond_18

    .line 840
    .line 841
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->J()Ljava/lang/String;

    .line 842
    .line 843
    .line 844
    move-result-object v1

    .line 845
    const-string v2, "mr_gbraid"

    .line 846
    .line 847
    invoke-static {v10, v2, v1, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 848
    .line 849
    .line 850
    :cond_18
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->L()Ljava/lang/String;

    .line 851
    .line 852
    .line 853
    move-result-object v1

    .line 854
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 855
    .line 856
    .line 857
    move-result v1

    .line 858
    if-nez v1, :cond_19

    .line 859
    .line 860
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->L()Ljava/lang/String;

    .line 861
    .line 862
    .line 863
    move-result-object v1

    .line 864
    const-string v2, "mr_gs"

    .line 865
    .line 866
    invoke-static {v10, v2, v1, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 867
    .line 868
    .line 869
    :cond_19
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->N()J

    .line 870
    .line 871
    .line 872
    move-result-wide v1

    .line 873
    cmp-long v1, v1, v7

    .line 874
    .line 875
    if-lez v1, :cond_1a

    .line 876
    .line 877
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o2;->N()J

    .line 878
    .line 879
    .line 880
    move-result-wide v0

    .line 881
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 882
    .line 883
    .line 884
    move-result-object v0

    .line 885
    const-string v1, "mr_click_ts"

    .line 886
    .line 887
    invoke-static {v10, v1, v0, v3}, Lvp/s0;->n0(Landroid/net/Uri$Builder;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 888
    .line 889
    .line 890
    :cond_1a
    new-instance v0, Lvp/o3;

    .line 891
    .line 892
    invoke-virtual {v10}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    .line 893
    .line 894
    .line 895
    move-result-object v1

    .line 896
    invoke-virtual {v1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 897
    .line 898
    .line 899
    move-result-object v1

    .line 900
    invoke-direct {v0, v5, v6, v1, v13}, Lvp/o3;-><init>(JLjava/lang/String;I)V

    .line 901
    .line 902
    .line 903
    return-object v0

    .line 904
    :cond_1b
    const/4 v0, 0x0

    .line 905
    return-object v0
.end method

.method public C0(Lh01/k;)Lcom/google/android/gms/internal/measurement/b3;
    .locals 5

    .line 1
    invoke-static {}, Lcom/google/android/gms/internal/measurement/b3;->z()Lcom/google/android/gms/internal/measurement/a3;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-wide v1, p1, Lh01/k;->f:J

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 8
    .line 9
    .line 10
    iget-object v3, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 11
    .line 12
    check-cast v3, Lcom/google/android/gms/internal/measurement/b3;

    .line 13
    .line 14
    invoke-virtual {v3, v1, v2}, Lcom/google/android/gms/internal/measurement/b3;->H(J)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p1, Lh01/k;->j:Ljava/lang/Iterable;

    .line 18
    .line 19
    check-cast v1, Lvp/s;

    .line 20
    .line 21
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    iget-object v1, v1, Lvp/s;->d:Landroid/os/Bundle;

    .line 25
    .line 26
    invoke-virtual {v1}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-eqz v3, :cond_0

    .line 39
    .line 40
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    check-cast v3, Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {}, Lcom/google/android/gms/internal/measurement/e3;->B()Lcom/google/android/gms/internal/measurement/d3;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    invoke-virtual {v4, v3}, Lcom/google/android/gms/internal/measurement/d3;->i(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0, v4, v3}, Lvp/s0;->A0(Lcom/google/android/gms/internal/measurement/d3;Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0, v4}, Lcom/google/android/gms/internal/measurement/a3;->m(Lcom/google/android/gms/internal/measurement/d3;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_0
    iget-object p0, p1, Lh01/k;->i:Ljava/io/Serializable;

    .line 68
    .line 69
    check-cast p0, Ljava/lang/String;

    .line 70
    .line 71
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    if-nez p1, :cond_1

    .line 76
    .line 77
    const-string p1, "_o"

    .line 78
    .line 79
    invoke-virtual {v1, p1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    if-nez v1, :cond_1

    .line 84
    .line 85
    invoke-static {}, Lcom/google/android/gms/internal/measurement/e3;->B()Lcom/google/android/gms/internal/measurement/d3;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-virtual {v1, p1}, Lcom/google/android/gms/internal/measurement/d3;->i(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v1, p0}, Lcom/google/android/gms/internal/measurement/d3;->j(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Lcom/google/android/gms/internal/measurement/e3;

    .line 100
    .line 101
    invoke-virtual {v0, p0}, Lcom/google/android/gms/internal/measurement/a3;->l(Lcom/google/android/gms/internal/measurement/e3;)V

    .line 102
    .line 103
    .line 104
    :cond_1
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    check-cast p0, Lcom/google/android/gms/internal/measurement/b3;

    .line 109
    .line 110
    return-object p0
.end method

.method public D0(Lcom/google/android/gms/internal/measurement/h3;)Ljava/lang/String;
    .locals 13

    .line 1
    const-string v0, "\nbatch {\n"

    .line 2
    .line 3
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/h3;->u()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, 0x0

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/h3;->v()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const-string v3, "upload_subdomain"

    .line 19
    .line 20
    invoke-static {v0, v2, v3, v1}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/h3;->s()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_1

    .line 28
    .line 29
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/h3;->t()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    const-string v3, "sgtm_join_id"

    .line 34
    .line 35
    invoke-static {v0, v2, v3, v1}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/h3;->p()Ljava/util/List;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    :cond_2
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_4b

    .line 51
    .line 52
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    check-cast v1, Lcom/google/android/gms/internal/measurement/j3;

    .line 57
    .line 58
    if-eqz v1, :cond_2

    .line 59
    .line 60
    const/4 v2, 0x1

    .line 61
    invoke-static {v2, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 62
    .line 63
    .line 64
    const-string v3, "bundle {\n"

    .line 65
    .line 66
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->P()Z

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    if-eqz v3, :cond_3

    .line 74
    .line 75
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->P0()I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    const-string v4, "protocol_version"

    .line 84
    .line 85
    invoke-static {v0, v2, v4, v3}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_3
    sget-object v3, Lcom/google/android/gms/internal/measurement/g9;->e:Lcom/google/android/gms/internal/measurement/g9;

    .line 89
    .line 90
    iget-object v3, v3, Lcom/google/android/gms/internal/measurement/g9;->d:Lgr/p;

    .line 91
    .line 92
    iget-object v3, v3, Lgr/p;->d:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v3, Lcom/google/android/gms/internal/measurement/h9;

    .line 95
    .line 96
    iget-object v3, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v3, Lvp/g1;

    .line 99
    .line 100
    iget-object v4, v3, Lvp/g1;->g:Lvp/h;

    .line 101
    .line 102
    iget-object v5, v3, Lvp/g1;->m:Lvp/k0;

    .line 103
    .line 104
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    sget-object v7, Lvp/z;->M0:Lvp/y;

    .line 109
    .line 110
    invoke-virtual {v4, v6, v7}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 111
    .line 112
    .line 113
    move-result v4

    .line 114
    if-eqz v4, :cond_4

    .line 115
    .line 116
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->v0()Z

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    if-eqz v4, :cond_4

    .line 121
    .line 122
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->w0()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    const-string v6, "session_stitching_token"

    .line 127
    .line 128
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    :cond_4
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->h2()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v4

    .line 135
    const-string v6, "platform"

    .line 136
    .line 137
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->r()Z

    .line 141
    .line 142
    .line 143
    move-result v4

    .line 144
    if-eqz v4, :cond_5

    .line 145
    .line 146
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->s()J

    .line 147
    .line 148
    .line 149
    move-result-wide v6

    .line 150
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 151
    .line 152
    .line 153
    move-result-object v4

    .line 154
    const-string v6, "gmp_version"

    .line 155
    .line 156
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    :cond_5
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->t()Z

    .line 160
    .line 161
    .line 162
    move-result v4

    .line 163
    if-eqz v4, :cond_6

    .line 164
    .line 165
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->u()J

    .line 166
    .line 167
    .line 168
    move-result-wide v6

    .line 169
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 170
    .line 171
    .line 172
    move-result-object v4

    .line 173
    const-string v6, "uploading_gmp_version"

    .line 174
    .line 175
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    :cond_6
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->r0()Z

    .line 179
    .line 180
    .line 181
    move-result v4

    .line 182
    if-eqz v4, :cond_7

    .line 183
    .line 184
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->s0()J

    .line 185
    .line 186
    .line 187
    move-result-wide v6

    .line 188
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 189
    .line 190
    .line 191
    move-result-object v4

    .line 192
    const-string v6, "dynamite_version"

    .line 193
    .line 194
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    :cond_7
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->L()Z

    .line 198
    .line 199
    .line 200
    move-result v4

    .line 201
    if-eqz v4, :cond_8

    .line 202
    .line 203
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->M()J

    .line 204
    .line 205
    .line 206
    move-result-wide v6

    .line 207
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 208
    .line 209
    .line 210
    move-result-object v4

    .line 211
    const-string v6, "config_version"

    .line 212
    .line 213
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    :cond_8
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->E()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v4

    .line 220
    const-string v6, "gmp_app_id"

    .line 221
    .line 222
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v4

    .line 229
    const-string v6, "app_id"

    .line 230
    .line 231
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->q()Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object v4

    .line 238
    const-string v6, "app_version"

    .line 239
    .line 240
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->J()Z

    .line 244
    .line 245
    .line 246
    move-result v4

    .line 247
    if-eqz v4, :cond_9

    .line 248
    .line 249
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->K()I

    .line 250
    .line 251
    .line 252
    move-result v4

    .line 253
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 254
    .line 255
    .line 256
    move-result-object v4

    .line 257
    const-string v6, "app_version_major"

    .line 258
    .line 259
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    :cond_9
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->I()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v4

    .line 266
    const-string v6, "firebase_instance_id"

    .line 267
    .line 268
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->z()Z

    .line 272
    .line 273
    .line 274
    move-result v4

    .line 275
    if-eqz v4, :cond_a

    .line 276
    .line 277
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->A()J

    .line 278
    .line 279
    .line 280
    move-result-wide v6

    .line 281
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 282
    .line 283
    .line 284
    move-result-object v4

    .line 285
    const-string v6, "dev_cert_hash"

    .line 286
    .line 287
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 288
    .line 289
    .line 290
    :cond_a
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->n2()Ljava/lang/String;

    .line 291
    .line 292
    .line 293
    move-result-object v4

    .line 294
    const-string v6, "app_store"

    .line 295
    .line 296
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->X1()Z

    .line 300
    .line 301
    .line 302
    move-result v4

    .line 303
    if-eqz v4, :cond_b

    .line 304
    .line 305
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->Y1()J

    .line 306
    .line 307
    .line 308
    move-result-wide v6

    .line 309
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 310
    .line 311
    .line 312
    move-result-object v4

    .line 313
    const-string v6, "upload_timestamp_millis"

    .line 314
    .line 315
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 316
    .line 317
    .line 318
    :cond_b
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->Z1()Z

    .line 319
    .line 320
    .line 321
    move-result v4

    .line 322
    if-eqz v4, :cond_c

    .line 323
    .line 324
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->a2()J

    .line 325
    .line 326
    .line 327
    move-result-wide v6

    .line 328
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 329
    .line 330
    .line 331
    move-result-object v4

    .line 332
    const-string v6, "start_timestamp_millis"

    .line 333
    .line 334
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 335
    .line 336
    .line 337
    :cond_c
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->b2()Z

    .line 338
    .line 339
    .line 340
    move-result v4

    .line 341
    if-eqz v4, :cond_d

    .line 342
    .line 343
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->c2()J

    .line 344
    .line 345
    .line 346
    move-result-wide v6

    .line 347
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 348
    .line 349
    .line 350
    move-result-object v4

    .line 351
    const-string v6, "end_timestamp_millis"

    .line 352
    .line 353
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    :cond_d
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->d2()Z

    .line 357
    .line 358
    .line 359
    move-result v4

    .line 360
    if-eqz v4, :cond_e

    .line 361
    .line 362
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->e2()J

    .line 363
    .line 364
    .line 365
    move-result-wide v6

    .line 366
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 367
    .line 368
    .line 369
    move-result-object v4

    .line 370
    const-string v6, "previous_bundle_start_timestamp_millis"

    .line 371
    .line 372
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 373
    .line 374
    .line 375
    :cond_e
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->f2()Z

    .line 376
    .line 377
    .line 378
    move-result v4

    .line 379
    if-eqz v4, :cond_f

    .line 380
    .line 381
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->g2()J

    .line 382
    .line 383
    .line 384
    move-result-wide v6

    .line 385
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 386
    .line 387
    .line 388
    move-result-object v4

    .line 389
    const-string v6, "previous_bundle_end_timestamp_millis"

    .line 390
    .line 391
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 392
    .line 393
    .line 394
    :cond_f
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->y()Ljava/lang/String;

    .line 395
    .line 396
    .line 397
    move-result-object v4

    .line 398
    const-string v6, "app_instance_id"

    .line 399
    .line 400
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 401
    .line 402
    .line 403
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->v()Ljava/lang/String;

    .line 404
    .line 405
    .line 406
    move-result-object v4

    .line 407
    const-string v6, "resettable_device_id"

    .line 408
    .line 409
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 410
    .line 411
    .line 412
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->O()Ljava/lang/String;

    .line 413
    .line 414
    .line 415
    move-result-object v4

    .line 416
    const-string v6, "ds_id"

    .line 417
    .line 418
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->w()Z

    .line 422
    .line 423
    .line 424
    move-result v4

    .line 425
    if-eqz v4, :cond_10

    .line 426
    .line 427
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->x()Z

    .line 428
    .line 429
    .line 430
    move-result v4

    .line 431
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 432
    .line 433
    .line 434
    move-result-object v4

    .line 435
    const-string v6, "limited_ad_tracking"

    .line 436
    .line 437
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 438
    .line 439
    .line 440
    :cond_10
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->i2()Ljava/lang/String;

    .line 441
    .line 442
    .line 443
    move-result-object v4

    .line 444
    const-string v6, "os_version"

    .line 445
    .line 446
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 447
    .line 448
    .line 449
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->j2()Ljava/lang/String;

    .line 450
    .line 451
    .line 452
    move-result-object v4

    .line 453
    const-string v6, "device_model"

    .line 454
    .line 455
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->k2()Ljava/lang/String;

    .line 459
    .line 460
    .line 461
    move-result-object v4

    .line 462
    const-string v6, "user_default_language"

    .line 463
    .line 464
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 465
    .line 466
    .line 467
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->l2()Z

    .line 468
    .line 469
    .line 470
    move-result v4

    .line 471
    if-eqz v4, :cond_11

    .line 472
    .line 473
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->m2()I

    .line 474
    .line 475
    .line 476
    move-result v4

    .line 477
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 478
    .line 479
    .line 480
    move-result-object v4

    .line 481
    const-string v6, "time_zone_offset_minutes"

    .line 482
    .line 483
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 484
    .line 485
    .line 486
    :cond_11
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->B()Z

    .line 487
    .line 488
    .line 489
    move-result v4

    .line 490
    if-eqz v4, :cond_12

    .line 491
    .line 492
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->C()I

    .line 493
    .line 494
    .line 495
    move-result v4

    .line 496
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 497
    .line 498
    .line 499
    move-result-object v4

    .line 500
    const-string v6, "bundle_sequential_index"

    .line 501
    .line 502
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 503
    .line 504
    .line 505
    :cond_12
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->J0()Z

    .line 506
    .line 507
    .line 508
    move-result v4

    .line 509
    if-eqz v4, :cond_13

    .line 510
    .line 511
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->K0()I

    .line 512
    .line 513
    .line 514
    move-result v4

    .line 515
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 516
    .line 517
    .line 518
    move-result-object v4

    .line 519
    const-string v6, "delivery_index"

    .line 520
    .line 521
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 522
    .line 523
    .line 524
    :cond_13
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->F()Z

    .line 525
    .line 526
    .line 527
    move-result v4

    .line 528
    if-eqz v4, :cond_14

    .line 529
    .line 530
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->G()Z

    .line 531
    .line 532
    .line 533
    move-result v4

    .line 534
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 535
    .line 536
    .line 537
    move-result-object v4

    .line 538
    const-string v6, "service_upload"

    .line 539
    .line 540
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 541
    .line 542
    .line 543
    :cond_14
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->D()Ljava/lang/String;

    .line 544
    .line 545
    .line 546
    move-result-object v4

    .line 547
    const-string v6, "health_monitor"

    .line 548
    .line 549
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 550
    .line 551
    .line 552
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->p0()Z

    .line 553
    .line 554
    .line 555
    move-result v4

    .line 556
    if-eqz v4, :cond_15

    .line 557
    .line 558
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->q0()I

    .line 559
    .line 560
    .line 561
    move-result v4

    .line 562
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 563
    .line 564
    .line 565
    move-result-object v4

    .line 566
    const-string v6, "retry_counter"

    .line 567
    .line 568
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 569
    .line 570
    .line 571
    :cond_15
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->t0()Z

    .line 572
    .line 573
    .line 574
    move-result v4

    .line 575
    if-eqz v4, :cond_16

    .line 576
    .line 577
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->u0()Ljava/lang/String;

    .line 578
    .line 579
    .line 580
    move-result-object v4

    .line 581
    const-string v6, "consent_signals"

    .line 582
    .line 583
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 584
    .line 585
    .line 586
    :cond_16
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->C0()Z

    .line 587
    .line 588
    .line 589
    move-result v4

    .line 590
    if-eqz v4, :cond_17

    .line 591
    .line 592
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->D0()Z

    .line 593
    .line 594
    .line 595
    move-result v4

    .line 596
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 597
    .line 598
    .line 599
    move-result-object v4

    .line 600
    const-string v6, "is_dma_region"

    .line 601
    .line 602
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 603
    .line 604
    .line 605
    :cond_17
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->E0()Z

    .line 606
    .line 607
    .line 608
    move-result v4

    .line 609
    if-eqz v4, :cond_18

    .line 610
    .line 611
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->F0()Ljava/lang/String;

    .line 612
    .line 613
    .line 614
    move-result-object v4

    .line 615
    const-string v6, "core_platform_services"

    .line 616
    .line 617
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 618
    .line 619
    .line 620
    :cond_18
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->A0()Z

    .line 621
    .line 622
    .line 623
    move-result v4

    .line 624
    if-eqz v4, :cond_19

    .line 625
    .line 626
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->B0()Ljava/lang/String;

    .line 627
    .line 628
    .line 629
    move-result-object v4

    .line 630
    const-string v6, "consent_diagnostics"

    .line 631
    .line 632
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 633
    .line 634
    .line 635
    :cond_19
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->x0()Z

    .line 636
    .line 637
    .line 638
    move-result v4

    .line 639
    if-eqz v4, :cond_1a

    .line 640
    .line 641
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->y0()J

    .line 642
    .line 643
    .line 644
    move-result-wide v6

    .line 645
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 646
    .line 647
    .line 648
    move-result-object v4

    .line 649
    const-string v6, "target_os_version"

    .line 650
    .line 651
    invoke-static {v0, v2, v6, v4}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 652
    .line 653
    .line 654
    :cond_1a
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 655
    .line 656
    .line 657
    iget-object v3, v3, Lvp/g1;->g:Lvp/h;

    .line 658
    .line 659
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->p()Ljava/lang/String;

    .line 660
    .line 661
    .line 662
    move-result-object v4

    .line 663
    sget-object v6, Lvp/z;->P0:Lvp/y;

    .line 664
    .line 665
    invoke-virtual {v3, v4, v6}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 666
    .line 667
    .line 668
    move-result v3

    .line 669
    const-string v4, "}\n"

    .line 670
    .line 671
    const/4 v6, 0x2

    .line 672
    if-eqz v3, :cond_1b

    .line 673
    .line 674
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->G0()I

    .line 675
    .line 676
    .line 677
    move-result v3

    .line 678
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 679
    .line 680
    .line 681
    move-result-object v3

    .line 682
    const-string v7, "ad_services_version"

    .line 683
    .line 684
    invoke-static {v0, v2, v7, v3}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 685
    .line 686
    .line 687
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->H0()Z

    .line 688
    .line 689
    .line 690
    move-result v3

    .line 691
    if-eqz v3, :cond_1b

    .line 692
    .line 693
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->I0()Lcom/google/android/gms/internal/measurement/r2;

    .line 694
    .line 695
    .line 696
    move-result-object v3

    .line 697
    if-eqz v3, :cond_1b

    .line 698
    .line 699
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 700
    .line 701
    .line 702
    const-string v7, "attribution_eligibility_status {\n"

    .line 703
    .line 704
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 705
    .line 706
    .line 707
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/r2;->p()Z

    .line 708
    .line 709
    .line 710
    move-result v7

    .line 711
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 712
    .line 713
    .line 714
    move-result-object v7

    .line 715
    const-string v8, "eligible"

    .line 716
    .line 717
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 718
    .line 719
    .line 720
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/r2;->q()Z

    .line 721
    .line 722
    .line 723
    move-result v7

    .line 724
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 725
    .line 726
    .line 727
    move-result-object v7

    .line 728
    const-string v8, "no_access_adservices_attribution_permission"

    .line 729
    .line 730
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 731
    .line 732
    .line 733
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/r2;->r()Z

    .line 734
    .line 735
    .line 736
    move-result v7

    .line 737
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 738
    .line 739
    .line 740
    move-result-object v7

    .line 741
    const-string v8, "pre_r"

    .line 742
    .line 743
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 744
    .line 745
    .line 746
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/r2;->s()Z

    .line 747
    .line 748
    .line 749
    move-result v7

    .line 750
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 751
    .line 752
    .line 753
    move-result-object v7

    .line 754
    const-string v8, "r_extensions_too_old"

    .line 755
    .line 756
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 757
    .line 758
    .line 759
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/r2;->t()Z

    .line 760
    .line 761
    .line 762
    move-result v7

    .line 763
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 764
    .line 765
    .line 766
    move-result-object v7

    .line 767
    const-string v8, "adservices_extension_too_old"

    .line 768
    .line 769
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 770
    .line 771
    .line 772
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/r2;->u()Z

    .line 773
    .line 774
    .line 775
    move-result v7

    .line 776
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 777
    .line 778
    .line 779
    move-result-object v7

    .line 780
    const-string v8, "ad_storage_not_allowed"

    .line 781
    .line 782
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 783
    .line 784
    .line 785
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/r2;->v()Z

    .line 786
    .line 787
    .line 788
    move-result v3

    .line 789
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 790
    .line 791
    .line 792
    move-result-object v3

    .line 793
    const-string v7, "measurement_manager_disabled"

    .line 794
    .line 795
    invoke-static {v0, v6, v7, v3}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 796
    .line 797
    .line 798
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 799
    .line 800
    .line 801
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 802
    .line 803
    .line 804
    :cond_1b
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->L0()Z

    .line 805
    .line 806
    .line 807
    move-result v3

    .line 808
    if-eqz v3, :cond_24

    .line 809
    .line 810
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->M0()Lcom/google/android/gms/internal/measurement/o2;

    .line 811
    .line 812
    .line 813
    move-result-object v3

    .line 814
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 815
    .line 816
    .line 817
    const-string v7, "ad_campaign_info {\n"

    .line 818
    .line 819
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 820
    .line 821
    .line 822
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->y()Z

    .line 823
    .line 824
    .line 825
    move-result v7

    .line 826
    if-eqz v7, :cond_1c

    .line 827
    .line 828
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->z()Ljava/lang/String;

    .line 829
    .line 830
    .line 831
    move-result-object v7

    .line 832
    const-string v8, "deep_link_gclid"

    .line 833
    .line 834
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 835
    .line 836
    .line 837
    :cond_1c
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->A()Z

    .line 838
    .line 839
    .line 840
    move-result v7

    .line 841
    if-eqz v7, :cond_1d

    .line 842
    .line 843
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->B()Ljava/lang/String;

    .line 844
    .line 845
    .line 846
    move-result-object v7

    .line 847
    const-string v8, "deep_link_gbraid"

    .line 848
    .line 849
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 850
    .line 851
    .line 852
    :cond_1d
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->C()Z

    .line 853
    .line 854
    .line 855
    move-result v7

    .line 856
    if-eqz v7, :cond_1e

    .line 857
    .line 858
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->D()Ljava/lang/String;

    .line 859
    .line 860
    .line 861
    move-result-object v7

    .line 862
    const-string v8, "deep_link_gad_source"

    .line 863
    .line 864
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 865
    .line 866
    .line 867
    :cond_1e
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->E()Z

    .line 868
    .line 869
    .line 870
    move-result v7

    .line 871
    if-eqz v7, :cond_1f

    .line 872
    .line 873
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->F()J

    .line 874
    .line 875
    .line 876
    move-result-wide v7

    .line 877
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 878
    .line 879
    .line 880
    move-result-object v7

    .line 881
    const-string v8, "deep_link_session_millis"

    .line 882
    .line 883
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 884
    .line 885
    .line 886
    :cond_1f
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->G()Z

    .line 887
    .line 888
    .line 889
    move-result v7

    .line 890
    if-eqz v7, :cond_20

    .line 891
    .line 892
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->H()Ljava/lang/String;

    .line 893
    .line 894
    .line 895
    move-result-object v7

    .line 896
    const-string v8, "market_referrer_gclid"

    .line 897
    .line 898
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 899
    .line 900
    .line 901
    :cond_20
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->I()Z

    .line 902
    .line 903
    .line 904
    move-result v7

    .line 905
    if-eqz v7, :cond_21

    .line 906
    .line 907
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->J()Ljava/lang/String;

    .line 908
    .line 909
    .line 910
    move-result-object v7

    .line 911
    const-string v8, "market_referrer_gbraid"

    .line 912
    .line 913
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 914
    .line 915
    .line 916
    :cond_21
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->K()Z

    .line 917
    .line 918
    .line 919
    move-result v7

    .line 920
    if-eqz v7, :cond_22

    .line 921
    .line 922
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->L()Ljava/lang/String;

    .line 923
    .line 924
    .line 925
    move-result-object v7

    .line 926
    const-string v8, "market_referrer_gad_source"

    .line 927
    .line 928
    invoke-static {v0, v6, v8, v7}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 929
    .line 930
    .line 931
    :cond_22
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->M()Z

    .line 932
    .line 933
    .line 934
    move-result v7

    .line 935
    if-eqz v7, :cond_23

    .line 936
    .line 937
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o2;->N()J

    .line 938
    .line 939
    .line 940
    move-result-wide v7

    .line 941
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 942
    .line 943
    .line 944
    move-result-object v3

    .line 945
    const-string v7, "market_referrer_click_millis"

    .line 946
    .line 947
    invoke-static {v0, v6, v7, v3}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 948
    .line 949
    .line 950
    :cond_23
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 951
    .line 952
    .line 953
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 954
    .line 955
    .line 956
    :cond_24
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->Q()Z

    .line 957
    .line 958
    .line 959
    move-result v3

    .line 960
    if-eqz v3, :cond_25

    .line 961
    .line 962
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->R()J

    .line 963
    .line 964
    .line 965
    move-result-wide v7

    .line 966
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 967
    .line 968
    .line 969
    move-result-object v3

    .line 970
    const-string v7, "batching_timestamp_millis"

    .line 971
    .line 972
    invoke-static {v0, v2, v7, v3}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 973
    .line 974
    .line 975
    :cond_25
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->N0()Z

    .line 976
    .line 977
    .line 978
    move-result v3

    .line 979
    const/4 v7, 0x4

    .line 980
    const/4 v8, 0x3

    .line 981
    if-eqz v3, :cond_2f

    .line 982
    .line 983
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->O0()Lcom/google/android/gms/internal/measurement/q3;

    .line 984
    .line 985
    .line 986
    move-result-object v3

    .line 987
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 988
    .line 989
    .line 990
    const-string v9, "sgtm_diagnostics {\n"

    .line 991
    .line 992
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 993
    .line 994
    .line 995
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/q3;->t()I

    .line 996
    .line 997
    .line 998
    move-result v9

    .line 999
    if-eq v9, v2, :cond_29

    .line 1000
    .line 1001
    if-eq v9, v6, :cond_28

    .line 1002
    .line 1003
    if-eq v9, v8, :cond_27

    .line 1004
    .line 1005
    if-eq v9, v7, :cond_26

    .line 1006
    .line 1007
    const-string v9, "SDK_SERVICE_UPLOAD"

    .line 1008
    .line 1009
    goto :goto_1

    .line 1010
    :cond_26
    const-string v9, "PACKAGE_SERVICE_UPLOAD"

    .line 1011
    .line 1012
    goto :goto_1

    .line 1013
    :cond_27
    const-string v9, "SDK_CLIENT_UPLOAD"

    .line 1014
    .line 1015
    goto :goto_1

    .line 1016
    :cond_28
    const-string v9, "GA_UPLOAD"

    .line 1017
    .line 1018
    goto :goto_1

    .line 1019
    :cond_29
    const-string v9, "UPLOAD_TYPE_UNKNOWN"

    .line 1020
    .line 1021
    :goto_1
    const-string v10, "upload_type"

    .line 1022
    .line 1023
    invoke-static {v0, v6, v10, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1024
    .line 1025
    .line 1026
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/q3;->p()I

    .line 1027
    .line 1028
    .line 1029
    move-result v9

    .line 1030
    invoke-static {v9}, Lc1/j0;->D(I)Ljava/lang/String;

    .line 1031
    .line 1032
    .line 1033
    move-result-object v9

    .line 1034
    const-string v10, "client_upload_eligibility"

    .line 1035
    .line 1036
    invoke-static {v0, v6, v10, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1037
    .line 1038
    .line 1039
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/q3;->u()I

    .line 1040
    .line 1041
    .line 1042
    move-result v3

    .line 1043
    if-eq v3, v2, :cond_2e

    .line 1044
    .line 1045
    if-eq v3, v6, :cond_2d

    .line 1046
    .line 1047
    if-eq v3, v8, :cond_2c

    .line 1048
    .line 1049
    if-eq v3, v7, :cond_2b

    .line 1050
    .line 1051
    const/4 v9, 0x5

    .line 1052
    if-eq v3, v9, :cond_2a

    .line 1053
    .line 1054
    const-string v3, "NON_PLAY_MISSING_SGTM_SERVER_URL"

    .line 1055
    .line 1056
    goto :goto_2

    .line 1057
    :cond_2a
    const-string v3, "MISSING_SGTM_PROXY_INFO"

    .line 1058
    .line 1059
    goto :goto_2

    .line 1060
    :cond_2b
    const-string v3, "MISSING_SGTM_SETTINGS"

    .line 1061
    .line 1062
    goto :goto_2

    .line 1063
    :cond_2c
    const-string v3, "NOT_IN_ROLLOUT"

    .line 1064
    .line 1065
    goto :goto_2

    .line 1066
    :cond_2d
    const-string v3, "SERVICE_UPLOAD_ELIGIBLE"

    .line 1067
    .line 1068
    goto :goto_2

    .line 1069
    :cond_2e
    const-string v3, "SERVICE_UPLOAD_ELIGIBILITY_UNKNOWN"

    .line 1070
    .line 1071
    :goto_2
    const-string v9, "service_upload_eligibility"

    .line 1072
    .line 1073
    invoke-static {v0, v6, v9, v3}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1074
    .line 1075
    .line 1076
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1077
    .line 1078
    .line 1079
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1080
    .line 1081
    .line 1082
    :cond_2f
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->S()Z

    .line 1083
    .line 1084
    .line 1085
    move-result v3

    .line 1086
    if-eqz v3, :cond_37

    .line 1087
    .line 1088
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->T()Lcom/google/android/gms/internal/measurement/x2;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v3

    .line 1092
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1093
    .line 1094
    .line 1095
    const-string v9, "consent_info_extra {\n"

    .line 1096
    .line 1097
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1098
    .line 1099
    .line 1100
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/x2;->p()Ljava/util/List;

    .line 1101
    .line 1102
    .line 1103
    move-result-object v3

    .line 1104
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v3

    .line 1108
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1109
    .line 1110
    .line 1111
    move-result v9

    .line 1112
    if-eqz v9, :cond_36

    .line 1113
    .line 1114
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v9

    .line 1118
    check-cast v9, Lcom/google/android/gms/internal/measurement/w2;

    .line 1119
    .line 1120
    invoke-static {v8, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1121
    .line 1122
    .line 1123
    const-string v10, "limited_data_modes {\n"

    .line 1124
    .line 1125
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1126
    .line 1127
    .line 1128
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/w2;->q()I

    .line 1129
    .line 1130
    .line 1131
    move-result v10

    .line 1132
    if-eq v10, v2, :cond_33

    .line 1133
    .line 1134
    if-eq v10, v6, :cond_32

    .line 1135
    .line 1136
    if-eq v10, v8, :cond_31

    .line 1137
    .line 1138
    if-eq v10, v7, :cond_30

    .line 1139
    .line 1140
    const-string v10, "AD_PERSONALIZATION"

    .line 1141
    .line 1142
    goto :goto_4

    .line 1143
    :cond_30
    const-string v10, "AD_USER_DATA"

    .line 1144
    .line 1145
    goto :goto_4

    .line 1146
    :cond_31
    const-string v10, "ANALYTICS_STORAGE"

    .line 1147
    .line 1148
    goto :goto_4

    .line 1149
    :cond_32
    const-string v10, "AD_STORAGE"

    .line 1150
    .line 1151
    goto :goto_4

    .line 1152
    :cond_33
    const-string v10, "CONSENT_TYPE_UNSPECIFIED"

    .line 1153
    .line 1154
    :goto_4
    const-string v11, "type"

    .line 1155
    .line 1156
    invoke-static {v0, v8, v11, v10}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1157
    .line 1158
    .line 1159
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/w2;->r()I

    .line 1160
    .line 1161
    .line 1162
    move-result v9

    .line 1163
    if-eq v9, v2, :cond_35

    .line 1164
    .line 1165
    if-eq v9, v6, :cond_34

    .line 1166
    .line 1167
    const-string v9, "NO_DATA_MODE"

    .line 1168
    .line 1169
    goto :goto_5

    .line 1170
    :cond_34
    const-string v9, "LIMITED_MODE"

    .line 1171
    .line 1172
    goto :goto_5

    .line 1173
    :cond_35
    const-string v9, "NOT_LIMITED"

    .line 1174
    .line 1175
    :goto_5
    const-string v10, "mode"

    .line 1176
    .line 1177
    invoke-static {v0, v8, v10, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1178
    .line 1179
    .line 1180
    invoke-static {v8, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1181
    .line 1182
    .line 1183
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1184
    .line 1185
    .line 1186
    goto :goto_3

    .line 1187
    :cond_36
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1188
    .line 1189
    .line 1190
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1191
    .line 1192
    .line 1193
    :cond_37
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->U1()Lcom/google/android/gms/internal/measurement/r5;

    .line 1194
    .line 1195
    .line 1196
    move-result-object v3

    .line 1197
    const-string v7, "name"

    .line 1198
    .line 1199
    if-nez v3, :cond_38

    .line 1200
    .line 1201
    goto/16 :goto_9

    .line 1202
    .line 1203
    :cond_38
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v3

    .line 1207
    :cond_39
    :goto_6
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1208
    .line 1209
    .line 1210
    move-result v8

    .line 1211
    if-eqz v8, :cond_3d

    .line 1212
    .line 1213
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1214
    .line 1215
    .line 1216
    move-result-object v8

    .line 1217
    check-cast v8, Lcom/google/android/gms/internal/measurement/s3;

    .line 1218
    .line 1219
    if-eqz v8, :cond_39

    .line 1220
    .line 1221
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1222
    .line 1223
    .line 1224
    const-string v9, "user_property {\n"

    .line 1225
    .line 1226
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1227
    .line 1228
    .line 1229
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/s3;->p()Z

    .line 1230
    .line 1231
    .line 1232
    move-result v9

    .line 1233
    const/4 v10, 0x0

    .line 1234
    if-eqz v9, :cond_3a

    .line 1235
    .line 1236
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/s3;->q()J

    .line 1237
    .line 1238
    .line 1239
    move-result-wide v11

    .line 1240
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v9

    .line 1244
    goto :goto_7

    .line 1245
    :cond_3a
    move-object v9, v10

    .line 1246
    :goto_7
    const-string v11, "set_timestamp_millis"

    .line 1247
    .line 1248
    invoke-static {v0, v6, v11, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1249
    .line 1250
    .line 1251
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 1252
    .line 1253
    .line 1254
    move-result-object v9

    .line 1255
    invoke-virtual {v5, v9}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 1256
    .line 1257
    .line 1258
    move-result-object v9

    .line 1259
    invoke-static {v0, v6, v7, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1260
    .line 1261
    .line 1262
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/s3;->t()Ljava/lang/String;

    .line 1263
    .line 1264
    .line 1265
    move-result-object v9

    .line 1266
    const-string v11, "string_value"

    .line 1267
    .line 1268
    invoke-static {v0, v6, v11, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1269
    .line 1270
    .line 1271
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/s3;->u()Z

    .line 1272
    .line 1273
    .line 1274
    move-result v9

    .line 1275
    if-eqz v9, :cond_3b

    .line 1276
    .line 1277
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/s3;->v()J

    .line 1278
    .line 1279
    .line 1280
    move-result-wide v11

    .line 1281
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v9

    .line 1285
    goto :goto_8

    .line 1286
    :cond_3b
    move-object v9, v10

    .line 1287
    :goto_8
    const-string v11, "int_value"

    .line 1288
    .line 1289
    invoke-static {v0, v6, v11, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1290
    .line 1291
    .line 1292
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/s3;->y()Z

    .line 1293
    .line 1294
    .line 1295
    move-result v9

    .line 1296
    if-eqz v9, :cond_3c

    .line 1297
    .line 1298
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/s3;->z()D

    .line 1299
    .line 1300
    .line 1301
    move-result-wide v8

    .line 1302
    invoke-static {v8, v9}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1303
    .line 1304
    .line 1305
    move-result-object v10

    .line 1306
    :cond_3c
    const-string v8, "double_value"

    .line 1307
    .line 1308
    invoke-static {v0, v6, v8, v10}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1309
    .line 1310
    .line 1311
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1312
    .line 1313
    .line 1314
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1315
    .line 1316
    .line 1317
    goto :goto_6

    .line 1318
    :cond_3d
    :goto_9
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->H()Lcom/google/android/gms/internal/measurement/r5;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v3

    .line 1322
    if-nez v3, :cond_3e

    .line 1323
    .line 1324
    goto :goto_b

    .line 1325
    :cond_3e
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1326
    .line 1327
    .line 1328
    move-result-object v3

    .line 1329
    :cond_3f
    :goto_a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1330
    .line 1331
    .line 1332
    move-result v8

    .line 1333
    if-eqz v8, :cond_43

    .line 1334
    .line 1335
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1336
    .line 1337
    .line 1338
    move-result-object v8

    .line 1339
    check-cast v8, Lcom/google/android/gms/internal/measurement/t2;

    .line 1340
    .line 1341
    if-eqz v8, :cond_3f

    .line 1342
    .line 1343
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1344
    .line 1345
    .line 1346
    const-string v9, "audience_membership {\n"

    .line 1347
    .line 1348
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1349
    .line 1350
    .line 1351
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/t2;->p()Z

    .line 1352
    .line 1353
    .line 1354
    move-result v9

    .line 1355
    if-eqz v9, :cond_40

    .line 1356
    .line 1357
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/t2;->q()I

    .line 1358
    .line 1359
    .line 1360
    move-result v9

    .line 1361
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1362
    .line 1363
    .line 1364
    move-result-object v9

    .line 1365
    const-string v10, "audience_id"

    .line 1366
    .line 1367
    invoke-static {v0, v6, v10, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1368
    .line 1369
    .line 1370
    :cond_40
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/t2;->u()Z

    .line 1371
    .line 1372
    .line 1373
    move-result v9

    .line 1374
    if-eqz v9, :cond_41

    .line 1375
    .line 1376
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/t2;->v()Z

    .line 1377
    .line 1378
    .line 1379
    move-result v9

    .line 1380
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1381
    .line 1382
    .line 1383
    move-result-object v9

    .line 1384
    const-string v10, "new_audience"

    .line 1385
    .line 1386
    invoke-static {v0, v6, v10, v9}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1387
    .line 1388
    .line 1389
    :cond_41
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/t2;->r()Lcom/google/android/gms/internal/measurement/m3;

    .line 1390
    .line 1391
    .line 1392
    move-result-object v9

    .line 1393
    const-string v10, "current_data"

    .line 1394
    .line 1395
    invoke-static {v0, v10, v9}, Lvp/s0;->r0(Ljava/lang/StringBuilder;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m3;)V

    .line 1396
    .line 1397
    .line 1398
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/t2;->s()Z

    .line 1399
    .line 1400
    .line 1401
    move-result v9

    .line 1402
    if-eqz v9, :cond_42

    .line 1403
    .line 1404
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/t2;->t()Lcom/google/android/gms/internal/measurement/m3;

    .line 1405
    .line 1406
    .line 1407
    move-result-object v8

    .line 1408
    const-string v9, "previous_data"

    .line 1409
    .line 1410
    invoke-static {v0, v9, v8}, Lvp/s0;->r0(Ljava/lang/StringBuilder;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m3;)V

    .line 1411
    .line 1412
    .line 1413
    :cond_42
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1414
    .line 1415
    .line 1416
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1417
    .line 1418
    .line 1419
    goto :goto_a

    .line 1420
    :cond_43
    :goto_b
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/j3;->P1()Ljava/util/List;

    .line 1421
    .line 1422
    .line 1423
    move-result-object v1

    .line 1424
    if-nez v1, :cond_44

    .line 1425
    .line 1426
    goto :goto_d

    .line 1427
    :cond_44
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1428
    .line 1429
    .line 1430
    move-result-object v1

    .line 1431
    :cond_45
    :goto_c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1432
    .line 1433
    .line 1434
    move-result v3

    .line 1435
    if-eqz v3, :cond_4a

    .line 1436
    .line 1437
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1438
    .line 1439
    .line 1440
    move-result-object v3

    .line 1441
    check-cast v3, Lcom/google/android/gms/internal/measurement/b3;

    .line 1442
    .line 1443
    if-eqz v3, :cond_45

    .line 1444
    .line 1445
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1446
    .line 1447
    .line 1448
    const-string v8, "event {\n"

    .line 1449
    .line 1450
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1451
    .line 1452
    .line 1453
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 1454
    .line 1455
    .line 1456
    move-result-object v8

    .line 1457
    invoke-virtual {v5, v8}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 1458
    .line 1459
    .line 1460
    move-result-object v8

    .line 1461
    invoke-static {v0, v6, v7, v8}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1462
    .line 1463
    .line 1464
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->t()Z

    .line 1465
    .line 1466
    .line 1467
    move-result v8

    .line 1468
    if-eqz v8, :cond_46

    .line 1469
    .line 1470
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->u()J

    .line 1471
    .line 1472
    .line 1473
    move-result-wide v8

    .line 1474
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1475
    .line 1476
    .line 1477
    move-result-object v8

    .line 1478
    const-string v9, "timestamp_millis"

    .line 1479
    .line 1480
    invoke-static {v0, v6, v9, v8}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1481
    .line 1482
    .line 1483
    :cond_46
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->v()Z

    .line 1484
    .line 1485
    .line 1486
    move-result v8

    .line 1487
    if-eqz v8, :cond_47

    .line 1488
    .line 1489
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->w()J

    .line 1490
    .line 1491
    .line 1492
    move-result-wide v8

    .line 1493
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1494
    .line 1495
    .line 1496
    move-result-object v8

    .line 1497
    const-string v9, "previous_timestamp_millis"

    .line 1498
    .line 1499
    invoke-static {v0, v6, v9, v8}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1500
    .line 1501
    .line 1502
    :cond_47
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->x()Z

    .line 1503
    .line 1504
    .line 1505
    move-result v8

    .line 1506
    if-eqz v8, :cond_48

    .line 1507
    .line 1508
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->y()I

    .line 1509
    .line 1510
    .line 1511
    move-result v8

    .line 1512
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1513
    .line 1514
    .line 1515
    move-result-object v8

    .line 1516
    const-string v9, "count"

    .line 1517
    .line 1518
    invoke-static {v0, v6, v9, v8}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 1519
    .line 1520
    .line 1521
    :cond_48
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->q()I

    .line 1522
    .line 1523
    .line 1524
    move-result v8

    .line 1525
    if-eqz v8, :cond_49

    .line 1526
    .line 1527
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/b3;->p()Ljava/util/List;

    .line 1528
    .line 1529
    .line 1530
    move-result-object v3

    .line 1531
    check-cast v3, Lcom/google/android/gms/internal/measurement/r5;

    .line 1532
    .line 1533
    invoke-virtual {p0, v0, v6, v3}, Lvp/s0;->k0(Ljava/lang/StringBuilder;ILcom/google/android/gms/internal/measurement/r5;)V

    .line 1534
    .line 1535
    .line 1536
    :cond_49
    invoke-static {v6, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1537
    .line 1538
    .line 1539
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1540
    .line 1541
    .line 1542
    goto :goto_c

    .line 1543
    :cond_4a
    :goto_d
    invoke-static {v2, v0}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 1544
    .line 1545
    .line 1546
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1547
    .line 1548
    .line 1549
    goto/16 :goto_0

    .line 1550
    .line 1551
    :cond_4b
    const-string p0, "} // End-of-batch\n"

    .line 1552
    .line 1553
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1554
    .line 1555
    .line 1556
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1557
    .line 1558
    .line 1559
    move-result-object p0

    .line 1560
    return-object p0
.end method

.method public E0(Lcom/google/android/gms/internal/measurement/v1;)Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "\nproperty_filter {\n"

    .line 2
    .line 3
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v1;->p()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, 0x0

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v1;->q()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    const-string v3, "filter_id"

    .line 23
    .line 24
    invoke-static {v0, v2, v3, v1}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v1, Lvp/g1;

    .line 30
    .line 31
    iget-object v1, v1, Lvp/g1;->m:Lvp/k0;

    .line 32
    .line 33
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v1;->r()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    invoke-virtual {v1, v3}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    const-string v3, "property_name"

    .line 42
    .line 43
    invoke-static {v0, v2, v3, v1}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v1;->t()Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v1;->u()Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v1;->w()Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    invoke-static {v1, v3, v4}, Lvp/s0;->o0(ZZZ)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-nez v3, :cond_1

    .line 67
    .line 68
    const-string v3, "filter_type"

    .line 69
    .line 70
    invoke-static {v0, v2, v3, v1}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :cond_1
    const/4 v1, 0x1

    .line 74
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v1;->s()Lcom/google/android/gms/internal/measurement/q1;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p0, v0, v1, p1}, Lvp/s0;->l0(Ljava/lang/StringBuilder;ILcom/google/android/gms/internal/measurement/q1;)V

    .line 79
    .line 80
    .line 81
    const-string p0, "}\n"

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

.method public F0([BLandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    :try_start_0
    array-length v2, p1

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-virtual {v1, p1, v3, v2}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, v3}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p2, v1}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Landroid/os/Parcelable;
    :try_end_0
    .catch Loo/b; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    .line 23
    move-object v0, p1

    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto :goto_1

    .line 27
    :catch_0
    :try_start_1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lvp/g1;

    .line 30
    .line 31
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 32
    .line 33
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 37
    .line 38
    const-string p1, "Failed to load parcelable from buffer"

    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    .line 42
    .line 43
    :goto_0
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 44
    .line 45
    .line 46
    return-object v0

    .line 47
    :goto_1
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 48
    .line 49
    .line 50
    throw p0
.end method

.method public J0(Lcom/google/android/gms/internal/measurement/q5;Ljava/util/List;)Ljava/util/List;
    .locals 7

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 8
    .line 9
    .line 10
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-eqz p2, :cond_2

    .line 19
    .line 20
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    check-cast p2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-gez v1, :cond_0

    .line 31
    .line 32
    iget-object v1, p0, Lvp/g1;->i:Lvp/p0;

    .line 33
    .line 34
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 35
    .line 36
    .line 37
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 38
    .line 39
    const-string v2, "Ignoring negative bit index to be cleared"

    .line 40
    .line 41
    invoke-virtual {v1, p2, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    div-int/lit8 v1, v1, 0x40

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-lt v1, v2, :cond_1

    .line 56
    .line 57
    iget-object v1, p0, Lvp/g1;->i:Lvp/p0;

    .line 58
    .line 59
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 60
    .line 61
    .line 62
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    const-string v3, "Ignoring bit index greater than bitSet size"

    .line 73
    .line 74
    invoke-virtual {v1, p2, v2, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_1
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    check-cast v2, Ljava/lang/Long;

    .line 83
    .line 84
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 85
    .line 86
    .line 87
    move-result-wide v2

    .line 88
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 89
    .line 90
    .line 91
    move-result p2

    .line 92
    rem-int/lit8 p2, p2, 0x40

    .line 93
    .line 94
    const-wide/16 v4, 0x1

    .line 95
    .line 96
    shl-long/2addr v4, p2

    .line 97
    not-long v4, v4

    .line 98
    and-long/2addr v2, v4

    .line 99
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    invoke-virtual {v0, v1, p2}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 108
    .line 109
    .line 110
    move-result p0

    .line 111
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 112
    .line 113
    .line 114
    move-result p1

    .line 115
    add-int/lit8 p1, p1, -0x1

    .line 116
    .line 117
    :goto_1
    move v6, p1

    .line 118
    move p1, p0

    .line 119
    move p0, v6

    .line 120
    if-ltz p0, :cond_4

    .line 121
    .line 122
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    check-cast p2, Ljava/lang/Long;

    .line 127
    .line 128
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 129
    .line 130
    .line 131
    move-result-wide v1

    .line 132
    const-wide/16 v3, 0x0

    .line 133
    .line 134
    cmp-long p2, v1, v3

    .line 135
    .line 136
    if-eqz p2, :cond_3

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_3
    add-int/lit8 p1, p0, -0x1

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_4
    :goto_2
    const/4 p0, 0x0

    .line 143
    invoke-virtual {v0, p0, p1}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0
.end method

.method public K0(JJ)Z
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    if-eqz v2, :cond_1

    .line 6
    .line 7
    cmp-long v0, p3, v0

    .line 8
    .line 9
    if-lez v0, :cond_1

    .line 10
    .line 11
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lvp/g1;

    .line 14
    .line 15
    iget-object p0, p0, Lvp/g1;->n:Lto/a;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 21
    .line 22
    .line 23
    move-result-wide v0

    .line 24
    sub-long/2addr v0, p1

    .line 25
    invoke-static {v0, v1}, Ljava/lang/Math;->abs(J)J

    .line 26
    .line 27
    .line 28
    move-result-wide p0

    .line 29
    cmp-long p0, p0, p3

    .line 30
    .line 31
    if-lez p0, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 p0, 0x0

    .line 35
    return p0

    .line 36
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 37
    return p0
.end method

.method public L0([B)J
    .locals 1

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lvp/g1;

    .line 7
    .line 8
    iget-object v0, p0, Lvp/g1;->l:Lvp/d4;

    .line 9
    .line 10
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 14
    .line 15
    .line 16
    invoke-static {}, Lvp/d4;->r0()Ljava/security/MessageDigest;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 23
    .line 24
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 28
    .line 29
    const-string p1, "Failed to get MD5"

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-wide/16 p0, 0x0

    .line 35
    .line 36
    return-wide p0

    .line 37
    :cond_0
    invoke-virtual {v0, p1}, Ljava/security/MessageDigest;->digest([B)[B

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0}, Lvp/d4;->s0([B)J

    .line 42
    .line 43
    .line 44
    move-result-wide p0

    .line 45
    return-wide p0
.end method

.method public M0([B)[B
    .locals 2

    .line 1
    :try_start_0
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/util/zip/GZIPOutputStream;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Ljava/util/zip/GZIPOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v1, p1}, Ljava/io/OutputStream;->write([B)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/io/OutputStream;->close()V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->close()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 21
    .line 22
    .line 23
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    return-object p0

    .line 25
    :catch_0
    move-exception p1

    .line 26
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lvp/g1;

    .line 29
    .line 30
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 31
    .line 32
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 36
    .line 37
    const-string v0, "Failed to gzip content"

    .line 38
    .line 39
    invoke-virtual {p0, p1, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p1
.end method

.method public final d0()V
    .locals 0

    .line 1
    iget p0, p0, Lvp/s0;->h:I

    .line 2
    .line 3
    return-void
.end method

.method public k0(Ljava/lang/StringBuilder;ILcom/google/android/gms/internal/measurement/r5;)V
    .locals 5

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    goto/16 :goto_4

    .line 4
    .line 5
    :cond_0
    add-int/lit8 p2, p2, 0x1

    .line 6
    .line 7
    invoke-interface {p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p3

    .line 11
    :cond_1
    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_7

    .line 16
    .line 17
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lcom/google/android/gms/internal/measurement/e3;

    .line 22
    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-static {p2, p1}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 26
    .line 27
    .line 28
    const-string v1, "param {\n"

    .line 29
    .line 30
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->p()Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    const/4 v2, 0x0

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Lvp/g1;

    .line 43
    .line 44
    iget-object v1, v1, Lvp/g1;->m:Lvp/k0;

    .line 45
    .line 46
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-virtual {v1, v3}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    goto :goto_1

    .line 55
    :cond_2
    move-object v1, v2

    .line 56
    :goto_1
    const-string v3, "name"

    .line 57
    .line 58
    invoke-static {p1, p2, v3, v1}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->r()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->s()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    goto :goto_2

    .line 72
    :cond_3
    move-object v1, v2

    .line 73
    :goto_2
    const-string v3, "string_value"

    .line 74
    .line 75
    invoke-static {p1, p2, v3, v1}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->t()Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_4

    .line 83
    .line 84
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->u()J

    .line 85
    .line 86
    .line 87
    move-result-wide v3

    .line 88
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    goto :goto_3

    .line 93
    :cond_4
    move-object v1, v2

    .line 94
    :goto_3
    const-string v3, "int_value"

    .line 95
    .line 96
    invoke-static {p1, p2, v3, v1}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->x()Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-eqz v1, :cond_5

    .line 104
    .line 105
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->y()D

    .line 106
    .line 107
    .line 108
    move-result-wide v1

    .line 109
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    :cond_5
    const-string v1, "double_value"

    .line 114
    .line 115
    invoke-static {p1, p2, v1, v2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->A()I

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-lez v1, :cond_6

    .line 123
    .line 124
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/e3;->z()Ljava/util/List;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    check-cast v0, Lcom/google/android/gms/internal/measurement/r5;

    .line 129
    .line 130
    invoke-virtual {p0, p1, p2, v0}, Lvp/s0;->k0(Ljava/lang/StringBuilder;ILcom/google/android/gms/internal/measurement/r5;)V

    .line 131
    .line 132
    .line 133
    :cond_6
    invoke-static {p2, p1}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 134
    .line 135
    .line 136
    const-string v0, "}\n"

    .line 137
    .line 138
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    goto/16 :goto_0

    .line 142
    .line 143
    :cond_7
    :goto_4
    return-void
.end method

.method public l0(Ljava/lang/StringBuilder;ILcom/google/android/gms/internal/measurement/q1;)V
    .locals 4

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p2, p1}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 5
    .line 6
    .line 7
    const-string v0, "filter {\n"

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/q1;->t()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/q1;->u()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    const-string v1, "complement"

    .line 27
    .line 28
    invoke-static {p1, p2, v1, v0}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    :cond_1
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/q1;->v()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Lvp/g1;

    .line 40
    .line 41
    iget-object p0, p0, Lvp/g1;->m:Lvp/k0;

    .line 42
    .line 43
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/q1;->w()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {p0, v0}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string v0, "param_name"

    .line 52
    .line 53
    invoke-static {p1, p2, v0, p0}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_2
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/q1;->p()Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    const-string v0, "}\n"

    .line 61
    .line 62
    if-eqz p0, :cond_9

    .line 63
    .line 64
    add-int/lit8 p0, p2, 0x1

    .line 65
    .line 66
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/q1;->q()Lcom/google/android/gms/internal/measurement/w1;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    if-nez v1, :cond_3

    .line 71
    .line 72
    goto/16 :goto_2

    .line 73
    .line 74
    :cond_3
    invoke-static {p0, p1}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 75
    .line 76
    .line 77
    const-string v2, "string_filter {\n"

    .line 78
    .line 79
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/w1;->p()Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-eqz v2, :cond_4

    .line 87
    .line 88
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/w1;->x()I

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    packed-switch v2, :pswitch_data_0

    .line 93
    .line 94
    .line 95
    const-string v2, "IN_LIST"

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :pswitch_0
    const-string v2, "EXACT"

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :pswitch_1
    const-string v2, "PARTIAL"

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :pswitch_2
    const-string v2, "ENDS_WITH"

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_3
    const-string v2, "BEGINS_WITH"

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :pswitch_4
    const-string v2, "REGEXP"

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :pswitch_5
    const-string v2, "UNKNOWN_MATCH_TYPE"

    .line 114
    .line 115
    :goto_0
    const-string v3, "match_type"

    .line 116
    .line 117
    invoke-static {p1, p0, v3, v2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_4
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/w1;->q()Z

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    if-eqz v2, :cond_5

    .line 125
    .line 126
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/w1;->r()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    const-string v3, "expression"

    .line 131
    .line 132
    invoke-static {p1, p0, v3, v2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :cond_5
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/w1;->s()Z

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    if-eqz v2, :cond_6

    .line 140
    .line 141
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/w1;->t()Z

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    const-string v3, "case_sensitive"

    .line 150
    .line 151
    invoke-static {p1, p0, v3, v2}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    :cond_6
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/w1;->v()I

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    if-lez v2, :cond_8

    .line 159
    .line 160
    add-int/lit8 v2, p2, 0x2

    .line 161
    .line 162
    invoke-static {v2, p1}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 163
    .line 164
    .line 165
    const-string v2, "expression_list {\n"

    .line 166
    .line 167
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/w1;->u()Lcom/google/android/gms/internal/measurement/r5;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 175
    .line 176
    .line 177
    move-result-object v1

    .line 178
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    if-eqz v2, :cond_7

    .line 183
    .line 184
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v2

    .line 188
    check-cast v2, Ljava/lang/String;

    .line 189
    .line 190
    add-int/lit8 v3, p2, 0x3

    .line 191
    .line 192
    invoke-static {v3, p1}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    const-string v2, "\n"

    .line 199
    .line 200
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    goto :goto_1

    .line 204
    :cond_7
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 205
    .line 206
    .line 207
    :cond_8
    invoke-static {p0, p1}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 211
    .line 212
    .line 213
    :cond_9
    :goto_2
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/q1;->r()Z

    .line 214
    .line 215
    .line 216
    move-result p0

    .line 217
    if-eqz p0, :cond_a

    .line 218
    .line 219
    add-int/lit8 p0, p2, 0x1

    .line 220
    .line 221
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/q1;->s()Lcom/google/android/gms/internal/measurement/t1;

    .line 222
    .line 223
    .line 224
    move-result-object p3

    .line 225
    const-string v1, "number_filter"

    .line 226
    .line 227
    invoke-static {p1, p0, v1, p3}, Lvp/s0;->t0(Ljava/lang/StringBuilder;ILjava/lang/String;Lcom/google/android/gms/internal/measurement/t1;)V

    .line 228
    .line 229
    .line 230
    :cond_a
    invoke-static {p2, p1}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 234
    .line 235
    .line 236
    return-void

    .line 237
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public u0()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lvp/g1;

    .line 7
    .line 8
    iget-object p0, p0, Lvp/g1;->d:Landroid/content/Context;

    .line 9
    .line 10
    const-string v0, "connectivity"

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Landroid/net/ConnectivityManager;

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    :try_start_0
    invoke-virtual {p0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    .line 22
    .line 23
    .line 24
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    :catch_0
    :cond_0
    if-eqz v0, :cond_1

    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/net/NetworkInfo;->isConnected()Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_1
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public y0(Lcom/google/android/gms/internal/measurement/r3;Ljava/lang/Object;)V
    .locals 2

    .line 1
    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 8
    .line 9
    check-cast v0, Lcom/google/android/gms/internal/measurement/s3;

    .line 10
    .line 11
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/s3;->E()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 15
    .line 16
    .line 17
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 18
    .line 19
    check-cast v0, Lcom/google/android/gms/internal/measurement/s3;

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/s3;->G()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 25
    .line 26
    .line 27
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 28
    .line 29
    check-cast v0, Lcom/google/android/gms/internal/measurement/s3;

    .line 30
    .line 31
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/s3;->I()V

    .line 32
    .line 33
    .line 34
    instance-of v0, p2, Ljava/lang/String;

    .line 35
    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    check-cast p2, Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 41
    .line 42
    .line 43
    iget-object p0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 44
    .line 45
    check-cast p0, Lcom/google/android/gms/internal/measurement/s3;

    .line 46
    .line 47
    invoke-virtual {p0, p2}, Lcom/google/android/gms/internal/measurement/s3;->D(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_0
    instance-of v0, p2, Ljava/lang/Long;

    .line 52
    .line 53
    if-eqz v0, :cond_1

    .line 54
    .line 55
    check-cast p2, Ljava/lang/Long;

    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 58
    .line 59
    .line 60
    move-result-wide v0

    .line 61
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 62
    .line 63
    .line 64
    iget-object p0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 65
    .line 66
    check-cast p0, Lcom/google/android/gms/internal/measurement/s3;

    .line 67
    .line 68
    invoke-virtual {p0, v0, v1}, Lcom/google/android/gms/internal/measurement/s3;->F(J)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :cond_1
    instance-of v0, p2, Ljava/lang/Double;

    .line 73
    .line 74
    if-eqz v0, :cond_2

    .line 75
    .line 76
    check-cast p2, Ljava/lang/Double;

    .line 77
    .line 78
    invoke-virtual {p2}, Ljava/lang/Double;->doubleValue()D

    .line 79
    .line 80
    .line 81
    move-result-wide v0

    .line 82
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 83
    .line 84
    .line 85
    iget-object p0, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 86
    .line 87
    check-cast p0, Lcom/google/android/gms/internal/measurement/s3;

    .line 88
    .line 89
    invoke-virtual {p0, v0, v1}, Lcom/google/android/gms/internal/measurement/s3;->H(D)V

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :cond_2
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p0, Lvp/g1;

    .line 96
    .line 97
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 98
    .line 99
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 100
    .line 101
    .line 102
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 103
    .line 104
    const-string p1, "Ignoring invalid (type) user attribute value"

    .line 105
    .line 106
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    return-void
.end method

.method public z0(Ljava/lang/String;Lvp/v3;Lcom/google/android/gms/internal/measurement/h3;Lvp/q0;)V
    .locals 10

    .line 1
    iget-object v0, p2, Lvp/v3;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lvp/g1;

    .line 6
    .line 7
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 11
    .line 12
    .line 13
    :try_start_0
    new-instance v2, Ljava/net/URI;

    .line 14
    .line 15
    invoke-direct {v2, v0}, Ljava/net/URI;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/net/URI;->toURL()Ljava/net/URL;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    iget-object v2, p0, Lvp/q3;->f:Lvp/z3;

    .line 23
    .line 24
    invoke-virtual {v2}, Lvp/z3;->i0()Lvp/s0;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    iget-object p3, v1, Lvp/g1;->j:Lvp/e1;

    .line 32
    .line 33
    invoke-static {p3}, Lvp/g1;->k(Lvp/n1;)V

    .line 34
    .line 35
    .line 36
    new-instance v3, Lvp/r0;

    .line 37
    .line 38
    iget-object p2, p2, Lvp/v3;->b:Ljava/util/Map;

    .line 39
    .line 40
    if-nez p2, :cond_0

    .line 41
    .line 42
    sget-object p2, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/net/MalformedURLException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/net/URISyntaxException; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    :cond_0
    move-object v4, p0

    .line 45
    move-object v5, p1

    .line 46
    move-object v8, p2

    .line 47
    move-object v9, p4

    .line 48
    :try_start_1
    invoke-direct/range {v3 .. v9}, Lvp/r0;-><init>(Lvp/s0;Ljava/lang/String;Ljava/net/URL;[BLjava/util/Map;Lvp/q0;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p3, v3}, Lvp/e1;->m0(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/net/MalformedURLException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/net/URISyntaxException; {:try_start_1 .. :try_end_1} :catch_1

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :catch_0
    move-object v5, p1

    .line 56
    :catch_1
    iget-object p0, v1, Lvp/g1;->i:Lvp/p0;

    .line 57
    .line 58
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 59
    .line 60
    .line 61
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 62
    .line 63
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    const-string p2, "Failed to parse URL. Not uploading MeasurementBatch. appId"

    .line 68
    .line 69
    invoke-virtual {p0, p1, v0, p2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    return-void
.end method

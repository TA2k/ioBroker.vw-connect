.class public final Lu/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/z;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Lv/b;

.field public final c:Lbu/c;

.field public final d:Ljava/lang/Object;

.field public e:Lu/m;

.field public final f:Li0/e;

.field public g:Ljava/util/ArrayList;

.field public final h:Ld01/x;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lv/d;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lu/z;->d:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lu/z;->g:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lu/z;->a:Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {p2, p1}, Lv/d;->a(Ljava/lang/String;)Lv/b;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    iput-object p2, p0, Lu/z;->b:Lv/b;

    .line 24
    .line 25
    new-instance v1, Lbu/c;

    .line 26
    .line 27
    const/4 v2, 0x1

    .line 28
    invoke-direct {v1, v2}, Lbu/c;-><init>(I)V

    .line 29
    .line 30
    .line 31
    iput-object p0, v1, Lbu/c;->e:Ljava/lang/Object;

    .line 32
    .line 33
    iput-object v1, p0, Lu/z;->c:Lbu/c;

    .line 34
    .line 35
    invoke-static {p2}, Llp/zd;->a(Lv/b;)Ld01/x;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    iput-object p2, p0, Lu/z;->h:Ld01/x;

    .line 40
    .line 41
    new-instance p2, Ljava/util/HashMap;

    .line 42
    .line 43
    invoke-direct {p2}, Ljava/util/HashMap;-><init>()V

    .line 44
    .line 45
    .line 46
    :try_start_0
    invoke-static {p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catch_0
    new-instance p2, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v1, "Camera id is not an integer: "

    .line 53
    .line 54
    invoke-direct {p2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string p1, ", unable to create Camera2EncoderProfilesProvider"

    .line 61
    .line 62
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    const-string p2, "Camera2EncoderProfilesProvider"

    .line 70
    .line 71
    invoke-static {p2, p1}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    :goto_0
    new-instance p1, Li0/e;

    .line 75
    .line 76
    new-instance p2, Lb0/d;

    .line 77
    .line 78
    const/4 v1, 0x5

    .line 79
    invoke-direct {p2, v1, v0}, Lb0/d;-><init>(ILb0/e;)V

    .line 80
    .line 81
    .line 82
    invoke-direct {p1, p2}, Li0/e;-><init>(Lb0/d;)V

    .line 83
    .line 84
    .line 85
    iput-object p1, p0, Lu/z;->f:Li0/e;

    .line 86
    .line 87
    return-void
.end method


# virtual methods
.method public final a(Lu/m;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lu/z;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iput-object p1, p0, Lu/z;->e:Lu/m;

    .line 5
    .line 6
    iget-object p1, p0, Lu/z;->g:Ljava/util/ArrayList;

    .line 7
    .line 8
    if-eqz p1, :cond_1

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

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
    move-result v1

    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Landroid/util/Pair;

    .line 25
    .line 26
    iget-object v2, p0, Lu/z;->e:Lu/m;

    .line 27
    .line 28
    iget-object v3, v1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v3, Ljava/util/concurrent/Executor;

    .line 31
    .line 32
    iget-object v1, v1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lh0/m;

    .line 35
    .line 36
    iget-object v4, v2, Lu/m;->c:Lj0/h;

    .line 37
    .line 38
    new-instance v5, La8/y0;

    .line 39
    .line 40
    const/16 v6, 0x15

    .line 41
    .line 42
    invoke-direct {v5, v2, v3, v1, v6}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v4, v5}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    goto :goto_2

    .line 51
    :cond_0
    const/4 p1, 0x0

    .line 52
    iput-object p1, p0, Lu/z;->g:Ljava/util/ArrayList;

    .line 53
    .line 54
    :cond_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 56
    .line 57
    sget-object p1, Landroid/hardware/camera2/CameraCharacteristics;->INFO_SUPPORTED_HARDWARE_LEVEL:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 58
    .line 59
    invoke-virtual {p0, p1}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Ljava/lang/Integer;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-eqz p0, :cond_6

    .line 73
    .line 74
    const/4 p1, 0x1

    .line 75
    if-eq p0, p1, :cond_5

    .line 76
    .line 77
    const/4 p1, 0x2

    .line 78
    if-eq p0, p1, :cond_4

    .line 79
    .line 80
    const/4 p1, 0x3

    .line 81
    if-eq p0, p1, :cond_3

    .line 82
    .line 83
    const/4 p1, 0x4

    .line 84
    if-eq p0, p1, :cond_2

    .line 85
    .line 86
    const-string p1, "Unknown value: "

    .line 87
    .line 88
    invoke-static {p0, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    goto :goto_1

    .line 93
    :cond_2
    const-string p0, "INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL"

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_3
    const-string p0, "INFO_SUPPORTED_HARDWARE_LEVEL_3"

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_4
    const-string p0, "INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY"

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_5
    const-string p0, "INFO_SUPPORTED_HARDWARE_LEVEL_FULL"

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_6
    const-string p0, "INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED"

    .line 106
    .line 107
    :goto_1
    const-string p1, "Camera2CameraInfo"

    .line 108
    .line 109
    new-instance v0, Ljava/lang/StringBuilder;

    .line 110
    .line 111
    const-string v1, "Device Level: "

    .line 112
    .line 113
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-static {p1, p0}, Ljp/v1;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    return-void

    .line 127
    :goto_2
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 128
    throw p0
.end method

.method public final c()Landroidx/lifecycle/g0;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/z;->f:Li0/e;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d()Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 2
    .line 3
    invoke-static {p0}, Lpv/g;->d(Lv/b;)Lpv/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lw/b;

    .line 10
    .line 11
    invoke-interface {p0}, Lw/b;->d()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final e()I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lu/z;->r(I)I

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public final f()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/z;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final g()Landroid/graphics/Rect;
    .locals 3

    .line 1
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 2
    .line 3
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->SENSOR_INFO_ACTIVE_ARRAY_SIZE:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Landroid/graphics/Rect;

    .line 10
    .line 11
    const-string v0, "robolectric"

    .line 12
    .line 13
    sget-object v1, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    new-instance p0, Landroid/graphics/Rect;

    .line 24
    .line 25
    const/16 v0, 0xfa0

    .line 26
    .line 27
    const/16 v1, 0xbb8

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    invoke-direct {p0, v2, v2, v0, v1}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 31
    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    return-object p0
.end method

.method public final h()I
    .locals 4

    .line 1
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 2
    .line 3
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->LENS_FACING:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljava/lang/Integer;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    const/4 v1, 0x1

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    move v2, v1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v2, v0

    .line 18
    :goto_0
    const-string v3, "Unable to get the lens facing of the camera."

    .line 19
    .line 20
    invoke-static {v2, v3}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_3

    .line 28
    .line 29
    if-eq p0, v1, :cond_2

    .line 30
    .line 31
    const/4 v0, 0x2

    .line 32
    if-ne p0, v0, :cond_1

    .line 33
    .line 34
    return v0

    .line 35
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 36
    .line 37
    const-string v1, "The given lens facing integer: "

    .line 38
    .line 39
    const-string v2, " can not be recognized."

    .line 40
    .line 41
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw v0

    .line 49
    :cond_2
    return v1

    .line 50
    :cond_3
    return v0
.end method

.method public final i()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 2
    .line 3
    iget-object p0, p0, Lv/b;->b:Lpv/g;

    .line 4
    .line 5
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroid/hardware/camera2/CameraCharacteristics;

    .line 8
    .line 9
    return-object p0
.end method

.method public final j()Ld01/x;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/z;->h:Ld01/x;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k(I)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv/b;->c()Lrn/i;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0, p1}, Lrn/i;->t(I)[Landroid/util/Size;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 19
    .line 20
    return-object p0
.end method

.method public final l(Ljava/util/concurrent/Executor;Lu/j;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lu/z;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lu/z;->e:Lu/m;

    .line 5
    .line 6
    if-nez v1, :cond_1

    .line 7
    .line 8
    iget-object v1, p0, Lu/z;->g:Ljava/util/ArrayList;

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    new-instance v1, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v1, p0, Lu/z;->g:Ljava/util/ArrayList;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    :goto_0
    iget-object p0, p0, Lu/z;->g:Ljava/util/ArrayList;

    .line 23
    .line 24
    new-instance v1, Landroid/util/Pair;

    .line 25
    .line 26
    invoke-direct {v1, p2, p1}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    monitor-exit v0

    .line 33
    return-void

    .line 34
    :cond_1
    iget-object p0, v1, Lu/m;->c:Lj0/h;

    .line 35
    .line 36
    new-instance v2, La8/y0;

    .line 37
    .line 38
    const/16 v3, 0x15

    .line 39
    .line 40
    invoke-direct {v2, v1, p1, p2, v3}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, v2}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 44
    .line 45
    .line 46
    monitor-exit v0

    .line 47
    return-void

    .line 48
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    throw p0
.end method

.method public final m()Ljava/util/Set;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 7
    .line 8
    sget-object v1, Landroid/hardware/camera2/CameraCharacteristics;->REQUEST_AVAILABLE_CAPABILITIES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 9
    .line 10
    invoke-virtual {p0, v1}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, [I

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    array-length v1, p0

    .line 19
    const/4 v2, 0x0

    .line 20
    :goto_0
    if-ge v2, v1, :cond_0

    .line 21
    .line 22
    aget v3, p0, v2

    .line 23
    .line 24
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v0, v3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    add-int/lit8 v2, v2, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    return-object v0
.end method

.method public final p(Lh0/m;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lu/z;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lu/z;->e:Lu/m;

    .line 5
    .line 6
    if-nez v1, :cond_3

    .line 7
    .line 8
    iget-object p0, p0, Lu/z;->g:Ljava/util/ArrayList;

    .line 9
    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_2

    .line 25
    .line 26
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Landroid/util/Pair;

    .line 31
    .line 32
    iget-object v1, v1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 33
    .line 34
    if-ne v1, p1, :cond_1

    .line 35
    .line 36
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    monitor-exit v0

    .line 41
    return-void

    .line 42
    :cond_3
    iget-object p0, v1, Lu/m;->c:Lj0/h;

    .line 43
    .line 44
    new-instance v2, Lno/nordicsemi/android/ble/o0;

    .line 45
    .line 46
    const/16 v3, 0xc

    .line 47
    .line 48
    invoke-direct {v2, v3, v1, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, v2}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 52
    .line 53
    .line 54
    monitor-exit v0

    .line 55
    return-void

    .line 56
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 57
    throw p0
.end method

.method public final q()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 2
    .line 3
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->INFO_SUPPORTED_HARDWARE_LEVEL:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    const/4 v0, 0x2

    .line 19
    if-ne p0, v0, :cond_0

    .line 20
    .line 21
    const-string p0, "androidx.camera.camera2.legacy"

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    const-string p0, "androidx.camera.camera2"

    .line 25
    .line 26
    return-object p0
.end method

.method public final r(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lu/z;->b:Lv/b;

    .line 2
    .line 3
    sget-object v1, Landroid/hardware/camera2/CameraCharacteristics;->SENSOR_ORIENTATION:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-static {p1}, Llp/h1;->c(I)I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    invoke-virtual {p0}, Lu/z;->h()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    const/4 v1, 0x1

    .line 27
    if-ne v1, p0, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v1, 0x0

    .line 31
    :goto_0
    invoke-static {p1, v0, v1}, Llp/h1;->b(IIZ)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method

.method public final s()Ljava/util/Set;
    .locals 4

    .line 1
    iget-object p0, p0, Lu/z;->b:Lv/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv/b;->c()Lrn/i;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lro/f;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    :try_start_0
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getOutputFormats()[I

    .line 20
    .line 21
    .line 22
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    goto :goto_0

    .line 24
    :catch_0
    move-exception p0

    .line 25
    const-string v1, "StreamConfigurationMapCompatBaseImpl"

    .line 26
    .line 27
    const-string v2, "Failed to get output formats from StreamConfigurationMap"

    .line 28
    .line 29
    invoke-static {v1, v2, p0}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 30
    .line 31
    .line 32
    move-object p0, v0

    .line 33
    :goto_0
    if-nez p0, :cond_0

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_0
    invoke-virtual {p0}, [I->clone()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    move-object v0, p0

    .line 41
    check-cast v0, [I

    .line 42
    .line 43
    :goto_1
    if-nez v0, :cond_1

    .line 44
    .line 45
    new-instance p0, Ljava/util/HashSet;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :cond_1
    new-instance p0, Ljava/util/HashSet;

    .line 52
    .line 53
    invoke-direct {p0}, Ljava/util/HashSet;-><init>()V

    .line 54
    .line 55
    .line 56
    array-length v1, v0

    .line 57
    const/4 v2, 0x0

    .line 58
    :goto_2
    if-ge v2, v1, :cond_2

    .line 59
    .line 60
    aget v3, v0, v2

    .line 61
    .line 62
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-virtual {p0, v3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    add-int/lit8 v2, v2, 0x1

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_2
    return-object p0
.end method

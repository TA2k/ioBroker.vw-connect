.class public final Lu/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/util/ArrayList;

.field public final c:Lu/o0;

.field public d:Lu/g1;

.field public e:Lu/g1;

.field public f:Lh0/z1;

.field public final g:Ljava/util/HashMap;

.field public h:Ljava/util/List;

.field public i:I

.field public j:I

.field public k:Ly4/k;

.field public l:Ly4/h;

.field public m:Ljava/util/HashMap;

.field public final n:La8/t1;

.field public final o:La8/t1;

.field public final p:Lb6/f;

.field public final q:Lpv/g;

.field public final r:Lk1/c0;

.field public final s:Z


# direct methods
.method public constructor <init>(Lpv/g;Ld01/x;Z)V
    .locals 2

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
    iput-object v0, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lu/p0;->b:Ljava/util/ArrayList;

    .line 17
    .line 18
    new-instance v0, Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lu/p0;->g:Ljava/util/HashMap;

    .line 24
    .line 25
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 26
    .line 27
    iput-object v0, p0, Lu/p0;->h:Ljava/util/List;

    .line 28
    .line 29
    const/4 v0, 0x1

    .line 30
    iput v0, p0, Lu/p0;->i:I

    .line 31
    .line 32
    iput v0, p0, Lu/p0;->j:I

    .line 33
    .line 34
    new-instance v0, Ljava/util/HashMap;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lu/p0;->m:Ljava/util/HashMap;

    .line 40
    .line 41
    new-instance v0, La8/t1;

    .line 42
    .line 43
    const/4 v1, 0x6

    .line 44
    invoke-direct {v0, v1}, La8/t1;-><init>(I)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Lu/p0;->n:La8/t1;

    .line 48
    .line 49
    new-instance v0, La8/t1;

    .line 50
    .line 51
    const/4 v1, 0x7

    .line 52
    invoke-direct {v0, v1}, La8/t1;-><init>(I)V

    .line 53
    .line 54
    .line 55
    iput-object v0, p0, Lu/p0;->o:La8/t1;

    .line 56
    .line 57
    const/4 v0, 0x3

    .line 58
    invoke-virtual {p0, v0}, Lu/p0;->p(I)V

    .line 59
    .line 60
    .line 61
    iput-object p1, p0, Lu/p0;->q:Lpv/g;

    .line 62
    .line 63
    new-instance p1, Lu/o0;

    .line 64
    .line 65
    invoke-direct {p1, p0}, Lu/o0;-><init>(Lu/p0;)V

    .line 66
    .line 67
    .line 68
    iput-object p1, p0, Lu/p0;->c:Lu/o0;

    .line 69
    .line 70
    new-instance p1, Lb6/f;

    .line 71
    .line 72
    const-class v0, Landroidx/camera/camera2/internal/compat/quirk/CaptureNoResponseQuirk;

    .line 73
    .line 74
    invoke-virtual {p2, v0}, Ld01/x;->k(Ljava/lang/Class;)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    invoke-direct {p1, v0}, Lb6/f;-><init>(Z)V

    .line 79
    .line 80
    .line 81
    iput-object p1, p0, Lu/p0;->p:Lb6/f;

    .line 82
    .line 83
    new-instance p1, Lk1/c0;

    .line 84
    .line 85
    const/4 v0, 0x2

    .line 86
    invoke-direct {p1, p2, v0}, Lk1/c0;-><init>(Ld01/x;I)V

    .line 87
    .line 88
    .line 89
    iput-object p1, p0, Lu/p0;->r:Lk1/c0;

    .line 90
    .line 91
    iput-boolean p3, p0, Lu/p0;->s:Z

    .line 92
    .line 93
    return-void
.end method

.method public static varargs c(Ljava/util/List;[Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)Lu/a0;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    array-length v2, p1

    .line 8
    add-int/2addr v1, v2

    .line 9
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_2

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Lh0/m;

    .line 27
    .line 28
    if-nez v1, :cond_0

    .line 29
    .line 30
    const/4 v1, 0x0

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    new-instance v2, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 35
    .line 36
    .line 37
    invoke-static {v1, v2}, Llp/a1;->a(Lh0/m;Ljava/util/ArrayList;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    const/4 v3, 0x1

    .line 45
    if-ne v1, v3, :cond_1

    .line 46
    .line 47
    const/4 v1, 0x0

    .line 48
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    check-cast v1, Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_1
    new-instance v1, Lu/a0;

    .line 56
    .line 57
    invoke-direct {v1, v2}, Lu/a0;-><init>(Ljava/util/List;)V

    .line 58
    .line 59
    .line 60
    :goto_1
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_2
    invoke-static {v0, p1}, Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    new-instance p0, Lu/a0;

    .line 68
    .line 69
    invoke-direct {p0, v0}, Lu/a0;-><init>(Ljava/util/List;)V

    .line 70
    .line 71
    .line 72
    return-object p0
.end method

.method public static d(Ljava/util/HashMap;Ljava/util/HashMap;)Ljava/util/HashMap;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

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
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_1

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    new-instance v3, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Ljava/util/List;

    .line 39
    .line 40
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-nez v4, :cond_0

    .line 49
    .line 50
    new-instance v2, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v4, "Skips to create instances for multi-resolution output. imageFormat: 0, streamInfos size: "

    .line 53
    .line 54
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    const-string v3, "CaptureSession"

    .line 69
    .line 70
    invoke-static {v3, v2}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_0
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    check-cast p0, Lh0/i;

    .line 79
    .line 80
    iget-object p0, p0, Lh0/i;->a:Lh0/t0;

    .line 81
    .line 82
    invoke-virtual {p1, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    check-cast p0, Landroid/view/Surface;

    .line 87
    .line 88
    invoke-static {p0}, Landroidx/camera/core/impl/utils/SurfaceUtil;->a(Landroid/view/Surface;)Ldv/a;

    .line 89
    .line 90
    .line 91
    invoke-static {}, Lu/m0;->b()V

    .line 92
    .line 93
    .line 94
    const/4 p0, 0x0

    .line 95
    throw p0

    .line 96
    :cond_1
    return-object v0
.end method

.method public static g(Ljava/util/ArrayList;)Ljava/util/ArrayList;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Lw/h;

    .line 26
    .line 27
    iget-object v3, v2, Lw/h;->a:Lw/j;

    .line 28
    .line 29
    invoke-virtual {v3}, Lw/j;->b()Landroid/view/Surface;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    iget-object v3, v2, Lw/h;->a:Lw/j;

    .line 41
    .line 42
    invoke-virtual {v3}, Lw/j;->b()Landroid/view/Surface;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    return-object v1
.end method

.method public static h(Ljava/util/ArrayList;)Ljava/util/HashMap;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

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
    if-eqz v1, :cond_3

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lh0/i;

    .line 21
    .line 22
    iget v2, v1, Lh0/i;->d:I

    .line 23
    .line 24
    if-lez v2, :cond_0

    .line 25
    .line 26
    iget-object v3, v1, Lh0/i;->b:Ljava/util/List;

    .line 27
    .line 28
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-nez v3, :cond_1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {v0, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    check-cast v3, Ljava/util/List;

    .line 44
    .line 45
    if-nez v3, :cond_2

    .line 46
    .line 47
    new-instance v3, Ljava/util/ArrayList;

    .line 48
    .line 49
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 50
    .line 51
    .line 52
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    invoke-virtual {v0, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    :cond_2
    invoke-interface {v3, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_3
    new-instance p0, Ljava/util/HashMap;

    .line 64
    .line 65
    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    :cond_4
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-eqz v2, :cond_5

    .line 81
    .line 82
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    check-cast v2, Ljava/lang/Integer;

    .line 87
    .line 88
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    check-cast v3, Ljava/util/List;

    .line 96
    .line 97
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    const/4 v4, 0x2

    .line 102
    if-lt v3, v4, :cond_4

    .line 103
    .line 104
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    check-cast v3, Ljava/util/List;

    .line 109
    .line 110
    invoke-virtual {p0, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_5
    return-object p0
.end method


# virtual methods
.method public final a(Ljava/util/ArrayList;Lu/k;)I
    .locals 6

    .line 1
    new-instance v0, Lu/k;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lu/k;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    const/4 v1, -0x1

    .line 12
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_2

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Landroid/hardware/camera2/CaptureRequest;

    .line 23
    .line 24
    iget-object v2, p0, Lu/p0;->e:Lu/g1;

    .line 25
    .line 26
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    iget-object v2, v2, Lu/g1;->f:Lro/f;

    .line 30
    .line 31
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    iget-object v2, v2, Lro/f;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v2, Lb81/c;

    .line 37
    .line 38
    iget-object v2, v2, Lb81/c;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v2, Landroid/hardware/camera2/CameraCaptureSession;

    .line 41
    .line 42
    instance-of v3, v2, Landroid/hardware/camera2/CameraConstrainedHighSpeedCaptureSession;

    .line 43
    .line 44
    if-eqz v3, :cond_0

    .line 45
    .line 46
    check-cast v2, Landroid/hardware/camera2/CameraConstrainedHighSpeedCaptureSession;

    .line 47
    .line 48
    invoke-virtual {v2, v1}, Landroid/hardware/camera2/CameraConstrainedHighSpeedCaptureSession;->createHighSpeedRequestList(Landroid/hardware/camera2/CaptureRequest;)Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    goto :goto_1

    .line 53
    :cond_0
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 54
    .line 55
    :goto_1
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    if-eqz v4, :cond_1

    .line 64
    .line 65
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    check-cast v4, Landroid/hardware/camera2/CaptureRequest;

    .line 70
    .line 71
    new-instance v5, Lu/z0;

    .line 72
    .line 73
    invoke-direct {v5, v1, p2}, Lu/z0;-><init>(Landroid/hardware/camera2/CaptureRequest;Lu/k;)V

    .line 74
    .line 75
    .line 76
    invoke-static {v5}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 77
    .line 78
    .line 79
    move-result-object v5

    .line 80
    invoke-virtual {v0, v4, v5}, Lu/k;->a(Landroid/hardware/camera2/CaptureRequest;Ljava/util/List;)V

    .line 81
    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_1
    iget-object v1, p0, Lu/p0;->e:Lu/g1;

    .line 85
    .line 86
    iget-object v3, v1, Lu/g1;->t:Lb6/f;

    .line 87
    .line 88
    invoke-virtual {v3, v0}, Lb6/f;->k(Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    iget-object v4, v1, Lu/g1;->f:Lro/f;

    .line 93
    .line 94
    const-string v5, "Need to call openCaptureSession before using this API."

    .line 95
    .line 96
    invoke-static {v4, v5}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    iget-object v4, v1, Lu/g1;->f:Lro/f;

    .line 100
    .line 101
    iget-object v1, v1, Lu/g1;->c:Lj0/h;

    .line 102
    .line 103
    iget-object v4, v4, Lro/f;->e:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v4, Lb81/c;

    .line 106
    .line 107
    iget-object v4, v4, Lb81/c;->e:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v4, Landroid/hardware/camera2/CameraCaptureSession;

    .line 110
    .line 111
    invoke-virtual {v4, v2, v1, v3}, Landroid/hardware/camera2/CameraCaptureSession;->captureBurstRequests(Ljava/util/List;Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    goto :goto_0

    .line 116
    :cond_2
    return v1
.end method

.method public final b()V
    .locals 6

    .line 1
    const-string v0, "close() should not be possible in state: "

    .line 2
    .line 3
    const-string v1, "The Opener shouldn\'t null in state:"

    .line 4
    .line 5
    const-string v2, "The Opener shouldn\'t null in state:"

    .line 6
    .line 7
    iget-object v3, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v3

    .line 10
    :try_start_0
    iget v4, p0, Lu/p0;->j:I

    .line 11
    .line 12
    invoke-static {v4}, Lu/w;->o(I)I

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    if-eqz v4, :cond_3

    .line 17
    .line 18
    const/4 v0, 0x2

    .line 19
    if-eq v4, v0, :cond_2

    .line 20
    .line 21
    const/4 v5, 0x3

    .line 22
    if-eq v4, v5, :cond_1

    .line 23
    .line 24
    const/4 v0, 0x6

    .line 25
    if-eq v4, v0, :cond_0

    .line 26
    .line 27
    const/4 v1, 0x7

    .line 28
    if-eq v4, v1, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object v1, p0, Lu/p0;->d:Lu/g1;

    .line 32
    .line 33
    iget v4, p0, Lu/p0;->j:I

    .line 34
    .line 35
    invoke-static {v4}, Lu/w;->q(I)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    invoke-virtual {v2, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    invoke-static {v1, v2}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lu/p0;->d:Lu/g1;

    .line 47
    .line 48
    invoke-virtual {v1}, Lu/g1;->q()Z

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, v0}, Lu/p0;->p(I)V

    .line 52
    .line 53
    .line 54
    iget-object v0, p0, Lu/p0;->p:Lb6/f;

    .line 55
    .line 56
    invoke-virtual {v0}, Lb6/f;->x()V

    .line 57
    .line 58
    .line 59
    const/4 v0, 0x0

    .line 60
    iput-object v0, p0, Lu/p0;->f:Lh0/z1;

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :catchall_0
    move-exception p0

    .line 64
    goto :goto_1

    .line 65
    :cond_1
    iget-object v2, p0, Lu/p0;->d:Lu/g1;

    .line 66
    .line 67
    iget v4, p0, Lu/p0;->j:I

    .line 68
    .line 69
    invoke-static {v4}, Lu/w;->q(I)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    invoke-virtual {v1, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    invoke-static {v2, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    iget-object v1, p0, Lu/p0;->d:Lu/g1;

    .line 81
    .line 82
    invoke-virtual {v1}, Lu/g1;->q()Z

    .line 83
    .line 84
    .line 85
    :cond_2
    invoke-virtual {p0, v0}, Lu/p0;->p(I)V

    .line 86
    .line 87
    .line 88
    :goto_0
    monitor-exit v3

    .line 89
    return-void

    .line 90
    :cond_3
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    iget p0, p0, Lu/p0;->j:I

    .line 93
    .line 94
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw v1

    .line 106
    :goto_1
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 107
    throw p0
.end method

.method public final e()V
    .locals 2

    .line 1
    iget v0, p0, Lu/p0;->j:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    const-string p0, "CaptureSession"

    .line 7
    .line 8
    const-string v0, "Skipping finishClose due to being state RELEASED."

    .line 9
    .line 10
    invoke-static {p0, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    invoke-virtual {p0, v1}, Lu/p0;->p(I)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lu/p0;->e:Lu/g1;

    .line 19
    .line 20
    iget-object v1, p0, Lu/p0;->l:Ly4/h;

    .line 21
    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-virtual {v1, v0}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Lu/p0;->l:Ly4/h;

    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public final f(Lh0/i;Ljava/util/HashMap;Ljava/lang/String;)Lw/h;
    .locals 6

    .line 1
    iget-object v0, p1, Lh0/i;->a:Lh0/t0;

    .line 2
    .line 3
    iget-object v1, p1, Lh0/i;->b:Ljava/util/List;

    .line 4
    .line 5
    invoke-virtual {p2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Landroid/view/Surface;

    .line 10
    .line 11
    const-string v2, "Surface in OutputConfig not found in configuredSurfaceMap."

    .line 12
    .line 13
    invoke-static {v0, v2}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v3, Lw/h;

    .line 17
    .line 18
    iget v4, p1, Lh0/i;->d:I

    .line 19
    .line 20
    invoke-direct {v3, v4, v0}, Lw/h;-><init>(ILandroid/view/Surface;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v3, Lw/h;->a:Lw/j;

    .line 24
    .line 25
    if-eqz p3, :cond_0

    .line 26
    .line 27
    invoke-virtual {v0}, Lw/j;->a()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    check-cast v4, Landroid/hardware/camera2/params/OutputConfiguration;

    .line 32
    .line 33
    invoke-virtual {v4, p3}, Landroid/hardware/camera2/params/OutputConfiguration;->setPhysicalCameraId(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v0}, Lw/j;->a()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p3

    .line 41
    check-cast p3, Landroid/hardware/camera2/params/OutputConfiguration;

    .line 42
    .line 43
    const/4 v4, 0x0

    .line 44
    invoke-virtual {p3, v4}, Landroid/hardware/camera2/params/OutputConfiguration;->setPhysicalCameraId(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    :goto_0
    iget p3, p1, Lh0/i;->c:I

    .line 48
    .line 49
    const/4 v4, 0x1

    .line 50
    if-nez p3, :cond_1

    .line 51
    .line 52
    invoke-virtual {v0, v4}, Lw/j;->d(I)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    if-ne p3, v4, :cond_2

    .line 57
    .line 58
    const/4 p3, 0x2

    .line 59
    invoke-virtual {v0, p3}, Lw/j;->d(I)V

    .line 60
    .line 61
    .line 62
    :cond_2
    :goto_1
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 63
    .line 64
    .line 65
    move-result p3

    .line 66
    if-nez p3, :cond_3

    .line 67
    .line 68
    invoke-virtual {v0}, Lw/j;->a()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p3

    .line 72
    check-cast p3, Landroid/hardware/camera2/params/OutputConfiguration;

    .line 73
    .line 74
    invoke-virtual {p3}, Landroid/hardware/camera2/params/OutputConfiguration;->enableSurfaceSharing()V

    .line 75
    .line 76
    .line 77
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object p3

    .line 81
    :goto_2
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-eqz v1, :cond_3

    .line 86
    .line 87
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    check-cast v1, Lh0/t0;

    .line 92
    .line 93
    invoke-virtual {p2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    check-cast v1, Landroid/view/Surface;

    .line 98
    .line 99
    invoke-static {v1, v2}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0}, Lw/j;->a()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v5

    .line 106
    check-cast v5, Landroid/hardware/camera2/params/OutputConfiguration;

    .line 107
    .line 108
    invoke-virtual {v5, v1}, Landroid/hardware/camera2/params/OutputConfiguration;->addSurface(Landroid/view/Surface;)V

    .line 109
    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_3
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 113
    .line 114
    const/16 p3, 0x21

    .line 115
    .line 116
    if-lt p2, p3, :cond_6

    .line 117
    .line 118
    iget-object p0, p0, Lu/p0;->q:Lpv/g;

    .line 119
    .line 120
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    if-lt p2, p3, :cond_4

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_4
    const/4 v4, 0x0

    .line 127
    :goto_3
    const-string p2, "DynamicRangesCompat can only be converted to DynamicRangeProfiles on API 33 or higher."

    .line 128
    .line 129
    invoke-static {p2, v4}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 130
    .line 131
    .line 132
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast p0, Lw/b;

    .line 135
    .line 136
    invoke-interface {p0}, Lw/b;->a()Landroid/hardware/camera2/params/DynamicRangeProfiles;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    if-eqz p0, :cond_6

    .line 141
    .line 142
    iget-object p1, p1, Lh0/i;->e:Lb0/y;

    .line 143
    .line 144
    invoke-static {p1, p0}, Lw/a;->a(Lb0/y;Landroid/hardware/camera2/params/DynamicRangeProfiles;)Ljava/lang/Long;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    if-nez p0, :cond_5

    .line 149
    .line 150
    new-instance p0, Ljava/lang/StringBuilder;

    .line 151
    .line 152
    const-string p2, "Requested dynamic range is not supported. Defaulting to STANDARD dynamic range profile.\nRequested dynamic range:\n  "

    .line 153
    .line 154
    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    const-string p1, "CaptureSession"

    .line 165
    .line 166
    invoke-static {p1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    goto :goto_4

    .line 170
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 171
    .line 172
    .line 173
    move-result-wide p0

    .line 174
    goto :goto_5

    .line 175
    :cond_6
    :goto_4
    const-wide/16 p0, 0x1

    .line 176
    .line 177
    :goto_5
    invoke-virtual {v0, p0, p1}, Lw/j;->c(J)V

    .line 178
    .line 179
    .line 180
    return-object v3
.end method

.method public final i()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget p0, p0, Lu/p0;->j:I

    .line 5
    .line 6
    const/16 v1, 0x8

    .line 7
    .line 8
    if-eq p0, v1, :cond_1

    .line 9
    .line 10
    const/4 v1, 0x7

    .line 11
    if-ne p0, v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    :goto_1
    monitor-exit v0

    .line 18
    return p0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    throw p0
.end method

.method public final j(Ljava/util/ArrayList;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget v1, p0, Lu/p0;->j:I

    .line 5
    .line 6
    const/16 v2, 0x8

    .line 7
    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    const-string p0, "CaptureSession"

    .line 11
    .line 12
    const-string p1, "Skipping issueBurstCaptureRequest due to session closed"

    .line 13
    .line 14
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    monitor-exit v0

    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    goto/16 :goto_4

    .line 21
    .line 22
    :cond_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    return-void

    .line 30
    :cond_1
    :try_start_1
    new-instance v1, Lu/k;

    .line 31
    .line 32
    const/4 v2, 0x1

    .line 33
    invoke-direct {v1, v2}, Lu/k;-><init>(I)V

    .line 34
    .line 35
    .line 36
    new-instance v2, Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 39
    .line 40
    .line 41
    const-string v3, "CaptureSession"

    .line 42
    .line 43
    const-string v4, "Issuing capture request."

    .line 44
    .line 45
    invoke-static {v3, v4}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    const/4 v3, 0x0

    .line 53
    move v4, v3

    .line 54
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    const/4 v6, 0x1

    .line 59
    if-eqz v5, :cond_a

    .line 60
    .line 61
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    check-cast v5, Lh0/o0;

    .line 66
    .line 67
    iget-object v7, v5, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-static {v7}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    if-eqz v7, :cond_2

    .line 78
    .line 79
    const-string v5, "CaptureSession"

    .line 80
    .line 81
    const-string v6, "Skipping issuing empty capture request."

    .line 82
    .line 83
    invoke-static {v5, v6}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :catch_0
    move-exception p0

    .line 88
    goto/16 :goto_2

    .line 89
    .line 90
    :cond_2
    iget-object v7, v5, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-static {v7}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 97
    .line 98
    .line 99
    move-result-object v7

    .line 100
    :cond_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    if-eqz v8, :cond_4

    .line 105
    .line 106
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v8

    .line 110
    check-cast v8, Lh0/t0;

    .line 111
    .line 112
    iget-object v9, p0, Lu/p0;->g:Ljava/util/HashMap;

    .line 113
    .line 114
    invoke-virtual {v9, v8}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v9

    .line 118
    if-nez v9, :cond_3

    .line 119
    .line 120
    const-string v5, "CaptureSession"

    .line 121
    .line 122
    new-instance v6, Ljava/lang/StringBuilder;

    .line 123
    .line 124
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 125
    .line 126
    .line 127
    const-string v7, "Skipping capture request with invalid surface: "

    .line 128
    .line 129
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v6

    .line 139
    invoke-static {v5, v6}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    goto :goto_0

    .line 143
    :cond_4
    iget v7, v5, Lh0/o0;->c:I

    .line 144
    .line 145
    const/4 v8, 0x2

    .line 146
    if-ne v7, v8, :cond_5

    .line 147
    .line 148
    move v4, v6

    .line 149
    :cond_5
    new-instance v6, Lb0/n1;

    .line 150
    .line 151
    invoke-direct {v6, v5}, Lb0/n1;-><init>(Lh0/o0;)V

    .line 152
    .line 153
    .line 154
    iget v7, v5, Lh0/o0;->c:I

    .line 155
    .line 156
    const/4 v8, 0x5

    .line 157
    if-ne v7, v8, :cond_6

    .line 158
    .line 159
    iget-object v7, v5, Lh0/o0;->g:Lh0/s;

    .line 160
    .line 161
    if-eqz v7, :cond_6

    .line 162
    .line 163
    iput-object v7, v6, Lb0/n1;->j:Ljava/lang/Object;

    .line 164
    .line 165
    :cond_6
    iget-object v7, p0, Lu/p0;->f:Lh0/z1;

    .line 166
    .line 167
    if-eqz v7, :cond_7

    .line 168
    .line 169
    iget-object v7, v7, Lh0/z1;->g:Lh0/o0;

    .line 170
    .line 171
    iget-object v7, v7, Lh0/o0;->b:Lh0/n1;

    .line 172
    .line 173
    invoke-virtual {v6, v7}, Lb0/n1;->i(Lh0/q0;)V

    .line 174
    .line 175
    .line 176
    :cond_7
    iget-object v7, v5, Lh0/o0;->b:Lh0/n1;

    .line 177
    .line 178
    invoke-virtual {v6, v7}, Lb0/n1;->i(Lh0/q0;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v6}, Lb0/n1;->j()Lh0/o0;

    .line 182
    .line 183
    .line 184
    move-result-object v6

    .line 185
    iget-object v7, p0, Lu/p0;->e:Lu/g1;

    .line 186
    .line 187
    iget-object v8, v7, Lu/g1;->f:Lro/f;

    .line 188
    .line 189
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 190
    .line 191
    .line 192
    iget-object v7, v7, Lu/g1;->f:Lro/f;

    .line 193
    .line 194
    iget-object v7, v7, Lro/f;->e:Ljava/lang/Object;

    .line 195
    .line 196
    check-cast v7, Lb81/c;

    .line 197
    .line 198
    iget-object v7, v7, Lb81/c;->e:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v7, Landroid/hardware/camera2/CameraCaptureSession;

    .line 201
    .line 202
    invoke-virtual {v7}, Landroid/hardware/camera2/CameraCaptureSession;->getDevice()Landroid/hardware/camera2/CameraDevice;

    .line 203
    .line 204
    .line 205
    move-result-object v7

    .line 206
    iget-object v8, p0, Lu/p0;->g:Ljava/util/HashMap;

    .line 207
    .line 208
    iget-object v9, p0, Lu/p0;->r:Lk1/c0;

    .line 209
    .line 210
    invoke-static {v6, v7, v8, v3, v9}, Llp/w0;->d(Lh0/o0;Landroid/hardware/camera2/CameraDevice;Ljava/util/HashMap;ZLk1/c0;)Landroid/hardware/camera2/CaptureRequest;

    .line 211
    .line 212
    .line 213
    move-result-object v6

    .line 214
    if-nez v6, :cond_8

    .line 215
    .line 216
    const-string p0, "CaptureSession"

    .line 217
    .line 218
    const-string p1, "Skipping issuing request without surface."

    .line 219
    .line 220
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 221
    .line 222
    .line 223
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 224
    return-void

    .line 225
    :cond_8
    :try_start_3
    new-instance v7, Ljava/util/ArrayList;

    .line 226
    .line 227
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 228
    .line 229
    .line 230
    iget-object v5, v5, Lh0/o0;->d:Ljava/util/List;

    .line 231
    .line 232
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 233
    .line 234
    .line 235
    move-result-object v5

    .line 236
    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 237
    .line 238
    .line 239
    move-result v8

    .line 240
    if-eqz v8, :cond_9

    .line 241
    .line 242
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v8

    .line 246
    check-cast v8, Lh0/m;

    .line 247
    .line 248
    invoke-static {v8, v7}, Llp/a1;->a(Lh0/m;Ljava/util/ArrayList;)V

    .line 249
    .line 250
    .line 251
    goto :goto_1

    .line 252
    :cond_9
    invoke-virtual {v1, v6, v7}, Lu/k;->a(Landroid/hardware/camera2/CaptureRequest;Ljava/util/List;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    goto/16 :goto_0

    .line 259
    .line 260
    :cond_a
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 261
    .line 262
    .line 263
    move-result p1

    .line 264
    if-nez p1, :cond_e

    .line 265
    .line 266
    iget-object p1, p0, Lu/p0;->n:La8/t1;

    .line 267
    .line 268
    invoke-virtual {p1, v2, v4}, La8/t1;->d(Ljava/util/ArrayList;Z)Z

    .line 269
    .line 270
    .line 271
    move-result p1

    .line 272
    if-eqz p1, :cond_b

    .line 273
    .line 274
    iget-object p1, p0, Lu/p0;->e:Lu/g1;

    .line 275
    .line 276
    iget-object v3, p1, Lu/g1;->f:Lro/f;

    .line 277
    .line 278
    const-string v5, "Need to call openCaptureSession before using this API."

    .line 279
    .line 280
    invoke-static {v3, v5}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    iget-object p1, p1, Lu/g1;->f:Lro/f;

    .line 284
    .line 285
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast p1, Lb81/c;

    .line 288
    .line 289
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 292
    .line 293
    invoke-virtual {p1}, Landroid/hardware/camera2/CameraCaptureSession;->stopRepeating()V

    .line 294
    .line 295
    .line 296
    new-instance p1, Lu/n0;

    .line 297
    .line 298
    invoke-direct {p1, p0}, Lu/n0;-><init>(Lu/p0;)V

    .line 299
    .line 300
    .line 301
    iput-object p1, v1, Lu/k;->c:Ljava/lang/Object;

    .line 302
    .line 303
    :cond_b
    iget-object p1, p0, Lu/p0;->o:La8/t1;

    .line 304
    .line 305
    invoke-virtual {p1, v2, v4}, La8/t1;->b(Ljava/util/ArrayList;Z)Z

    .line 306
    .line 307
    .line 308
    move-result p1

    .line 309
    if-eqz p1, :cond_c

    .line 310
    .line 311
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 312
    .line 313
    .line 314
    move-result p1

    .line 315
    sub-int/2addr p1, v6

    .line 316
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object p1

    .line 320
    check-cast p1, Landroid/hardware/camera2/CaptureRequest;

    .line 321
    .line 322
    new-instance v3, Lu/a0;

    .line 323
    .line 324
    invoke-direct {v3, p0}, Lu/a0;-><init>(Lu/p0;)V

    .line 325
    .line 326
    .line 327
    invoke-static {v3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 328
    .line 329
    .line 330
    move-result-object v3

    .line 331
    invoke-virtual {v1, p1, v3}, Lu/k;->a(Landroid/hardware/camera2/CaptureRequest;Ljava/util/List;)V

    .line 332
    .line 333
    .line 334
    :cond_c
    iget-object p1, p0, Lu/p0;->f:Lh0/z1;

    .line 335
    .line 336
    if-eqz p1, :cond_d

    .line 337
    .line 338
    iget p1, p1, Lh0/z1;->h:I

    .line 339
    .line 340
    if-ne p1, v6, :cond_d

    .line 341
    .line 342
    invoke-virtual {p0, v2, v1}, Lu/p0;->a(Ljava/util/ArrayList;Lu/k;)I
    :try_end_3
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 343
    .line 344
    .line 345
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 346
    return-void

    .line 347
    :cond_d
    :try_start_5
    iget-object p0, p0, Lu/p0;->e:Lu/g1;

    .line 348
    .line 349
    iget-object p1, p0, Lu/g1;->t:Lb6/f;

    .line 350
    .line 351
    invoke-virtual {p1, v1}, Lb6/f;->k(Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 352
    .line 353
    .line 354
    move-result-object p1

    .line 355
    iget-object v1, p0, Lu/g1;->f:Lro/f;

    .line 356
    .line 357
    const-string v3, "Need to call openCaptureSession before using this API."

    .line 358
    .line 359
    invoke-static {v1, v3}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    iget-object v1, p0, Lu/g1;->f:Lro/f;

    .line 363
    .line 364
    iget-object p0, p0, Lu/g1;->c:Lj0/h;

    .line 365
    .line 366
    iget-object v1, v1, Lro/f;->e:Ljava/lang/Object;

    .line 367
    .line 368
    check-cast v1, Lb81/c;

    .line 369
    .line 370
    iget-object v1, v1, Lb81/c;->e:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast v1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 373
    .line 374
    invoke-virtual {v1, v2, p0, p1}, Landroid/hardware/camera2/CameraCaptureSession;->captureBurstRequests(Ljava/util/List;Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)I
    :try_end_5
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 375
    .line 376
    .line 377
    :try_start_6
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 378
    return-void

    .line 379
    :cond_e
    :try_start_7
    const-string p0, "CaptureSession"

    .line 380
    .line 381
    const-string p1, "Skipping issuing burst request due to no valid request elements"

    .line 382
    .line 383
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_7
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_7 .. :try_end_7} :catch_0
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 384
    .line 385
    .line 386
    goto :goto_3

    .line 387
    :goto_2
    :try_start_8
    const-string p1, "CaptureSession"

    .line 388
    .line 389
    new-instance v1, Ljava/lang/StringBuilder;

    .line 390
    .line 391
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 392
    .line 393
    .line 394
    const-string v2, "Unable to access camera: "

    .line 395
    .line 396
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 397
    .line 398
    .line 399
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 400
    .line 401
    .line 402
    move-result-object p0

    .line 403
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 404
    .line 405
    .line 406
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 407
    .line 408
    .line 409
    move-result-object p0

    .line 410
    invoke-static {p1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 411
    .line 412
    .line 413
    invoke-static {}, Ljava/lang/Thread;->dumpStack()V

    .line 414
    .line 415
    .line 416
    :goto_3
    monitor-exit v0

    .line 417
    return-void

    .line 418
    :goto_4
    monitor-exit v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 419
    throw p0
.end method

.method public final k(Ljava/util/List;)V
    .locals 3

    .line 1
    const-string v0, "issueCaptureRequests() should not be possible in state: "

    .line 2
    .line 3
    iget-object v1, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget v2, p0, Lu/p0;->j:I

    .line 7
    .line 8
    invoke-static {v2}, Lu/w;->o(I)I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    packed-switch v2, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :pswitch_0
    iget-object v0, p0, Lu/p0;->b:Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lu/p0;->p:Lb6/f;

    .line 22
    .line 23
    invoke-virtual {p1}, Lb6/f;->m()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    new-instance v0, Lm8/o;

    .line 28
    .line 29
    const/16 v2, 0xf

    .line 30
    .line 31
    invoke-direct {v0, p0, v2}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 32
    .line 33
    .line 34
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-interface {p1, p0, v0}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception p0

    .line 43
    goto :goto_1

    .line 44
    :pswitch_1
    iget-object p0, p0, Lu/p0;->b:Ljava/util/ArrayList;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 47
    .line 48
    .line 49
    :goto_0
    monitor-exit v1

    .line 50
    return-void

    .line 51
    :pswitch_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "Cannot issue capture request on a closed/released session."

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :pswitch_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    iget p0, p0, Lu/p0;->j:I

    .line 62
    .line 63
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p1

    .line 75
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 76
    throw p0

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final l(Lh0/z1;)V
    .locals 7

    .line 1
    const-string v0, "Unable to access camera: "

    .line 2
    .line 3
    const-string v1, "Unable to access camera: "

    .line 4
    .line 5
    iget-object v2, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v2

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    :try_start_0
    const-string p0, "CaptureSession"

    .line 11
    .line 12
    const-string p1, "Skipping issueRepeatingCaptureRequests for no configuration case."

    .line 13
    .line 14
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    monitor-exit v2

    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    goto/16 :goto_4

    .line 21
    .line 22
    :cond_0
    iget v3, p0, Lu/p0;->j:I

    .line 23
    .line 24
    const/16 v4, 0x8

    .line 25
    .line 26
    if-eq v3, v4, :cond_1

    .line 27
    .line 28
    const-string p0, "CaptureSession"

    .line 29
    .line 30
    const-string p1, "Skipping issueRepeatingCaptureRequests due to session closed"

    .line 31
    .line 32
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    monitor-exit v2

    .line 36
    return-void

    .line 37
    :cond_1
    iget-object v3, p1, Lh0/z1;->g:Lh0/o0;

    .line 38
    .line 39
    iget-object v4, v3, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-static {v4}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_2

    .line 50
    .line 51
    const-string p1, "CaptureSession"

    .line 52
    .line 53
    const-string v0, "Skipping issueRepeatingCaptureRequests for no surface."

    .line 54
    .line 55
    invoke-static {p1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 56
    .line 57
    .line 58
    :try_start_1
    iget-object p0, p0, Lu/p0;->e:Lu/g1;

    .line 59
    .line 60
    iget-object p1, p0, Lu/g1;->f:Lro/f;

    .line 61
    .line 62
    const-string v0, "Need to call openCaptureSession before using this API."

    .line 63
    .line 64
    invoke-static {p1, v0}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Lu/g1;->f:Lro/f;

    .line 68
    .line 69
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p0, Lb81/c;

    .line 72
    .line 73
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p0, Landroid/hardware/camera2/CameraCaptureSession;

    .line 76
    .line 77
    invoke-virtual {p0}, Landroid/hardware/camera2/CameraCaptureSession;->stopRepeating()V
    :try_end_1
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :catch_0
    move-exception p0

    .line 82
    :try_start_2
    const-string p1, "CaptureSession"

    .line 83
    .line 84
    new-instance v0, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-static {p1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-static {}, Ljava/lang/Thread;->dumpStack()V

    .line 104
    .line 105
    .line 106
    :goto_0
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 107
    goto/16 :goto_3

    .line 108
    .line 109
    :cond_2
    :try_start_3
    const-string v1, "CaptureSession"

    .line 110
    .line 111
    const-string v4, "Issuing request for session."

    .line 112
    .line 113
    invoke-static {v1, v4}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    iget-object v1, p0, Lu/p0;->e:Lu/g1;

    .line 117
    .line 118
    iget-object v4, v1, Lu/g1;->f:Lro/f;

    .line 119
    .line 120
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    iget-object v1, v1, Lu/g1;->f:Lro/f;

    .line 124
    .line 125
    iget-object v1, v1, Lro/f;->e:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v1, Lb81/c;

    .line 128
    .line 129
    iget-object v1, v1, Lb81/c;->e:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 132
    .line 133
    invoke-virtual {v1}, Landroid/hardware/camera2/CameraCaptureSession;->getDevice()Landroid/hardware/camera2/CameraDevice;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    iget-object v4, p0, Lu/p0;->g:Ljava/util/HashMap;

    .line 138
    .line 139
    iget-object v5, p0, Lu/p0;->r:Lk1/c0;

    .line 140
    .line 141
    const/4 v6, 0x1

    .line 142
    invoke-static {v3, v1, v4, v6, v5}, Llp/w0;->d(Lh0/o0;Landroid/hardware/camera2/CameraDevice;Ljava/util/HashMap;ZLk1/c0;)Landroid/hardware/camera2/CaptureRequest;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    if-nez v1, :cond_3

    .line 147
    .line 148
    const-string p0, "CaptureSession"

    .line 149
    .line 150
    const-string p1, "Skipping issuing empty request for session."

    .line 151
    .line 152
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_3
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 153
    .line 154
    .line 155
    :try_start_4
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 156
    return-void

    .line 157
    :catch_1
    move-exception p0

    .line 158
    goto :goto_2

    .line 159
    :cond_3
    :try_start_5
    iget-object v4, p0, Lu/p0;->p:Lb6/f;

    .line 160
    .line 161
    iget-object v3, v3, Lh0/o0;->d:Ljava/util/List;

    .line 162
    .line 163
    const/4 v5, 0x0

    .line 164
    new-array v5, v5, [Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 165
    .line 166
    invoke-static {v3, v5}, Lu/p0;->c(Ljava/util/List;[Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)Lu/a0;

    .line 167
    .line 168
    .line 169
    move-result-object v3

    .line 170
    invoke-virtual {v4, v3}, Lb6/f;->k(Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    iget p1, p1, Lh0/z1;->h:I

    .line 175
    .line 176
    if-ne p1, v6, :cond_5

    .line 177
    .line 178
    iget-object p1, p0, Lu/p0;->e:Lu/g1;

    .line 179
    .line 180
    iget-object p1, p1, Lu/g1;->f:Lro/f;

    .line 181
    .line 182
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 183
    .line 184
    .line 185
    iget-object p1, p1, Lro/f;->e:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast p1, Lb81/c;

    .line 188
    .line 189
    iget-object p1, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast p1, Landroid/hardware/camera2/CameraCaptureSession;

    .line 192
    .line 193
    instance-of v4, p1, Landroid/hardware/camera2/CameraConstrainedHighSpeedCaptureSession;

    .line 194
    .line 195
    if-eqz v4, :cond_4

    .line 196
    .line 197
    check-cast p1, Landroid/hardware/camera2/CameraConstrainedHighSpeedCaptureSession;

    .line 198
    .line 199
    invoke-virtual {p1, v1}, Landroid/hardware/camera2/CameraConstrainedHighSpeedCaptureSession;->createHighSpeedRequestList(Landroid/hardware/camera2/CaptureRequest;)Ljava/util/List;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    goto :goto_1

    .line 204
    :cond_4
    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 205
    .line 206
    :goto_1
    iget-object p0, p0, Lu/p0;->e:Lu/g1;

    .line 207
    .line 208
    invoke-virtual {p0, p1, v3}, Lu/g1;->n(Ljava/util/List;Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)I
    :try_end_5
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 209
    .line 210
    .line 211
    :try_start_6
    monitor-exit v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 212
    return-void

    .line 213
    :cond_5
    :try_start_7
    iget-object p0, p0, Lu/p0;->e:Lu/g1;

    .line 214
    .line 215
    invoke-virtual {p0, v1, v3}, Lu/g1;->o(Landroid/hardware/camera2/CaptureRequest;Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)I
    :try_end_7
    .catch Landroid/hardware/camera2/CameraAccessException; {:try_start_7 .. :try_end_7} :catch_1
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 216
    .line 217
    .line 218
    :try_start_8
    monitor-exit v2

    .line 219
    return-void

    .line 220
    :goto_2
    const-string p1, "CaptureSession"

    .line 221
    .line 222
    new-instance v1, Ljava/lang/StringBuilder;

    .line 223
    .line 224
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 232
    .line 233
    .line 234
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    invoke-static {p1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    invoke-static {}, Ljava/lang/Thread;->dumpStack()V

    .line 242
    .line 243
    .line 244
    monitor-exit v2

    .line 245
    :goto_3
    return-void

    .line 246
    :goto_4
    monitor-exit v2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 247
    throw p0
.end method

.method public final m(Lh0/z1;Landroid/hardware/camera2/CameraDevice;Lu/g1;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 5

    .line 1
    const-string v0, "open() should not allow the state: "

    .line 2
    .line 3
    const-string v1, "Open not allowed in state: "

    .line 4
    .line 5
    iget-object v2, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v2

    .line 8
    :try_start_0
    iget v3, p0, Lu/p0;->j:I

    .line 9
    .line 10
    invoke-static {v3}, Lu/w;->o(I)I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    const/4 v4, 0x2

    .line 15
    if-eq v3, v4, :cond_0

    .line 16
    .line 17
    const-string p1, "CaptureSession"

    .line 18
    .line 19
    iget p2, p0, Lu/p0;->j:I

    .line 20
    .line 21
    invoke-static {p2}, Lu/w;->q(I)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    invoke-virtual {v1, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    invoke-static {p1, p2}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    iget p0, p0, Lu/p0;->j:I

    .line 35
    .line 36
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    new-instance p0, Lk0/j;

    .line 48
    .line 49
    const/4 p2, 0x1

    .line 50
    invoke-direct {p0, p1, p2}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 51
    .line 52
    .line 53
    monitor-exit v2

    .line 54
    return-object p0

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    goto :goto_0

    .line 57
    :cond_0
    const/4 v0, 0x4

    .line 58
    invoke-virtual {p0, v0}, Lu/p0;->p(I)V

    .line 59
    .line 60
    .line 61
    new-instance v0, Ljava/util/ArrayList;

    .line 62
    .line 63
    invoke-virtual {p1}, Lh0/z1;->b()Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 68
    .line 69
    .line 70
    iput-object v0, p0, Lu/p0;->h:Ljava/util/List;

    .line 71
    .line 72
    iput-object p3, p0, Lu/p0;->d:Lu/g1;

    .line 73
    .line 74
    iget-object v1, p3, Lu/g1;->o:Ljava/lang/Object;

    .line 75
    .line 76
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 77
    :try_start_1
    iput-object v0, p3, Lu/g1;->p:Ljava/util/ArrayList;

    .line 78
    .line 79
    invoke-virtual {p3, v0}, Lu/g1;->p(Ljava/util/ArrayList;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 80
    .line 81
    .line 82
    move-result-object p3

    .line 83
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 84
    :try_start_2
    invoke-static {p3}, Lk0/d;->b(Lcom/google/common/util/concurrent/ListenableFuture;)Lk0/d;

    .line 85
    .line 86
    .line 87
    move-result-object p3

    .line 88
    new-instance v0, Lbb/i;

    .line 89
    .line 90
    const/16 v1, 0xb

    .line 91
    .line 92
    invoke-direct {v0, p0, p1, p2, v1}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 93
    .line 94
    .line 95
    iget-object p1, p0, Lu/p0;->d:Lu/g1;

    .line 96
    .line 97
    iget-object p1, p1, Lu/g1;->c:Lj0/h;

    .line 98
    .line 99
    invoke-static {p3, v0, p1}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    new-instance p2, Lpv/g;

    .line 104
    .line 105
    const/16 p3, 0x9

    .line 106
    .line 107
    invoke-direct {p2, p0, p3}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 108
    .line 109
    .line 110
    iget-object p0, p0, Lu/p0;->d:Lu/g1;

    .line 111
    .line 112
    iget-object p0, p0, Lu/g1;->c:Lj0/h;

    .line 113
    .line 114
    new-instance p3, Lk0/g;

    .line 115
    .line 116
    const/4 v0, 0x0

    .line 117
    invoke-direct {p3, v0, p1, p2}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1, p0, p3}, Lk0/d;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 121
    .line 122
    .line 123
    invoke-static {p1}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 128
    return-object p0

    .line 129
    :catchall_1
    move-exception p0

    .line 130
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 131
    :try_start_4
    throw p0

    .line 132
    :goto_0
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 133
    throw p0
.end method

.method public final n()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 5

    .line 1
    const-string v0, "release() should not be possible in state: "

    .line 2
    .line 3
    const-string v1, "The Opener shouldn\'t null in state:"

    .line 4
    .line 5
    const-string v2, "The Opener shouldn\'t null in state:"

    .line 6
    .line 7
    iget-object v3, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v3

    .line 10
    :try_start_0
    iget v4, p0, Lu/p0;->j:I

    .line 11
    .line 12
    invoke-static {v4}, Lu/w;->o(I)I

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    if-eqz v4, :cond_3

    .line 17
    .line 18
    packed-switch v4, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    goto :goto_1

    .line 22
    :pswitch_0
    iget-object v0, p0, Lu/p0;->e:Lu/g1;

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-virtual {v0}, Lu/g1;->i()V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :catchall_0
    move-exception p0

    .line 31
    goto :goto_2

    .line 32
    :cond_0
    :goto_0
    :pswitch_1
    const/4 v0, 0x5

    .line 33
    invoke-virtual {p0, v0}, Lu/p0;->p(I)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lu/p0;->p:Lb6/f;

    .line 37
    .line 38
    invoke-virtual {v0}, Lb6/f;->x()V

    .line 39
    .line 40
    .line 41
    iget-object v0, p0, Lu/p0;->d:Lu/g1;

    .line 42
    .line 43
    iget v1, p0, Lu/p0;->j:I

    .line 44
    .line 45
    invoke-static {v1}, Lu/w;->q(I)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-static {v0, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Lu/p0;->d:Lu/g1;

    .line 57
    .line 58
    invoke-virtual {v0}, Lu/g1;->q()Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-eqz v0, :cond_1

    .line 63
    .line 64
    invoke-virtual {p0}, Lu/p0;->e()V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    :pswitch_2
    iget-object v0, p0, Lu/p0;->k:Ly4/k;

    .line 69
    .line 70
    if-nez v0, :cond_2

    .line 71
    .line 72
    new-instance v0, Lu/n0;

    .line 73
    .line 74
    invoke-direct {v0, p0}, Lu/n0;-><init>(Lu/p0;)V

    .line 75
    .line 76
    .line 77
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    iput-object v0, p0, Lu/p0;->k:Ly4/k;

    .line 82
    .line 83
    :cond_2
    iget-object p0, p0, Lu/p0;->k:Ly4/k;

    .line 84
    .line 85
    monitor-exit v3

    .line 86
    return-object p0

    .line 87
    :pswitch_3
    iget-object v0, p0, Lu/p0;->d:Lu/g1;

    .line 88
    .line 89
    iget v2, p0, Lu/p0;->j:I

    .line 90
    .line 91
    invoke-static {v2}, Lu/w;->q(I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    invoke-static {v0, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    iget-object v0, p0, Lu/p0;->d:Lu/g1;

    .line 103
    .line 104
    invoke-virtual {v0}, Lu/g1;->q()Z

    .line 105
    .line 106
    .line 107
    :pswitch_4
    const/4 v0, 0x2

    .line 108
    invoke-virtual {p0, v0}, Lu/p0;->p(I)V

    .line 109
    .line 110
    .line 111
    :goto_1
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 112
    sget-object p0, Lk0/j;->f:Lk0/j;

    .line 113
    .line 114
    return-object p0

    .line 115
    :cond_3
    :try_start_1
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 116
    .line 117
    iget p0, p0, Lu/p0;->j:I

    .line 118
    .line 119
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw v1

    .line 131
    :goto_2
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 132
    throw p0

    .line 133
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final o(Lh0/z1;)V
    .locals 3

    .line 1
    const-string v0, "setSessionConfig() should not be possible in state: "

    .line 2
    .line 3
    iget-object v1, p0, Lu/p0;->a:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget v2, p0, Lu/p0;->j:I

    .line 7
    .line 8
    invoke-static {v2}, Lu/w;->o(I)I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    packed-switch v2, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :pswitch_0
    iput-object p1, p0, Lu/p0;->f:Lh0/z1;

    .line 17
    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    monitor-exit v1

    .line 21
    return-void

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    iget-object v0, p0, Lu/p0;->g:Ljava/util/HashMap;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {p1}, Lh0/z1;->b()Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-interface {v0, p1}, Ljava/util/Set;->containsAll(Ljava/util/Collection;)Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-nez p1, :cond_1

    .line 39
    .line 40
    const-string p0, "CaptureSession"

    .line 41
    .line 42
    const-string p1, "Does not have the proper configured lists"

    .line 43
    .line 44
    invoke-static {p0, p1}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    monitor-exit v1

    .line 48
    return-void

    .line 49
    :cond_1
    const-string p1, "CaptureSession"

    .line 50
    .line 51
    const-string v0, "Attempting to submit CaptureRequest after setting"

    .line 52
    .line 53
    invoke-static {p1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object p1, p0, Lu/p0;->f:Lh0/z1;

    .line 57
    .line 58
    invoke-virtual {p0, p1}, Lu/p0;->l(Lh0/z1;)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_1
    iput-object p1, p0, Lu/p0;->f:Lh0/z1;

    .line 63
    .line 64
    :goto_0
    monitor-exit v1

    .line 65
    return-void

    .line 66
    :pswitch_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    const-string p1, "Session configuration cannot be set on a closed/released session."

    .line 69
    .line 70
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p0

    .line 74
    :pswitch_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    iget p0, p0, Lu/p0;->j:I

    .line 77
    .line 78
    invoke-static {p0}, Lu/w;->q(I)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p1

    .line 90
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 91
    throw p0

    .line 92
    nop

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final p(I)V
    .locals 2

    .line 1
    invoke-static {p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget v1, p0, Lu/p0;->i:I

    .line 6
    .line 7
    invoke-static {v1}, Lu/w;->o(I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-le v0, v1, :cond_0

    .line 12
    .line 13
    iput p1, p0, Lu/p0;->i:I

    .line 14
    .line 15
    :cond_0
    iput p1, p0, Lu/p0;->j:I

    .line 16
    .line 17
    invoke-static {}, Lab/a;->a()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    iget v0, p0, Lu/p0;->i:I

    .line 24
    .line 25
    invoke-static {v0}, Lu/w;->o(I)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const/4 v1, 0x3

    .line 30
    if-lt v0, v1, :cond_1

    .line 31
    .line 32
    new-instance v0, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string v1, "CX:C2State["

    .line 35
    .line 36
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string v1, "CaptureSession@%x"

    .line 52
    .line 53
    invoke-static {v1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string p0, "]"

    .line 61
    .line 62
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-static {p1}, Lu/w;->o(I)I

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    invoke-static {p0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    int-to-long v0, p1

    .line 78
    invoke-static {p0, v0, v1}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 79
    .line 80
    .line 81
    :cond_1
    return-void
.end method

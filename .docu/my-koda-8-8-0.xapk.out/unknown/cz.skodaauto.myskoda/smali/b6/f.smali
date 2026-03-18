.class public Lb6/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Los/k;
.implements Llp/kg;
.implements Lu/k1;


# instance fields
.field public d:Z

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    new-instance v0, Landroid/util/SparseBooleanArray;

    invoke-direct {v0}, Landroid/util/SparseBooleanArray;-><init>()V

    iput-object v0, p0, Lb6/f;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/net/Uri;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb6/f;->e:Ljava/lang/Object;

    iput-boolean p2, p0, Lb6/f;->d:Z

    return-void
.end method

.method public constructor <init>(Lb6/e;Z)V
    .locals 0

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-object p1, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 12
    iput-boolean p2, p0, Lb6/f;->d:Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;)V
    .locals 0

    .line 2
    iput-object p1, p0, Lb6/f;->e:Ljava/lang/Object;

    const/4 p1, 0x1

    iput-boolean p1, p0, Lb6/f;->d:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Z)V
    .locals 0

    .line 3
    iput-boolean p2, p0, Lb6/f;->d:Z

    iput-object p1, p0, Lb6/f;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 1

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    invoke-static {v0}, Ljava/util/Collections;->synchronizedList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 9
    iput-boolean p1, p0, Lb6/f;->d:Z

    return-void
.end method

.method public static j(Lv/b;)Z
    .locals 5

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x22

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-gt v0, v1, :cond_0

    .line 7
    .line 8
    return v2

    .line 9
    :cond_0
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->CONTROL_AE_AVAILABLE_MODES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, [I

    .line 16
    .line 17
    if-eqz p0, :cond_2

    .line 18
    .line 19
    array-length v0, p0

    .line 20
    move v1, v2

    .line 21
    :goto_0
    if-ge v1, v0, :cond_2

    .line 22
    .line 23
    aget v3, p0, v1

    .line 24
    .line 25
    const/4 v4, 0x6

    .line 26
    if-ne v3, v4, :cond_1

    .line 27
    .line 28
    const/4 p0, 0x1

    .line 29
    return p0

    .line 30
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_2
    return v2
.end method


# virtual methods
.method public A(Ljava/lang/String;Z)Lcom/google/android/gms/internal/measurement/n4;
    .locals 2

    .line 1
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    sget-object v0, Lcom/google/android/gms/internal/measurement/n4;->g:Ljava/lang/Object;

    .line 6
    .line 7
    new-instance v0, Lcom/google/android/gms/internal/measurement/n4;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-direct {v0, p0, p1, p2, v1}, Lcom/google/android/gms/internal/measurement/n4;-><init>(Lb6/f;Ljava/lang/String;Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public B(Ljava/lang/String;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/n4;
    .locals 2

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/n4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    new-instance v0, Lcom/google/android/gms/internal/measurement/n4;

    .line 4
    .line 5
    const/4 v1, 0x3

    .line 6
    invoke-direct {v0, p0, p1, p2, v1}, Lcom/google/android/gms/internal/measurement/n4;-><init>(Lb6/f;Ljava/lang/String;Ljava/lang/Object;I)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method public a(Landroid/hardware/camera2/TotalCaptureResult;)V
    .locals 0

    .line 1
    return-void
.end method

.method public b(Lb0/h1;)V
    .locals 2

    .line 1
    invoke-static {}, Lu/a;->b()Landroid/hardware/camera2/CaptureRequest$Key;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/high16 v1, 0x3f800000    # 1.0f

    .line 6
    .line 7
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1, v0, v1}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-boolean p0, p0, Lb6/f;->d:Z

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 19
    .line 20
    const/16 v0, 0x22

    .line 21
    .line 22
    if-lt p0, v0, :cond_0

    .line 23
    .line 24
    invoke-static {}, Lt51/b;->f()Landroid/hardware/camera2/CaptureRequest$Key;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {p1, p0, v0}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    return-void
.end method

.method public c()Lbb/g0;
    .locals 4

    .line 1
    new-instance v0, Lin/z1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-boolean v1, p0, Lb6/f;->d:Z

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    sget-object v1, Llp/sb;->f:Llp/sb;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    sget-object v1, Llp/sb;->e:Llp/sb;

    .line 14
    .line 15
    :goto_0
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Llp/tb;

    .line 18
    .line 19
    iput-object v1, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 20
    .line 21
    new-instance v1, Lj1/a;

    .line 22
    .line 23
    const/16 v2, 0xb

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-direct {v1, v2, v3}, Lj1/a;-><init>(IZ)V

    .line 27
    .line 28
    .line 29
    iput-object p0, v1, Lj1/a;->e:Ljava/lang/Object;

    .line 30
    .line 31
    new-instance p0, Llp/te;

    .line 32
    .line 33
    invoke-direct {p0, v1}, Llp/te;-><init>(Lj1/a;)V

    .line 34
    .line 35
    .line 36
    iput-object p0, v0, Lin/z1;->e:Ljava/lang/Object;

    .line 37
    .line 38
    new-instance p0, Lbb/g0;

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    const/4 v2, 0x0

    .line 42
    invoke-direct {p0, v0, v1, v2}, Lbb/g0;-><init>(Lin/z1;IB)V

    .line 43
    .line 44
    .line 45
    return-object p0
.end method

.method public d(Los/j;I)V
    .locals 1

    .line 1
    iget-object p1, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    iget-boolean v0, p0, Lb6/f;->d:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput-boolean v0, p0, Lb6/f;->d:Z

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-string p0, ", "

    .line 14
    .line 15
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    :goto_0
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public e()F
    .locals 0

    .line 1
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/util/Range;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljava/lang/Float;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public f()V
    .locals 0

    .line 1
    return-void
.end method

.method public g()F
    .locals 0

    .line 1
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/util/Range;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ljava/lang/Float;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public h(I)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lb6/f;->d:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    xor-int/2addr v0, v1

    .line 5
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Landroid/util/SparseBooleanArray;

    .line 11
    .line 12
    invoke-virtual {p0, p1, v1}, Landroid/util/SparseBooleanArray;->append(IZ)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public i()Lt7/m;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lb6/f;->d:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    xor-int/2addr v0, v1

    .line 5
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 6
    .line 7
    .line 8
    iput-boolean v1, p0, Lb6/f;->d:Z

    .line 9
    .line 10
    new-instance v0, Lt7/m;

    .line 11
    .line 12
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Landroid/util/SparseBooleanArray;

    .line 15
    .line 16
    invoke-direct {v0, p0}, Lt7/m;-><init>(Landroid/util/SparseBooleanArray;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public k(Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;
    .locals 5

    .line 1
    iget-boolean v0, p0, Lb6/f;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lu/k;

    .line 6
    .line 7
    const/4 v1, 0x2

    .line 8
    invoke-direct {v0, v1}, Lu/k;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iget-object v2, v0, Lu/k;->b:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, Ly4/k;

    .line 14
    .line 15
    iget-object v3, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v3, Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {v3, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    new-instance v3, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v4, "RequestListener "

    .line 25
    .line 26
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v4, " monitoring "

    .line 33
    .line 34
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    const-string v4, "RequestMonitor"

    .line 45
    .line 46
    invoke-static {v4, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 47
    .line 48
    .line 49
    new-instance v3, La8/y0;

    .line 50
    .line 51
    const/16 v4, 0x19

    .line 52
    .line 53
    invoke-direct {v3, p0, v0, v2, v4}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    iget-object v2, v2, Ly4/k;->e:Ly4/j;

    .line 61
    .line 62
    invoke-virtual {v2, p0, v3}, Ly4/g;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 63
    .line 64
    .line 65
    new-array p0, v1, [Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 66
    .line 67
    const/4 v1, 0x0

    .line 68
    aput-object v0, p0, v1

    .line 69
    .line 70
    const/4 v0, 0x1

    .line 71
    aput-object p1, p0, v0

    .line 72
    .line 73
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    new-instance p1, Lu/a0;

    .line 78
    .line 79
    invoke-direct {p1, p0}, Lu/a0;-><init>(Ljava/util/List;)V

    .line 80
    .line 81
    .line 82
    :cond_0
    return-object p1
.end method

.method public l()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lb6/f;->d:Z

    .line 2
    .line 3
    return p0
.end method

.method public m()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 4

    .line 1
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    sget-object p0, Lk0/j;->f:Lk0/j;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-direct {v0, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 17
    .line 18
    .line 19
    new-instance p0, Lk0/k;

    .line 20
    .line 21
    new-instance v1, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 24
    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-direct {p0, v1, v0, v2}, Lk0/k;-><init>(Ljava/util/ArrayList;ZLj0/a;)V

    .line 32
    .line 33
    .line 34
    new-instance v0, Lt0/c;

    .line 35
    .line 36
    const/16 v1, 0x16

    .line 37
    .line 38
    invoke-direct {v0, v1}, Lt0/c;-><init>(I)V

    .line 39
    .line 40
    .line 41
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    new-instance v2, Lh6/e;

    .line 46
    .line 47
    const/16 v3, 0x9

    .line 48
    .line 49
    invoke-direct {v2, v0, v3}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 50
    .line 51
    .line 52
    invoke-static {p0, v2, v1}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method

.method public n(ILjava/lang/CharSequence;)Z
    .locals 6

    .line 1
    if-eqz p2, :cond_6

    .line 2
    .line 3
    if-ltz p1, :cond_6

    .line 4
    .line 5
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    sub-int/2addr v0, p1

    .line 10
    if-ltz v0, :cond_6

    .line 11
    .line 12
    iget-object v0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Lb6/e;

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lb6/f;->l()Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    const/4 v1, 0x2

    .line 28
    move v2, v0

    .line 29
    move v3, v1

    .line 30
    :goto_0
    const/4 v4, 0x1

    .line 31
    if-ge v2, p1, :cond_3

    .line 32
    .line 33
    if-ne v3, v1, :cond_3

    .line 34
    .line 35
    invoke-interface {p2, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    invoke-static {v3}, Ljava/lang/Character;->getDirectionality(C)B

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    sget-object v5, Lb6/g;->a:Lb6/f;

    .line 44
    .line 45
    if-eqz v3, :cond_2

    .line 46
    .line 47
    if-eq v3, v4, :cond_1

    .line 48
    .line 49
    if-eq v3, v1, :cond_1

    .line 50
    .line 51
    packed-switch v3, :pswitch_data_0

    .line 52
    .line 53
    .line 54
    move v3, v1

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    :pswitch_0
    move v3, v0

    .line 57
    goto :goto_1

    .line 58
    :cond_2
    :pswitch_1
    move v3, v4

    .line 59
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    if-eqz v3, :cond_5

    .line 63
    .line 64
    if-eq v3, v4, :cond_4

    .line 65
    .line 66
    invoke-virtual {p0}, Lb6/f;->l()Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    return p0

    .line 71
    :cond_4
    return v0

    .line 72
    :cond_5
    return v4

    .line 73
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 74
    .line 75
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 76
    .line 77
    .line 78
    throw p0

    .line 79
    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public o()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lb6/f;->d:Z

    .line 3
    .line 4
    return-void
.end method

.method public p(B)V
    .locals 2

    .line 1
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb11/a;

    .line 4
    .line 5
    int-to-long v0, p1

    .line 6
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lb11/a;->m(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public q(C)V
    .locals 3

    .line 1
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb11/a;

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iget v1, p0, Lb11/a;->e:I

    .line 7
    .line 8
    invoke-virtual {p0, v1, v0}, Lb11/a;->b(II)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, [C

    .line 14
    .line 15
    iget v1, p0, Lb11/a;->e:I

    .line 16
    .line 17
    add-int/lit8 v2, v1, 0x1

    .line 18
    .line 19
    iput v2, p0, Lb11/a;->e:I

    .line 20
    .line 21
    aput-char p1, v0, v1

    .line 22
    .line 23
    return-void
.end method

.method public r(I)V
    .locals 2

    .line 1
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb11/a;

    .line 4
    .line 5
    int-to-long v0, p1

    .line 6
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lb11/a;->m(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public s(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb11/a;

    .line 4
    .line 5
    invoke-static {p1, p2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Lb11/a;->m(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public t(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "v"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lb11/a;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lb11/a;->m(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public u(S)V
    .locals 2

    .line 1
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb11/a;

    .line 4
    .line 5
    int-to-long v0, p1

    .line 6
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lb11/a;->m(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public v(Ljava/lang/String;)V
    .locals 10

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lb11/a;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v1, 0x2

    .line 15
    add-int/2addr v0, v1

    .line 16
    iget v2, p0, Lb11/a;->e:I

    .line 17
    .line 18
    invoke-virtual {p0, v2, v0}, Lb11/a;->b(II)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, [C

    .line 24
    .line 25
    iget v2, p0, Lb11/a;->e:I

    .line 26
    .line 27
    add-int/lit8 v3, v2, 0x1

    .line 28
    .line 29
    const/16 v4, 0x22

    .line 30
    .line 31
    aput-char v4, v0, v2

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    const/4 v5, 0x0

    .line 38
    invoke-virtual {p1, v5, v2, v0, v3}, Ljava/lang/String;->getChars(II[CI)V

    .line 39
    .line 40
    .line 41
    add-int/2addr v2, v3

    .line 42
    move v6, v3

    .line 43
    :goto_0
    if-ge v6, v2, :cond_5

    .line 44
    .line 45
    aget-char v7, v0, v6

    .line 46
    .line 47
    sget-object v8, Lwz0/e0;->b:[B

    .line 48
    .line 49
    array-length v9, v8

    .line 50
    if-ge v7, v9, :cond_4

    .line 51
    .line 52
    aget-byte v7, v8, v7

    .line 53
    .line 54
    if-eqz v7, :cond_4

    .line 55
    .line 56
    sub-int v0, v6, v3

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    :goto_1
    const/4 v3, 0x1

    .line 63
    if-ge v0, v2, :cond_3

    .line 64
    .line 65
    invoke-virtual {p0, v6, v1}, Lb11/a;->b(II)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    .line 69
    .line 70
    .line 71
    move-result v7

    .line 72
    sget-object v8, Lwz0/e0;->b:[B

    .line 73
    .line 74
    array-length v9, v8

    .line 75
    if-ge v7, v9, :cond_2

    .line 76
    .line 77
    aget-byte v8, v8, v7

    .line 78
    .line 79
    if-nez v8, :cond_0

    .line 80
    .line 81
    iget-object v3, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v3, [C

    .line 84
    .line 85
    add-int/lit8 v8, v6, 0x1

    .line 86
    .line 87
    int-to-char v7, v7

    .line 88
    aput-char v7, v3, v6

    .line 89
    .line 90
    :goto_2
    move v6, v8

    .line 91
    goto :goto_3

    .line 92
    :cond_0
    if-ne v8, v3, :cond_1

    .line 93
    .line 94
    sget-object v3, Lwz0/e0;->a:[Ljava/lang/String;

    .line 95
    .line 96
    aget-object v3, v3, v7

    .line 97
    .line 98
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 102
    .line 103
    .line 104
    move-result v7

    .line 105
    invoke-virtual {p0, v6, v7}, Lb11/a;->b(II)V

    .line 106
    .line 107
    .line 108
    iget-object v7, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v7, [C

    .line 111
    .line 112
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 113
    .line 114
    .line 115
    move-result v8

    .line 116
    invoke-virtual {v3, v5, v8, v7, v6}, Ljava/lang/String;->getChars(II[CI)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    add-int/2addr v3, v6

    .line 124
    iput v3, p0, Lb11/a;->e:I

    .line 125
    .line 126
    move v6, v3

    .line 127
    goto :goto_3

    .line 128
    :cond_1
    iget-object v3, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v3, [C

    .line 131
    .line 132
    const/16 v7, 0x5c

    .line 133
    .line 134
    aput-char v7, v3, v6

    .line 135
    .line 136
    add-int/lit8 v7, v6, 0x1

    .line 137
    .line 138
    int-to-char v8, v8

    .line 139
    aput-char v8, v3, v7

    .line 140
    .line 141
    add-int/lit8 v6, v6, 0x2

    .line 142
    .line 143
    iput v6, p0, Lb11/a;->e:I

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_2
    iget-object v3, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v3, [C

    .line 149
    .line 150
    add-int/lit8 v8, v6, 0x1

    .line 151
    .line 152
    int-to-char v7, v7

    .line 153
    aput-char v7, v3, v6

    .line 154
    .line 155
    goto :goto_2

    .line 156
    :goto_3
    add-int/lit8 v0, v0, 0x1

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_3
    invoke-virtual {p0, v6, v3}, Lb11/a;->b(II)V

    .line 160
    .line 161
    .line 162
    iget-object p1, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast p1, [C

    .line 165
    .line 166
    add-int/lit8 v0, v6, 0x1

    .line 167
    .line 168
    aput-char v4, p1, v6

    .line 169
    .line 170
    iput v0, p0, Lb11/a;->e:I

    .line 171
    .line 172
    return-void

    .line 173
    :cond_4
    add-int/lit8 v6, v6, 0x1

    .line 174
    .line 175
    goto/16 :goto_0

    .line 176
    .line 177
    :cond_5
    add-int/lit8 p1, v2, 0x1

    .line 178
    .line 179
    aput-char v4, v0, v2

    .line 180
    .line 181
    iput p1, p0, Lb11/a;->e:I

    .line 182
    .line 183
    return-void
.end method

.method public w()V
    .locals 0

    .line 1
    return-void
.end method

.method public x()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/LinkedList;

    .line 2
    .line 3
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/util/List;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Ljava/util/LinkedList;-><init>(Ljava/util/Collection;)V

    .line 8
    .line 9
    .line 10
    :goto_0
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/util/LinkedList;->poll()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 21
    .line 22
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 26
    .line 27
    const/4 v1, 0x1

    .line 28
    invoke-interface {p0, v1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    return-void
.end method

.method public y()V
    .locals 0

    .line 1
    return-void
.end method

.method public z(JLjava/lang/String;)Lcom/google/android/gms/internal/measurement/n4;
    .locals 1

    .line 1
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    sget-object p2, Lcom/google/android/gms/internal/measurement/n4;->g:Ljava/lang/Object;

    .line 6
    .line 7
    new-instance p2, Lcom/google/android/gms/internal/measurement/n4;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    invoke-direct {p2, p0, p3, p1, v0}, Lcom/google/android/gms/internal/measurement/n4;-><init>(Lb6/f;Ljava/lang/String;Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    return-object p2
.end method

.class public final Lu/e0;
.super Landroid/hardware/camera2/CameraManager$AvailabilityCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lb0/d1;


# direct methods
.method public constructor <init>(Lb0/d1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lu/e0;->a:Lb0/d1;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/hardware/camera2/CameraManager$AvailabilityCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onCameraAccessPrioritiesChanged()V
    .locals 2

    .line 1
    const-string v0, "Camera2PresenceSrc"

    .line 2
    .line 3
    const-string v1, "System onCameraAccessPrioritiesChanged."

    .line 4
    .line 5
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lu/e0;->a:Lb0/d1;

    .line 9
    .line 10
    invoke-virtual {p0}, Lb0/d1;->d()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly4/k;

    .line 15
    .line 16
    new-instance v0, Lk0/e;

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    invoke-direct {v0, p0, v1}, Lk0/e;-><init>(Lcom/google/common/util/concurrent/ListenableFuture;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public final onCameraAvailable(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "cameraId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "System onCameraAvailable: "

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v0, "Camera2PresenceSrc"

    .line 13
    .line 14
    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lu/e0;->a:Lb0/d1;

    .line 18
    .line 19
    invoke-virtual {p0}, Lb0/d1;->d()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Ly4/k;

    .line 24
    .line 25
    new-instance p1, Lk0/e;

    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    invoke-direct {p1, p0, v0}, Lk0/e;-><init>(Lcom/google/common/util/concurrent/ListenableFuture;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {p1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final onCameraUnavailable(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "cameraId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "System onCameraUnavailable: "

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v0, "Camera2PresenceSrc"

    .line 13
    .line 14
    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lu/e0;->a:Lb0/d1;

    .line 18
    .line 19
    invoke-virtual {p0}, Lb0/d1;->d()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Ly4/k;

    .line 24
    .line 25
    new-instance p1, Lk0/e;

    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    invoke-direct {p1, p0, v0}, Lk0/e;-><init>(Lcom/google/common/util/concurrent/ListenableFuture;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {p1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 32
    .line 33
    .line 34
    return-void
.end method

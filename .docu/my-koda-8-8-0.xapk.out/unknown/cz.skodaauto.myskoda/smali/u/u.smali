.class public final Lu/u;
.super Landroid/hardware/camera2/CameraManager$AvailabilityCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public b:Z

.field public final synthetic c:Lu/y;


# direct methods
.method public constructor <init>(Lu/y;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lu/u;->c:Lu/y;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/hardware/camera2/CameraManager$AvailabilityCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    iput-boolean p1, p0, Lu/u;->b:Z

    .line 8
    .line 9
    iput-object p2, p0, Lu/u;->a:Ljava/lang/String;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final onCameraAvailable(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lu/u;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p1, 0x1

    .line 11
    iput-boolean p1, p0, Lu/u;->b:Z

    .line 12
    .line 13
    iget-object p1, p0, Lu/u;->c:Lu/y;

    .line 14
    .line 15
    iget p1, p1, Lu/y;->O:I

    .line 16
    .line 17
    const/4 v0, 0x4

    .line 18
    if-eq p1, v0, :cond_2

    .line 19
    .line 20
    iget-object p1, p0, Lu/u;->c:Lu/y;

    .line 21
    .line 22
    iget p1, p1, Lu/y;->O:I

    .line 23
    .line 24
    const/4 v0, 0x5

    .line 25
    if-ne p1, v0, :cond_1

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    :goto_0
    return-void

    .line 29
    :cond_2
    :goto_1
    iget-object p0, p0, Lu/u;->c:Lu/y;

    .line 30
    .line 31
    const/4 p1, 0x0

    .line 32
    invoke-virtual {p0, p1}, Lu/y;->L(Z)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final onCameraUnavailable(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lu/u;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    const/4 p1, 0x0

    .line 11
    iput-boolean p1, p0, Lu/u;->b:Z

    .line 12
    .line 13
    return-void
.end method

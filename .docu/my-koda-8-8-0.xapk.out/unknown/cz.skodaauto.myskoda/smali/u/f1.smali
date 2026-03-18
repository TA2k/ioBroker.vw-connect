.class public final synthetic Lu/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lu/g1;


# direct methods
.method public synthetic constructor <init>(Lu/g1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lu/f1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu/f1;->e:Lu/g1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Lu/f1;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lu/f1;->e:Lu/g1;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "Session call super.close()"

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lu/g1;->k(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 14
    .line 15
    const-string v1, "Need to call openCaptureSession before using this API."

    .line 16
    .line 17
    invoke-static {v0, v1}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Lu/g1;->b:Lu/x0;

    .line 21
    .line 22
    iget-object v1, v0, Lu/x0;->b:Ljava/lang/Object;

    .line 23
    .line 24
    monitor-enter v1

    .line 25
    :try_start_0
    iget-object v0, v0, Lu/x0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Ljava/util/LinkedHashSet;

    .line 28
    .line 29
    invoke-interface {v0, p0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    iget-object v0, p0, Lu/g1;->f:Lro/f;

    .line 34
    .line 35
    iget-object v0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Lb81/c;

    .line 38
    .line 39
    iget-object v0, v0, Lb81/c;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Landroid/hardware/camera2/CameraCaptureSession;

    .line 42
    .line 43
    invoke-virtual {v0}, Landroid/hardware/camera2/CameraCaptureSession;->close()V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Lu/g1;->c:Lj0/h;

    .line 47
    .line 48
    new-instance v1, Lu/f1;

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    invoke-direct {v1, p0, v2}, Lu/f1;-><init>(Lu/g1;I)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :catchall_0
    move-exception p0

    .line 59
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 60
    throw p0

    .line 61
    :pswitch_0
    invoke-virtual {p0, p0}, Lu/g1;->g(Lu/g1;)V

    .line 62
    .line 63
    .line 64
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

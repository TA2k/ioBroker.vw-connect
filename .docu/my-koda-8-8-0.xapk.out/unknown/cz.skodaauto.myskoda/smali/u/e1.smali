.class public final synthetic Lu/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lu/g1;

.field public final synthetic f:Lu/g1;


# direct methods
.method public synthetic constructor <init>(Lu/g1;Lu/g1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lu/e1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu/e1;->e:Lu/g1;

    .line 4
    .line 5
    iput-object p2, p0, Lu/e1;->f:Lu/g1;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, Lu/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lu/e1;->e:Lu/g1;

    .line 7
    .line 8
    iget-object p0, p0, Lu/e1;->f:Lu/g1;

    .line 9
    .line 10
    iget-object v1, v0, Lu/g1;->e:Lu/o0;

    .line 11
    .line 12
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    iget-object v0, v0, Lu/g1;->e:Lu/o0;

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Lu/o0;->g(Lu/g1;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_0
    iget-object v0, p0, Lu/e1;->e:Lu/g1;

    .line 22
    .line 23
    iget-object p0, p0, Lu/e1;->f:Lu/g1;

    .line 24
    .line 25
    iget-object v1, v0, Lu/g1;->b:Lu/x0;

    .line 26
    .line 27
    iget-object v2, v1, Lu/x0;->b:Ljava/lang/Object;

    .line 28
    .line 29
    monitor-enter v2

    .line 30
    :try_start_0
    iget-object v3, v1, Lu/x0;->c:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v3, Ljava/util/LinkedHashSet;

    .line 33
    .line 34
    invoke-interface {v3, v0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    iget-object v1, v1, Lu/x0;->d:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v1, Ljava/util/LinkedHashSet;

    .line 40
    .line 41
    invoke-interface {v1, v0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    invoke-virtual {v0, p0}, Lu/g1;->g(Lu/g1;)V

    .line 46
    .line 47
    .line 48
    iget-object v1, v0, Lu/g1;->f:Lro/f;

    .line 49
    .line 50
    if-eqz v1, :cond_0

    .line 51
    .line 52
    iget-object v1, v0, Lu/g1;->e:Lu/o0;

    .line 53
    .line 54
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    iget-object v0, v0, Lu/g1;->e:Lu/o0;

    .line 58
    .line 59
    invoke-virtual {v0, p0}, Lu/o0;->c(Lu/g1;)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    const-string p0, "SyncCaptureSessionBase"

    .line 64
    .line 65
    new-instance v1, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    const-string v2, "["

    .line 68
    .line 69
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v0, "] Cannot call onClosed() when the CameraCaptureSession is not correctly configured."

    .line 76
    .line 77
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-static {p0, v0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    :goto_0
    return-void

    .line 88
    :catchall_0
    move-exception p0

    .line 89
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 90
    throw p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

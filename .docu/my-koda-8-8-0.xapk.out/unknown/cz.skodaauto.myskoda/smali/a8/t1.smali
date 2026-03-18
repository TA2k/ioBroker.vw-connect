.class public final La8/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:Z


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, La8/t1;->a:I

    packed-switch p1, :pswitch_data_0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    const-class p1, Landroidx/camera/core/internal/compat/quirk/SurfaceOrderQuirk;

    .line 5
    sget-object v0, Lm0/a;->a:Ld01/x;

    invoke-virtual {v0, p1}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    .line 6
    :goto_0
    iput-boolean p1, p0, La8/t1;->b:Z

    return-void

    .line 7
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    const-class p1, Landroidx/camera/camera2/internal/compat/quirk/TorchIsClosedAfterImageCapturingQuirk;

    .line 9
    sget-object v0, Lx/a;->a:Ld01/x;

    invoke-virtual {v0, p1}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object p1

    if-eqz p1, :cond_1

    const/4 p1, 0x1

    goto :goto_1

    :cond_1
    const/4 p1, 0x0

    .line 10
    :goto_1
    iput-boolean p1, p0, La8/t1;->b:Z

    return-void

    .line 11
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    const-class p1, Landroidx/camera/camera2/internal/compat/quirk/StillCaptureFlashStopRepeatingQuirk;

    .line 13
    sget-object v0, Lx/a;->a:Ld01/x;

    invoke-virtual {v0, p1}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object p1

    .line 14
    check-cast p1, Landroidx/camera/camera2/internal/compat/quirk/StillCaptureFlashStopRepeatingQuirk;

    if-eqz p1, :cond_2

    const/4 p1, 0x1

    goto :goto_2

    :cond_2
    const/4 p1, 0x0

    .line 15
    :goto_2
    iput-boolean p1, p0, La8/t1;->b:Z

    return-void

    :pswitch_data_0
    .packed-switch 0x6
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;Lw7/r;I)V
    .locals 0

    iput p4, p0, La8/t1;->a:I

    packed-switch p4, :pswitch_data_0

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    new-instance p0, Let/d;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const/4 p4, 0x1

    invoke-direct {p0, p1, p4}, Let/d;-><init>(Ljava/lang/Object;I)V

    const/4 p0, 0x0

    .line 18
    invoke-virtual {p3, p2, p0}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    return-void

    .line 19
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    new-instance p0, Lfv/b;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    invoke-direct {p0, p1}, Lfv/b;-><init>(Landroid/content/Context;)V

    const/4 p0, 0x0

    .line 21
    invoke-virtual {p3, p2, p0}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Ld01/x;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, La8/t1;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    const-class v0, Landroidx/camera/camera2/internal/compat/quirk/Preview3AThreadCrashQuirk;

    invoke-virtual {p1, v0}, Ld01/x;->k(Ljava/lang/Class;)Z

    move-result p1

    iput-boolean p1, p0, La8/t1;->b:Z

    return-void
.end method

.method public constructor <init>(Lx7/n;Lx7/p;)V
    .locals 5

    const/4 v0, 0x4

    iput v0, p0, La8/t1;->a:I

    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    iget v0, p2, Lx7/p;->a:I

    iget-object p2, p2, Lx7/p;->b:Ljava/nio/ByteBuffer;

    const/4 v1, 0x6

    const/4 v2, 0x0

    const/4 v3, 0x3

    const/4 v4, 0x1

    if-eq v0, v1, :cond_1

    if-ne v0, v3, :cond_0

    goto :goto_0

    :cond_0
    move v0, v2

    goto :goto_1

    :cond_1
    :goto_0
    move v0, v4

    :goto_1
    invoke-static {v0}, Lw7/a;->c(Z)V

    const/4 v0, 0x4

    .line 26
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    move-result v1

    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    move-result v0

    new-array v1, v0, [B

    .line 27
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->asReadOnlyBuffer()Ljava/nio/ByteBuffer;

    move-result-object p2

    invoke-virtual {p2, v1}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 28
    new-instance p2, Lm9/f;

    .line 29
    invoke-direct {p2, v0, v1}, Lm9/f;-><init>(I[B)V

    .line 30
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    invoke-virtual {p2}, Lm9/f;->h()Z

    move-result p1

    if-eqz p1, :cond_2

    .line 32
    iput-boolean v2, p0, La8/t1;->b:Z

    goto :goto_2

    :cond_2
    const/4 p1, 0x2

    .line 33
    invoke-virtual {p2, p1}, Lm9/f;->i(I)I

    move-result p1

    .line 34
    invoke-virtual {p2}, Lm9/f;->h()Z

    move-result v0

    if-nez v0, :cond_3

    .line 35
    iput-boolean v4, p0, La8/t1;->b:Z

    :goto_2
    return-void

    :cond_3
    if-eq p1, v3, :cond_5

    if-nez p1, :cond_4

    goto :goto_3

    .line 36
    :cond_4
    invoke-virtual {p2}, Lm9/f;->h()Z

    .line 37
    :cond_5
    :goto_3
    invoke-virtual {p2}, Lm9/f;->s()V

    .line 38
    new-instance p0, Lx7/o;

    .line 39
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    .line 40
    throw p0
.end method

.method public constructor <init>(Z)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, La8/t1;->a:I

    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    iput-boolean p1, p0, La8/t1;->b:Z

    return-void
.end method

.method public static a(Lh0/o0;)Lh0/o0;
    .locals 4

    .line 1
    new-instance v0, Lb0/n1;

    .line 2
    .line 3
    invoke-direct {v0}, Lb0/n1;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Lh0/o0;->c:I

    .line 7
    .line 8
    iput v1, v0, Lb0/n1;->d:I

    .line 9
    .line 10
    iget-object v1, p0, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Lh0/t0;

    .line 31
    .line 32
    iget-object v3, v0, Lb0/n1;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v3, Ljava/util/HashSet;

    .line 35
    .line 36
    invoke-virtual {v3, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    iget-object p0, p0, Lh0/o0;->b:Lh0/n1;

    .line 41
    .line 42
    invoke-virtual {v0, p0}, Lb0/n1;->i(Lh0/q0;)V

    .line 43
    .line 44
    .line 45
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    sget-object v1, Landroid/hardware/camera2/CaptureRequest;->FLASH_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 50
    .line 51
    const/4 v2, 0x0

    .line 52
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    invoke-static {v1}, Lt/a;->X(Landroid/hardware/camera2/CaptureRequest$Key;)Lh0/g;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {p0, v1, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    new-instance v1, Lt/a;

    .line 64
    .line 65
    invoke-static {p0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const/4 v2, 0x0

    .line 70
    invoke-direct {v1, p0, v2}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0, v1}, Lb0/n1;->i(Lh0/q0;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0}, Lb0/n1;->j()Lh0/o0;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0
.end method


# virtual methods
.method public b(Ljava/util/ArrayList;Z)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, La8/t1;->b:Z

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    if-eqz p2, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eqz p1, :cond_1

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Landroid/hardware/camera2/CaptureRequest;

    .line 22
    .line 23
    sget-object p2, Landroid/hardware/camera2/CaptureRequest;->FLASH_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 24
    .line 25
    invoke-virtual {p1, p2}, Landroid/hardware/camera2/CaptureRequest;->get(Landroid/hardware/camera2/CaptureRequest$Key;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    check-cast p1, Ljava/lang/Integer;

    .line 30
    .line 31
    if-eqz p1, :cond_0

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    const/4 p2, 0x2

    .line 38
    if-ne p1, p2, :cond_0

    .line 39
    .line 40
    const/4 p0, 0x1

    .line 41
    return p0

    .line 42
    :cond_1
    const/4 p0, 0x0

    .line 43
    return p0
.end method

.method public c(Z)V
    .locals 1

    .line 1
    iget v0, p0, La8/t1;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, La8/t1;->b:Z

    .line 7
    .line 8
    if-ne v0, p1, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    iput-boolean p1, p0, La8/t1;->b:Z

    .line 12
    .line 13
    :goto_0
    return-void

    .line 14
    :pswitch_0
    iget-boolean v0, p0, La8/t1;->b:Z

    .line 15
    .line 16
    if-ne v0, p1, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    iput-boolean p1, p0, La8/t1;->b:Z

    .line 20
    .line 21
    :goto_1
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public d(Ljava/util/ArrayList;Z)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, La8/t1;->b:Z

    .line 2
    .line 3
    if-eqz p0, :cond_3

    .line 4
    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-eqz p1, :cond_3

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Landroid/hardware/camera2/CaptureRequest;

    .line 23
    .line 24
    sget-object p2, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AE_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 25
    .line 26
    invoke-virtual {p1, p2}, Landroid/hardware/camera2/CaptureRequest;->get(Landroid/hardware/camera2/CaptureRequest$Key;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    check-cast p1, Ljava/lang/Integer;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    const/4 p2, 0x2

    .line 37
    if-eq p1, p2, :cond_2

    .line 38
    .line 39
    const/4 p2, 0x3

    .line 40
    if-ne p1, p2, :cond_1

    .line 41
    .line 42
    :cond_2
    const/4 p0, 0x1

    .line 43
    return p0

    .line 44
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 45
    return p0
.end method

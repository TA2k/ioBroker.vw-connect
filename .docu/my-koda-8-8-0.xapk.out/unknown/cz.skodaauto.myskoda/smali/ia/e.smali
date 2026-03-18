.class public final synthetic Lia/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/Choreographer$FrameCallback;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroidx/profileinstaller/ProfileInstallerInitializer;Landroid/content/Context;)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    iput p1, p0, Lia/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lia/e;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lvy0/l;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lia/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lia/e;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final doFrame(J)V
    .locals 3

    .line 1
    iget v0, p0, Lia/e;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lia/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lvy0/l;

    .line 9
    .line 10
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 11
    .line 12
    sget-object v0, Laz0/m;->a:Lwy0/c;

    .line 13
    .line 14
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0, v0, p1}, Lvy0/l;->D(Lvy0/x;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_0
    check-cast p0, Landroid/content/Context;

    .line 23
    .line 24
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-static {p1}, Landroid/os/Handler;->createAsync(Landroid/os/Looper;)Landroid/os/Handler;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    new-instance p2, Ljava/util/Random;

    .line 33
    .line 34
    invoke-direct {p2}, Ljava/util/Random;-><init>()V

    .line 35
    .line 36
    .line 37
    const/16 v0, 0x3e8

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    invoke-virtual {p2, v0}, Ljava/util/Random;->nextInt(I)I

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    new-instance v0, Lh/k;

    .line 49
    .line 50
    const/4 v1, 0x2

    .line 51
    invoke-direct {v0, p0, v1}, Lh/k;-><init>(Landroid/content/Context;I)V

    .line 52
    .line 53
    .line 54
    add-int/lit16 p2, p2, 0x1388

    .line 55
    .line 56
    int-to-long v1, p2

    .line 57
    invoke-virtual {p1, v0, v1, v2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

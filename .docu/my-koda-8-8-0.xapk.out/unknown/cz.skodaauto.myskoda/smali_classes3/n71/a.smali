.class public interface abstract Ln71/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static synthetic a(Ln71/a;Lay0/a;)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    invoke-interface {p0, v0, v1, p1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static synthetic b(Ln71/a;Lay0/a;)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    invoke-interface {p0, v0, v1, p1}, Ln71/a;->dispatchToIOThread(JLay0/a;)Ln71/b;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static synthetic d(Ln71/a;Lay0/a;)Ln71/b;
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    invoke-interface {p0, v0, v1, p1}, Ln71/a;->dispatchToMainThread(JLay0/a;)Ln71/b;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method


# virtual methods
.method public abstract cancelAllDispatchJobs()V
.end method

.method public abstract dispatchToIOThread(JLay0/a;)Ln71/b;
.end method

.method public abstract dispatchToMainThread(JLay0/a;)Ln71/b;
.end method

.method public abstract dispatchToRPAThread(JLay0/a;)Ln71/b;
.end method

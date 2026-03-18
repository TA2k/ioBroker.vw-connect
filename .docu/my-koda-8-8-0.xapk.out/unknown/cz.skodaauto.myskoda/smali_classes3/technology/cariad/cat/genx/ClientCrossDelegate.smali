.class public final Ltechnology/cariad/cat/genx/ClientCrossDelegate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/ClientDelegate;
.implements Ltechnology/cariad/cat/genx/Referencing;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0014\u0008\u0000\u0018\u00002\u00020\u00012\u00020\u0002B\u0017\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0010\u0010\n\u001a\u00020\tH\u0083 \u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0010\u0010\r\u001a\u00020\u000cH\u0083 \u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0010\u0010\u000f\u001a\u00020\u000cH\u0083 \u00a2\u0006\u0004\u0008\u000f\u0010\u000eJ(\u0010\u0016\u001a\u00020\u000c2\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0015\u001a\u00020\u0014H\u0083 \u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u0018\u0010\u001a\u001a\u00020\u000c2\u0006\u0010\u0019\u001a\u00020\u0018H\u0083 \u00a2\u0006\u0004\u0008\u001a\u0010\u001bJ\u0010\u0010\u001c\u001a\u00020\u0012H\u0083 \u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\u000f\u0010\u001e\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008\u001e\u0010\u000bJ\r\u0010\u001f\u001a\u00020\t\u00a2\u0006\u0004\u0008\u001f\u0010\u000bJ\u000f\u0010 \u001a\u00020\tH\u0017\u00a2\u0006\u0004\u0008 \u0010\u000bJ\u000f\u0010!\u001a\u00020\tH\u0017\u00a2\u0006\u0004\u0008!\u0010\u000bJ\'\u0010\"\u001a\u00020\t2\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0015\u001a\u00020\u0014H\u0017\u00a2\u0006\u0004\u0008\"\u0010#J\u0017\u0010$\u001a\u00020\t2\u0006\u0010\u0019\u001a\u00020\u0018H\u0017\u00a2\u0006\u0004\u0008$\u0010%J\u000f\u0010&\u001a\u00020\u0012H\u0017\u00a2\u0006\u0004\u0008&\u0010\u001dR\u0014\u0010\u0006\u001a\u00020\u00058\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0006\u0010\'R\u0016\u0010(\u001a\u00020\u00038\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008(\u0010)R\u0014\u0010\u0004\u001a\u00020\u00038VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008*\u0010+\u00a8\u0006,"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/ClientCrossDelegate;",
        "Ltechnology/cariad/cat/genx/ClientDelegate;",
        "Ltechnology/cariad/cat/genx/Referencing;",
        "",
        "reference",
        "Ltechnology/cariad/cat/genx/Client;",
        "client",
        "<init>",
        "(JLtechnology/cariad/cat/genx/Client;)V",
        "Llx0/b0;",
        "destroy",
        "()V",
        "",
        "nativeClientDidConnect",
        "()I",
        "nativeClientDidDisconnect",
        "Ltechnology/cariad/cat/genx/Channel;",
        "channel",
        "",
        "success",
        "",
        "message",
        "nativeClientDidDiscover",
        "(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)I",
        "Ltechnology/cariad/cat/genx/TypedFrame;",
        "typedFrame",
        "nativeClientDidReceive",
        "(Ltechnology/cariad/cat/genx/TypedFrame;)I",
        "nativeClientShouldBeRemovedAfterAdvertisementDidStop",
        "()Z",
        "close",
        "finalize",
        "onClientConnected",
        "onClientDisconnected",
        "onClientDiscoveredChannel",
        "(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)V",
        "onClientReceivedTypedFrame",
        "(Ltechnology/cariad/cat/genx/TypedFrame;)V",
        "shouldClientBeRemovedAfterAdvertisementStopped",
        "Ltechnology/cariad/cat/genx/Client;",
        "_reference",
        "J",
        "getReference",
        "()J",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private _reference:J

.field private final client:Ltechnology/cariad/cat/genx/Client;


# direct methods
.method public constructor <init>(JLtechnology/cariad/cat/genx/Client;)V
    .locals 1

    .line 1
    const-string v0, "client"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p3, p0, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->client:Ltechnology/cariad/cat/genx/Client;

    .line 10
    .line 11
    iput-wide p1, p0, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->_reference:J

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/Channel;Z)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->onClientDiscoveredChannel$lambda$1$0(Ltechnology/cariad/cat/genx/Channel;Z)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/ClientCrossDelegate;)I
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->onClientConnected$lambda$0(Ltechnology/cariad/cat/genx/ClientCrossDelegate;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/genx/ClientCrossDelegate;Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->onClientDiscoveredChannel$lambda$0(Ltechnology/cariad/cat/genx/ClientCrossDelegate;Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private final native destroy()V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->onClientReceivedTypedFrame$lambda$0(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->onClientConnected$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->onClientReceivedTypedFrame$lambda$2$0(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/genx/ClientCrossDelegate;Ltechnology/cariad/cat/genx/TypedFrame;)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->onClientReceivedTypedFrame$lambda$1(Ltechnology/cariad/cat/genx/ClientCrossDelegate;Ltechnology/cariad/cat/genx/TypedFrame;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic k(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->onClientDisconnected$lambda$0(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final native nativeClientDidConnect()I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeClientDidDisconnect()I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeClientDidDiscover(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeClientDidReceive(Ltechnology/cariad/cat/genx/TypedFrame;)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeClientShouldBeRemovedAfterAdvertisementDidStop()Z
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private static final onClientConnected$lambda$0(Ltechnology/cariad/cat/genx/ClientCrossDelegate;)I
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->nativeClientDidConnect()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final onClientConnected$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onClientConnected(): Failed to forward CGXClientDidConnect"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onClientDisconnected$lambda$0(I)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatusKt;->getCoreGenXStatus(I)Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "onClientDisconnected(): Failed to forward CGXClientDidDisconnect with CoreGenXStatus: "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private static final onClientDiscoveredChannel$lambda$0(Ltechnology/cariad/cat/genx/ClientCrossDelegate;Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)I
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->nativeClientDidDiscover(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final onClientDiscoveredChannel$lambda$1$0(Ltechnology/cariad/cat/genx/Channel;Z)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onClientDiscoveredChannel(): Failed to forward discovered channel = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, ", success = "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string p0, " to CGXClientDidDiscover"

    .line 20
    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method private static final onClientReceivedTypedFrame$lambda$0(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onClientReceivedTypedFrame(): "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final onClientReceivedTypedFrame$lambda$1(Ltechnology/cariad/cat/genx/ClientCrossDelegate;Ltechnology/cariad/cat/genx/TypedFrame;)I
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->nativeClientDidReceive(Ltechnology/cariad/cat/genx/TypedFrame;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final onClientReceivedTypedFrame$lambda$2$0(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onClientReceivedTypedFrame(): Failed to forward the received typedFrame = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, " to CGXClientDidReceive"

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method


# virtual methods
.method public close()V
    .locals 4

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->_reference:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->destroy()V

    .line 10
    .line 11
    .line 12
    iput-wide v2, p0, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->_reference:J

    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final finalize()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->close()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public getReference()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->_reference:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public onClientConnected()V
    .locals 3
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/t0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, v1}, Ltechnology/cariad/cat/genx/t0;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    new-instance v1, Ltechnology/cariad/cat/genx/s0;

    .line 14
    .line 15
    const/16 v2, 0x8

    .line 16
    .line 17
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 18
    .line 19
    .line 20
    const-string v2, "GenX"

    .line 21
    .line 22
    invoke-static {p0, v2, v0, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public onClientDisconnected()V
    .locals 3
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->nativeClientDidDisconnect()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sget-object v1, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 6
    .line 7
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getSuccess()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance v1, Le1/h1;

    .line 19
    .line 20
    const/4 v2, 0x6

    .line 21
    invoke-direct {v1, v0, v2}, Le1/h1;-><init>(II)V

    .line 22
    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    const-string v2, "GenX"

    .line 26
    .line 27
    invoke-static {p0, v2, v0, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public onClientDiscoveredChannel(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)V
    .locals 7
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    const-string v0, "channel"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "message"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Li61/f;

    .line 12
    .line 13
    const/4 v6, 0x1

    .line 14
    move-object v2, p0

    .line 15
    move-object v3, p1

    .line 16
    move v4, p2

    .line 17
    move-object v5, p3

    .line 18
    invoke-direct/range {v1 .. v6}, Li61/f;-><init>(Ljava/lang/Object;Ljava/lang/Enum;ZLjava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v1}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    new-instance p1, Lc/d;

    .line 28
    .line 29
    const/16 p2, 0xe

    .line 30
    .line 31
    invoke-direct {p1, v3, v4, p2}, Lc/d;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    const-string p2, "GenX"

    .line 35
    .line 36
    invoke-static {v2, p2, p0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 37
    .line 38
    .line 39
    :cond_0
    return-void
.end method

.method public onClientReceivedTypedFrame(Ltechnology/cariad/cat/genx/TypedFrame;)V
    .locals 8
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    const-string v0, "typedFrame"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/TypedFrame;->getType()Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sget-object v1, Ltechnology/cariad/cat/genx/TypedFrameType;->Advertisement:Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 11
    .line 12
    if-ne v0, v1, :cond_0

    .line 13
    .line 14
    sget-object v0, Ltechnology/cariad/cat/genx/Logging;->INSTANCE:Ltechnology/cariad/cat/genx/Logging;

    .line 15
    .line 16
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/Logging;->getConfig()Ltechnology/cariad/cat/genx/Logging$Config;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    :cond_0
    new-instance v4, Ltechnology/cariad/cat/genx/a;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {v4, p1, v0}, Ltechnology/cariad/cat/genx/a;-><init>(Ltechnology/cariad/cat/genx/TypedFrame;I)V

    .line 30
    .line 31
    .line 32
    new-instance v1, Lt51/j;

    .line 33
    .line 34
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v6

    .line 38
    const-string v0, "getName(...)"

    .line 39
    .line 40
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v7

    .line 44
    const-string v2, "GenX"

    .line 45
    .line 46
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 47
    .line 48
    const/4 v5, 0x0

    .line 49
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    new-instance v0, Ltechnology/cariad/cat/genx/u0;

    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    invoke-direct {v0, v1, p0, p1}, Ltechnology/cariad/cat/genx/u0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-static {v0}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    if-eqz v0, :cond_2

    .line 66
    .line 67
    new-instance v1, Ltechnology/cariad/cat/genx/a;

    .line 68
    .line 69
    const/4 v2, 0x1

    .line 70
    invoke-direct {v1, p1, v2}, Ltechnology/cariad/cat/genx/a;-><init>(Ltechnology/cariad/cat/genx/TypedFrame;I)V

    .line 71
    .line 72
    .line 73
    const-string p1, "GenX"

    .line 74
    .line 75
    invoke-static {p0, p1, v0, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    return-void
.end method

.method public shouldClientBeRemovedAfterAdvertisementStopped()Z
    .locals 0
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->nativeClientShouldBeRemovedAfterAdvertisementDidStop()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

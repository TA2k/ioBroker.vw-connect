.class public final Ltechnology/cariad/cat/genx/ClientManagerKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\t\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u001a\u001b\u0010\u0004\u001a\u00020\u0003*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u0001H\u0000\u00a2\u0006\u0004\u0008\u0004\u0010\u0005\u001a\u0013\u0010\u0007\u001a\u00020\u0006*\u00020\u0000H\u0001\u00a2\u0006\u0004\u0008\u0007\u0010\u0008\u001a \u0010\n\u001a\u00020\u00032\u0006\u0010\t\u001a\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u0001H\u0082 \u00a2\u0006\u0004\u0008\n\u0010\u0005\u001a\u0018\u0010\u000b\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\u0000H\u0083 \u00a2\u0006\u0004\u0008\u000b\u0010\u0008\u00a8\u0006\u000c"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/ClientManager;",
        "",
        "cgxTransportType",
        "",
        "nativeCreate",
        "(Ltechnology/cariad/cat/genx/ClientManager;B)J",
        "Llx0/b0;",
        "nativeDestroy",
        "(Ltechnology/cariad/cat/genx/ClientManager;)V",
        "clientManager",
        "extNativeCreate",
        "extNativeDestroy",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static synthetic a(B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientManagerKt;->nativeCreate$lambda$0(B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/ClientManager;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientManagerKt;->nativeDestroy$lambda$0(Ltechnology/cariad/cat/genx/ClientManager;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final native extNativeCreate(Ltechnology/cariad/cat/genx/ClientManager;B)J
.end method

.method private static final native extNativeDestroy(Ltechnology/cariad/cat/genx/ClientManager;)V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public static final nativeCreate(Ltechnology/cariad/cat/genx/ClientManager;B)J
    .locals 8

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/e;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {v4, p1, v0}, Ltechnology/cariad/cat/genx/e;-><init>(BI)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string v0, "getName(...)"

    .line 19
    .line 20
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/ClientManagerKt;->extNativeCreate(Ltechnology/cariad/cat/genx/ClientManager;B)J

    .line 36
    .line 37
    .line 38
    move-result-wide p0

    .line 39
    return-wide p0
.end method

.method private static final nativeCreate$lambda$0(B)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "nativeCreate(): Create ClientManager for "

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static final nativeDestroy(Ltechnology/cariad/cat/genx/ClientManager;)V
    .locals 8
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/t0;

    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    invoke-direct {v4, p0, v0}, Ltechnology/cariad/cat/genx/t0;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string v0, "getName(...)"

    .line 19
    .line 20
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientManagerKt;->extNativeDestroy(Ltechnology/cariad/cat/genx/ClientManager;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method private static final nativeDestroy$lambda$0(Ltechnology/cariad/cat/genx/ClientManager;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/Referencing;->getReference()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-string p0, "nativeDestroy(): "

    .line 6
    .line 7
    invoke-static {v0, v1, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.class public final Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0080\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0011\u0010\u0004\u001a\u00020\u0005*\u00020\u0006H\u0000\u00a2\u0006\u0002\u0008\u0007J\u0015\u0010\u0008\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\nH\u0000\u00a2\u0006\u0002\u0008\u000b\u00a8\u0006\u000c"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;",
        "",
        "<init>",
        "()V",
        "getWifiState",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;",
        "Landroid/content/Context;",
        "getWifiState$genx_release",
        "byStateInt",
        "wifiState",
        "",
        "byStateInt$genx_release",
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


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;-><init>()V

    return-void
.end method

.method public static synthetic a(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;->byStateInt$lambda$0(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final byStateInt$lambda$0(I)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "byStateInt(): Wifi state "

    .line 2
    .line 3
    const-string v1, " not handled"

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public final byStateInt$genx_release(I)Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;
    .locals 2

    .line 1
    if-eqz p1, :cond_4

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p1, v0, :cond_3

    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    if-eq p1, v0, :cond_2

    .line 8
    .line 9
    const/4 v0, 0x3

    .line 10
    if-eq p1, v0, :cond_1

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    if-eq p1, v0, :cond_0

    .line 14
    .line 15
    new-instance v0, Le1/h1;

    .line 16
    .line 17
    const/16 v1, 0xd

    .line 18
    .line 19
    invoke-direct {v0, p1, v1}, Le1/h1;-><init>(II)V

    .line 20
    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    const-string v1, "GenX"

    .line 24
    .line 25
    invoke-static {p0, v1, p1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_0
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_1
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->ENABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_2
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->ENABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_3
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->DISABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_4
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->DISABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 44
    .line 45
    return-object p0
.end method

.method public final getWifiState$genx_release(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;
    .locals 0

    .line 1
    const-string p0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getWifiManager(Landroid/content/Context;)Landroid/net/wifi/WifiManager;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    invoke-virtual {p0}, Landroid/net/wifi/WifiManager;->getWifiState()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    sget-object p1, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->Companion:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;->byStateInt$genx_release(I)Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    if-nez p0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-object p0

    .line 26
    :cond_1
    :goto_0
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 27
    .line 28
    return-object p0
.end method

.class public final Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008\u0080\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0011\u0010\u0004\u001a\u00020\u0005*\u00020\u0006H\u0000\u00a2\u0006\u0002\u0008\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;",
        "",
        "<init>",
        "()V",
        "getAccessPointState",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;",
        "Landroid/content/Context;",
        "getAccessPointState$genx_release",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;-><init>()V

    return-void
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;->getAccessPointState$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic b(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;->getAccessPointState$lambda$1(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final getAccessPointState$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "getAccessPointState(): Failed to get AccessPointState"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final getAccessPointState$lambda$1(I)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "getAccessPointState(): Received not handled wifi state \'"

    .line 2
    .line 3
    const-string v1, "\'"

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
.method public final getAccessPointState$genx_release(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;
    .locals 4

    .line 1
    const-string p0, "GenX"

    .line 2
    .line 3
    const-string v0, "<this>"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :try_start_0
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getWifiManager(Landroid/content/Context;)Landroid/net/wifi/WifiManager;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 15
    .line 16
    return-object p0

    .line 17
    :catch_0
    move-exception v0

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const-string v2, "getWifiApState"

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {v1}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-nez v2, :cond_1

    .line 35
    .line 36
    const/4 v2, 0x1

    .line 37
    invoke-virtual {v1, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 38
    .line 39
    .line 40
    :cond_1
    invoke-virtual {v1, v0, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    instance-of v1, v0, Ljava/lang/Integer;

    .line 45
    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    check-cast v0, Ljava/lang/Integer;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    move-object v0, v3

    .line 52
    :goto_0
    if-eqz v0, :cond_4

    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 55
    .line 56
    .line 57
    move-result v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 58
    const/4 v1, -0x1

    .line 59
    if-eq v0, v1, :cond_3

    .line 60
    .line 61
    packed-switch v0, :pswitch_data_0

    .line 62
    .line 63
    .line 64
    new-instance v1, Le1/h1;

    .line 65
    .line 66
    const/16 v2, 0xc

    .line 67
    .line 68
    invoke-direct {v1, v0, v2}, Le1/h1;-><init>(II)V

    .line 69
    .line 70
    .line 71
    invoke-static {p1, p0, v3, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 72
    .line 73
    .line 74
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_0
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->FAILED:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 78
    .line 79
    return-object p0

    .line 80
    :pswitch_1
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->ENABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_2
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->ENABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 84
    .line 85
    return-object p0

    .line 86
    :pswitch_3
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->DISABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_4
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->DISABLING:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 90
    .line 91
    return-object p0

    .line 92
    :cond_3
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 93
    .line 94
    return-object p0

    .line 95
    :cond_4
    :try_start_1
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 96
    .line 97
    return-object p0

    .line 98
    :goto_1
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/g;

    .line 99
    .line 100
    const/4 v2, 0x2

    .line 101
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 102
    .line 103
    .line 104
    invoke-static {p1, p0, v0, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 105
    .line 106
    .line 107
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 108
    .line 109
    return-object p0

    .line 110
    nop

    .line 111
    :pswitch_data_0
    .packed-switch 0xa
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

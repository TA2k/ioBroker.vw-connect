.class final Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lay0/k;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic $networkCallback:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$1;->$networkCallback:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Throwable;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$1;->invoke(Ljava/lang/Throwable;)V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public final invoke(Ljava/lang/Throwable;)V
    .locals 0

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$1;->$networkCallback:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;

    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregisterIfStillRegistered()V

    return-void
.end method

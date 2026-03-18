.class public final synthetic Ltechnology/cariad/cat/genx/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/r;


# instance fields
.field public final synthetic d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/genx/i0;->d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    check-cast p2, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 4
    .line 5
    check-cast p3, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 6
    .line 7
    check-cast p4, Ljava/lang/Short;

    .line 8
    .line 9
    invoke-virtual {p4}, Ljava/lang/Short;->shortValue()S

    .line 10
    .line 11
    .line 12
    move-result p4

    .line 13
    check-cast p5, Ljava/lang/Short;

    .line 14
    .line 15
    invoke-virtual {p5}, Ljava/lang/Short;->shortValue()S

    .line 16
    .line 17
    .line 18
    move-result p5

    .line 19
    check-cast p6, Ljava/lang/Short;

    .line 20
    .line 21
    invoke-virtual {p6}, Ljava/lang/Short;->shortValue()S

    .line 22
    .line 23
    .line 24
    move-result p6

    .line 25
    iget-object p0, p0, Ltechnology/cariad/cat/genx/i0;->d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 26
    .line 27
    invoke-static/range {p0 .. p6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->K0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)Ltechnology/cariad/cat/genx/GenXError;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

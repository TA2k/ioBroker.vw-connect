.class public final Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer;
.super Ltechnology/cariad/cat/genx/VehicleAntennaImpl;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaImpl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Outer"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000l\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0018\u00002\u00020\u00012\u00020\u0002By\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u0012\n\u0010\t\u001a\u00060\u0007j\u0002`\u0008\u0012\u0006\u0010\u000b\u001a\u00020\n\u0012\u0006\u0010\r\u001a\u00020\u000c\u0012\u0006\u0010\u000f\u001a\u00020\u000e\u0012\u0006\u0010\u0010\u001a\u00020\u000e\u0012\u0006\u0010\u0012\u001a\u00020\u0011\u0012\u0006\u0010\u0014\u001a\u00020\u0013\u0012\u0006\u0010\u0016\u001a\u00020\u0015\u0012\u000c\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00180\u0017\u0012\u0006\u0010\u001b\u001a\u00020\u001a\u0012\u0006\u0010\u001d\u001a\u00020\u001c\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ\u0016\u0010$\u001a\u0008\u0012\u0004\u0012\u00020!0 H\u0096@\u00a2\u0006\u0004\u0008\"\u0010#\u00a8\u0006%"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaImpl;",
        "Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;",
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "credentialsStore",
        "Landroid/content/Context;",
        "context",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "vin",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "localKeyPair",
        "Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;",
        "remoteCredentials",
        "Llx0/z;",
        "beaconMajor",
        "beaconMinor",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "deviceInformation",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "linkedParametersRequestValues",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "Ljava/lang/ref/WeakReference;",
        "Ltechnology/cariad/cat/genx/ScanningManager;",
        "scanningManager",
        "Lvy0/b0;",
        "coroutineScope",
        "",
        "initialBLEState",
        "<init>",
        "(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZLkotlin/jvm/internal/g;)V",
        "Llx0/o;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "bleTransport-IoAF18A",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "bleTransport",
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
.method private constructor <init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;Z)V
    .locals 16
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
            "Landroid/content/Context;",
            "Ljava/lang/String;",
            "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
            "Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;",
            "SS",
            "Ltechnology/cariad/cat/genx/DeviceInformation;",
            "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
            "Ltechnology/cariad/cat/genx/GenXDispatcher;",
            "Ljava/lang/ref/WeakReference<",
            "Ltechnology/cariad/cat/genx/ScanningManager;",
            ">;",
            "Lvy0/b0;",
            "Z)V"
        }
    .end annotation

    const-string v0, "credentialsStore"

    move-object/from16 v2, p1

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "context"

    move-object/from16 v3, p2

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "vin"

    move-object/from16 v5, p3

    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "localKeyPair"

    move-object/from16 v7, p4

    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "remoteCredentials"

    move-object/from16 v8, p5

    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "deviceInformation"

    move-object/from16 v1, p8

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "linkedParametersRequestValues"

    move-object/from16 v12, p9

    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "genXDispatcher"

    move-object/from16 v13, p10

    invoke-static {v13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "scanningManager"

    move-object/from16 v14, p11

    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "coroutineScope"

    move-object/from16 v15, p12

    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v4, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 3
    sget-object v6, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    const/4 v11, 0x0

    move/from16 v9, p6

    move/from16 v10, p7

    .line 4
    invoke-direct/range {v4 .. v11}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLkotlin/jvm/internal/g;)V

    const/4 v11, 0x0

    move/from16 v10, p13

    move-object v6, v1

    move-object v5, v12

    move-object v7, v13

    move-object v8, v14

    move-object v9, v15

    move-object/from16 v1, p0

    .line 5
    invoke-direct/range {v1 .. v11}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZ)V

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p13}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;Z)V

    return-void
.end method


# virtual methods
.method public bleTransport-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p1, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p1, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 52
    .line 53
    iput v3, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer$bleTransport$1;->label:I

    .line 54
    .line 55
    invoke-virtual {p0, p1, v0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getTransport(Ltechnology/cariad/cat/genx/TransportType;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    check-cast p1, Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;

    .line 63
    .line 64
    if-eqz p1, :cond_4

    .line 65
    .line 66
    return-object p1

    .line 67
    :cond_4
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$VehicleAntennaTransportNotAvailable;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleAntennaTransportNotAvailable;

    .line 68
    .line 69
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0
.end method

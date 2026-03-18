.class public final synthetic Ltechnology/cariad/cat/genx/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/t0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/t0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/t0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/t0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->e(Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 16
    .line 17
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->W0(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_1
    check-cast p0, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 23
    .line 24
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->T(Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_2
    check-cast p0, Ltechnology/cariad/cat/genx/Logging$Config;

    .line 30
    .line 31
    invoke-static {p0}, Ltechnology/cariad/cat/genx/Logging;->b(Ltechnology/cariad/cat/genx/Logging$Config;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_3
    check-cast p0, Ltechnology/cariad/cat/genx/ClientManager;

    .line 37
    .line 38
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientManagerKt;->b(Ltechnology/cariad/cat/genx/ClientManager;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_4
    check-cast p0, Ltechnology/cariad/cat/genx/ClientCrossDelegate;

    .line 44
    .line 45
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->b(Ltechnology/cariad/cat/genx/ClientCrossDelegate;)I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :pswitch_5
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 55
    .line 56
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$startScanning$1;->f(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

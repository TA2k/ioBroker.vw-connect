.class public final Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;
.super Ltechnology/cariad/cat/genx/protocol/InternalC2PMessageHandler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000j\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u000f\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008\u0000\u0018\u0000 82\u00020\u0001:\u00018BU\u0012\u000c\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002\u0012\u000c\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u0002\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u0012\u0014\u0010\u000c\u001a\u0010\u0012\u0004\u0012\u00020\n\u0012\u0006\u0012\u0004\u0018\u00010\u000b0\t\u0012\u0012\u0010\u000e\u001a\u000e\u0012\u0004\u0012\u00020\r\u0012\u0004\u0012\u00020\u00050\t\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\u0005H\u0002\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J/\u0010\u001b\u001a\u00020\u00172\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0016\u001a\u00020\u00152\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u001a\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u0015\u0010\u001f\u001a\u00020\u00052\u0006\u0010\u001e\u001a\u00020\u001d\u00a2\u0006\u0004\u0008\u001f\u0010 R\u001d\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008!\u0010\"\u001a\u0004\u0008#\u0010$R\u001d\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0006\u0010\"\u001a\u0004\u0008%\u0010$R\u0017\u0010\u0008\u001a\u00020\u00078\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0008\u0010&\u001a\u0004\u0008\'\u0010(R%\u0010\u000c\u001a\u0010\u0012\u0004\u0012\u00020\n\u0012\u0006\u0012\u0004\u0018\u00010\u000b0\t8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u000c\u0010)\u001a\u0004\u0008*\u0010+R#\u0010\u000e\u001a\u000e\u0012\u0004\u0012\u00020\r\u0012\u0004\u0012\u00020\u00050\t8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u000e\u0010)\u001a\u0004\u0008,\u0010+R \u0010/\u001a\u0008\u0012\u0004\u0012\u00020.0-8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008/\u00100\u001a\u0004\u00081\u00102R\u001a\u00104\u001a\u0002038\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00084\u00105\u001a\u0004\u00086\u00107\u00a8\u00069"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;",
        "Ltechnology/cariad/cat/genx/protocol/InternalC2PMessageHandler;",
        "Lkotlin/Function0;",
        "Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;",
        "smartphoneInformationResponse",
        "Llx0/b0;",
        "onSmartphoneInformationResponseSent",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
        "vehicleAntennaTransportIdentifier",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/genx/protocol/Message;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "sendMessageDispatched",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;",
        "onLinkParametersReceived",
        "<init>",
        "(Lay0/a;Lay0/a;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;Lay0/k;Lay0/k;)V",
        "sendSmartphoneInformationResponse",
        "()V",
        "",
        "rawAddress",
        "",
        "rawPriority",
        "",
        "requiresQueuing",
        "",
        "data",
        "handleMessage",
        "(JBZ[B)Z",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "linkParametersRequestValues",
        "sendLinkParameterRequest",
        "(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;)V",
        "smartphoneInformationResponse$1",
        "Lay0/a;",
        "getSmartphoneInformationResponse",
        "()Lay0/a;",
        "getOnSmartphoneInformationResponseSent",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
        "getVehicleAntennaTransportIdentifier",
        "()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
        "Lay0/k;",
        "getSendMessageDispatched",
        "()Lay0/k;",
        "getOnLinkParametersReceived",
        "",
        "Ltechnology/cariad/cat/genx/protocol/Address;",
        "addresses",
        "Ljava/util/List;",
        "getAddresses",
        "()Ljava/util/List;",
        "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "globalServiceID",
        "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "getGlobalServiceID",
        "()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "Companion",
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


# static fields
.field public static final Companion:Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler$Companion;

.field private static final globalServiceId:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

.field private static final linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;


# instance fields
.field private final addresses:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;"
        }
    .end annotation
.end field

.field private final globalServiceID:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

.field private final onLinkParametersReceived:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private final onSmartphoneInformationResponseSent:Lay0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/a;"
        }
    .end annotation
.end field

.field private final sendMessageDispatched:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private final smartphoneInformationResponse$1:Lay0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/a;"
        }
    .end annotation
.end field

.field private final vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->Companion:Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler$Companion;

    .line 8
    .line 9
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 10
    .line 11
    const/16 v2, 0x4c

    .line 12
    .line 13
    const/16 v3, 0x45

    .line 14
    .line 15
    const/16 v4, 0x42

    .line 16
    .line 17
    invoke-direct {v0, v4, v2, v3, v1}, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->globalServiceId:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 21
    .line 22
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 23
    .line 24
    sget-object v3, Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;

    .line 25
    .line 26
    const/4 v4, 0x0

    .line 27
    invoke-direct {v2, v0, v4, v3, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 28
    .line 29
    .line 30
    sput-object v2, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 31
    .line 32
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 33
    .line 34
    const/4 v5, 0x1

    .line 35
    invoke-direct {v2, v0, v5, v3, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 36
    .line 37
    .line 38
    sput-object v2, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 39
    .line 40
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 41
    .line 42
    sget-object v3, Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;

    .line 43
    .line 44
    invoke-direct {v2, v0, v4, v3, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 45
    .line 46
    .line 47
    sput-object v2, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 48
    .line 49
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 50
    .line 51
    invoke-direct {v2, v0, v5, v3, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 52
    .line 53
    .line 54
    sput-object v2, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 55
    .line 56
    return-void
.end method

.method public constructor <init>(Lay0/a;Lay0/a;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;Lay0/k;Lay0/k;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            "Lay0/a;",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
            "Lay0/k;",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "smartphoneInformationResponse"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onSmartphoneInformationResponseSent"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "vehicleAntennaTransportIdentifier"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "sendMessageDispatched"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "onLinkParametersReceived"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/protocol/InternalC2PMessageHandler;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationResponse$1:Lay0/a;

    .line 30
    .line 31
    iput-object p2, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->onSmartphoneInformationResponseSent:Lay0/a;

    .line 32
    .line 33
    iput-object p3, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 34
    .line 35
    iput-object p4, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendMessageDispatched:Lay0/k;

    .line 36
    .line 37
    iput-object p5, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->onLinkParametersReceived:Lay0/k;

    .line 38
    .line 39
    sget-object p1, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 40
    .line 41
    sget-object p2, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 42
    .line 43
    sget-object p3, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 44
    .line 45
    sget-object p4, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 46
    .line 47
    filled-new-array {p1, p2, p3, p4}, [Ltechnology/cariad/cat/genx/protocol/Address;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->addresses:Ljava/util/List;

    .line 56
    .line 57
    sget-object p1, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->globalServiceId:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 58
    .line 59
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->globalServiceID:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 60
    .line 61
    return-void
.end method

.method public static synthetic a(JLtechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->handleMessage$lambda$4(JLtechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getGlobalServiceId$cp()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->globalServiceId:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getLinkParameterRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getLinkParameterResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSmartphoneInformationRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSmartphoneInformationResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendSmartphoneInformationResponse$lambda$1(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->handleMessage$lambda$3(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendSmartphoneInformationResponse$lambda$0(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendLinkParameterRequest$lambda$1$0(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->handleMessage$lambda$1$0(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendLinkParameterRequest$lambda$0(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->handleMessage$lambda$0(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final handleMessage$lambda$0(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "handleMessage(): Received \'linkParameterResponse\' - "

    .line 4
    .line 5
    invoke-static {v0, p0}, Lp3/m;->m(Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final handleMessage$lambda$1$0(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "handleMessage(): Received link parameters = "

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, " - "

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method private static final handleMessage$lambda$2([BLtechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "handleMessage(): Cannot decode data to \'LinkParameters\', data = "

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, " - "

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method private static final handleMessage$lambda$3(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "handleMessage(): Received \'smartphoneInformationRequest\' - "

    .line 4
    .line 5
    invoke-static {v0, p0}, Lp3/m;->m(Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final handleMessage$lambda$4(JLtechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/protocol/AddressKt;->toHexString(J)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p1, p2, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 6
    .line 7
    new-instance p2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v0, "handleMessage(): Message should not be handled by the client, address = "

    .line 10
    .line 11
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, " - "

    .line 18
    .line 19
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic i([BLtechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->handleMessage$lambda$2([BLtechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final sendLinkParameterRequest$lambda$0(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "sendLinkParameterRequest(): Sending LinkParameterRequest = "

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, " - "

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method private static final sendLinkParameterRequest$lambda$1$0(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "sendLinkParameterRequest(): Failed to send SmartphoneInfo response - "

    .line 4
    .line 5
    invoke-static {v0, p0}, Lp3/m;->m(Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private final sendSmartphoneInformationResponse()V
    .locals 15

    .line 1
    new-instance v3, Lp51/a;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {v3, p0, v0}, Lp51/a;-><init>(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;I)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lt51/j;

    .line 8
    .line 9
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const-string v7, "getName(...)"

    .line 14
    .line 15
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v1, "GenX"

    .line 20
    .line 21
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendMessageDispatched:Lay0/k;

    .line 31
    .line 32
    new-instance v1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 33
    .line 34
    sget-object v2, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 35
    .line 36
    sget-object v3, Ltechnology/cariad/cat/genx/protocol/Priority;->LOW:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 37
    .line 38
    iget-object v4, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationResponse$1:Lay0/a;

    .line 39
    .line 40
    invoke-interface {v4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    check-cast v4, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;

    .line 45
    .line 46
    invoke-static {v4}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->toByteArray(Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;)[B

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    const/4 v5, 0x1

    .line 51
    invoke-direct {v1, v2, v3, v5, v4}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 52
    .line 53
    .line 54
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    move-object v12, v0

    .line 59
    check-cast v12, Ltechnology/cariad/cat/genx/GenXError;

    .line 60
    .line 61
    if-eqz v12, :cond_0

    .line 62
    .line 63
    new-instance v11, Lp51/a;

    .line 64
    .line 65
    const/4 v0, 0x1

    .line 66
    invoke-direct {v11, p0, v0}, Lp51/a;-><init>(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;I)V

    .line 67
    .line 68
    .line 69
    new-instance v8, Lt51/j;

    .line 70
    .line 71
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v13

    .line 75
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v14

    .line 79
    const-string v9, "GenX"

    .line 80
    .line 81
    sget-object v10, Lt51/e;->a:Lt51/e;

    .line 82
    .line 83
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->onSmartphoneInformationResponseSent:Lay0/a;

    .line 91
    .line 92
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    return-void
.end method

.method private static final sendSmartphoneInformationResponse$lambda$0(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "sendSmartphoneInformationResponse(): Sending SmartphoneInfo response - "

    .line 4
    .line 5
    invoke-static {v0, p0}, Lp3/m;->m(Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final sendSmartphoneInformationResponse$lambda$1(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "sendSmartphoneInformationResponse(): Failed to send SmartphoneInfo response - "

    .line 4
    .line 5
    invoke-static {v0, p0}, Lp3/m;->m(Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public getAddresses()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->addresses:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getGlobalServiceID()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->globalServiceID:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOnLinkParametersReceived()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->onLinkParametersReceived:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOnSmartphoneInformationResponseSent()Lay0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/a;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->onSmartphoneInformationResponseSent:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSendMessageDispatched()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendMessageDispatched:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSmartphoneInformationResponse()Lay0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/a;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationResponse$1:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVehicleAntennaTransportIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public handleMessage(JBZ[B)Z
    .locals 10

    .line 1
    const-string p3, "data"

    .line 2
    .line 3
    invoke-static {p5, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p3, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 7
    .line 8
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 9
    .line 10
    .line 11
    move-result-wide p3

    .line 12
    cmp-long p3, p1, p3

    .line 13
    .line 14
    const-string p4, "GenX"

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    sget-object v3, Lt51/d;->a:Lt51/d;

    .line 18
    .line 19
    const/4 v8, 0x1

    .line 20
    const-string v9, "getName(...)"

    .line 21
    .line 22
    if-nez p3, :cond_1

    .line 23
    .line 24
    new-instance v4, Lp51/a;

    .line 25
    .line 26
    const/4 p1, 0x2

    .line 27
    invoke-direct {v4, p0, p1}, Lp51/a;-><init>(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;I)V

    .line 28
    .line 29
    .line 30
    new-instance v1, Lt51/j;

    .line 31
    .line 32
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v6

    .line 36
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    const-string v2, "GenX"

    .line 41
    .line 42
    const/4 v5, 0x0

    .line 43
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 47
    .line 48
    .line 49
    invoke-static {p5}, Ltechnology/cariad/cat/genx/protocol/data/LinkParametersKt;->toLinkParametersResponseValues([B)Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    if-eqz p1, :cond_0

    .line 54
    .line 55
    new-instance v4, Lo51/c;

    .line 56
    .line 57
    const/4 p2, 0x4

    .line 58
    invoke-direct {v4, p2, p1, p0}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    new-instance v1, Lt51/j;

    .line 62
    .line 63
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v7

    .line 71
    const-string v2, "GenX"

    .line 72
    .line 73
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 74
    .line 75
    const/4 v5, 0x0

    .line 76
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->onLinkParametersReceived:Lay0/k;

    .line 83
    .line 84
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    return v8

    .line 88
    :cond_0
    new-instance p1, Lo51/c;

    .line 89
    .line 90
    const/4 p2, 0x5

    .line 91
    invoke-direct {p1, p2, p5, p0}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    invoke-static {p0, p4, v0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 95
    .line 96
    .line 97
    return v8

    .line 98
    :cond_1
    sget-object p3, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 99
    .line 100
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 101
    .line 102
    .line 103
    move-result-wide v1

    .line 104
    cmp-long p3, p1, v1

    .line 105
    .line 106
    if-nez p3, :cond_2

    .line 107
    .line 108
    new-instance v4, Lp51/a;

    .line 109
    .line 110
    const/4 p1, 0x3

    .line 111
    invoke-direct {v4, p0, p1}, Lp51/a;-><init>(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;I)V

    .line 112
    .line 113
    .line 114
    new-instance v1, Lt51/j;

    .line 115
    .line 116
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v7

    .line 124
    const-string v2, "GenX"

    .line 125
    .line 126
    const/4 v5, 0x0

    .line 127
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 131
    .line 132
    .line 133
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendSmartphoneInformationResponse()V

    .line 134
    .line 135
    .line 136
    return v8

    .line 137
    :cond_2
    sget-object p3, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 138
    .line 139
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 140
    .line 141
    .line 142
    move-result-wide v1

    .line 143
    cmp-long p3, p1, v1

    .line 144
    .line 145
    if-eqz p3, :cond_4

    .line 146
    .line 147
    sget-object p3, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 148
    .line 149
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 150
    .line 151
    .line 152
    move-result-wide v1

    .line 153
    cmp-long p3, p1, v1

    .line 154
    .line 155
    if-nez p3, :cond_3

    .line 156
    .line 157
    goto :goto_0

    .line 158
    :cond_3
    const/4 p0, 0x0

    .line 159
    return p0

    .line 160
    :cond_4
    :goto_0
    new-instance p3, Lh2/u2;

    .line 161
    .line 162
    const/4 p5, 0x3

    .line 163
    invoke-direct {p3, p1, p2, p0, p5}, Lh2/u2;-><init>(JLjava/lang/Object;I)V

    .line 164
    .line 165
    .line 166
    invoke-static {p0, p4, v0, p3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 167
    .line 168
    .line 169
    return v8
.end method

.method public final sendLinkParameterRequest(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;)V
    .locals 8

    .line 1
    const-string v0, "linkParametersRequestValues"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Lo51/c;

    .line 7
    .line 8
    const/4 v0, 0x6

    .line 9
    invoke-direct {v4, v0, p1, p0}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

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
    sget-object v3, Lt51/d;->a:Lt51/d;

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
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->sendMessageDispatched:Lay0/k;

    .line 36
    .line 37
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 38
    .line 39
    sget-object v3, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 40
    .line 41
    sget-object v4, Ltechnology/cariad/cat/genx/protocol/Priority;->LOW:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 42
    .line 43
    const/4 v5, 0x1

    .line 44
    invoke-static {p1}, Ltechnology/cariad/cat/genx/protocol/data/LinkParametersKt;->toByteArray(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;)[B

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-direct {v2, v3, v4, v5, p1}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 49
    .line 50
    .line 51
    invoke-interface {v1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    move-object v5, p1

    .line 56
    check-cast v5, Ltechnology/cariad/cat/genx/GenXError;

    .line 57
    .line 58
    if-eqz v5, :cond_0

    .line 59
    .line 60
    new-instance v4, Lp51/a;

    .line 61
    .line 62
    const/4 p1, 0x4

    .line 63
    invoke-direct {v4, p0, p1}, Lp51/a;-><init>(Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;I)V

    .line 64
    .line 65
    .line 66
    new-instance v1, Lt51/j;

    .line 67
    .line 68
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v7

    .line 76
    const-string v2, "GenX"

    .line 77
    .line 78
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 79
    .line 80
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 84
    .line 85
    .line 86
    :cond_0
    return-void
.end method

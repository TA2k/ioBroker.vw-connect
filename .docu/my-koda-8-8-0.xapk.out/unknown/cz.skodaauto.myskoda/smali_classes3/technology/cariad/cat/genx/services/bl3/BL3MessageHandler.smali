.class public final Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;
.super Ltechnology/cariad/cat/genx/protocol/InternalC2PMessageHandler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000|\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0012\n\u0002\u0008 \n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0000\u0018\u0000 L2\u00020\u0001:\u0001LB\u008b\u0001\u0012\u000c\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002\u0012\u000c\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u0002\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u0012\u0014\u0010\u000c\u001a\u0010\u0012\u0004\u0012\u00020\n\u0012\u0006\u0012\u0004\u0018\u00010\u000b0\t\u0012\u000c\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\r0\u0002\u0012\u0012\u0010\u0010\u001a\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00050\t\u0012\u0012\u0010\u0012\u001a\u000e\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u00050\t\u0012\u0012\u0010\u0014\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00050\t\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J/\u0010\u001f\u001a\u00020\u001b2\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u001c\u001a\u00020\u001b2\u0006\u0010\u001e\u001a\u00020\u001dH\u0016\u00a2\u0006\u0004\u0008\u001f\u0010 J\u0015\u0010\"\u001a\u00020\u00052\u0006\u0010!\u001a\u00020\r\u00a2\u0006\u0004\u0008\"\u0010#J\r\u0010$\u001a\u00020\u0005\u00a2\u0006\u0004\u0008$\u0010%J\r\u0010&\u001a\u00020\u0005\u00a2\u0006\u0004\u0008&\u0010%J\u0015\u0010(\u001a\u00020\u00052\u0006\u0010\'\u001a\u00020\u0011\u00a2\u0006\u0004\u0008(\u0010)J\u000f\u0010*\u001a\u00020\u0005H\u0002\u00a2\u0006\u0004\u0008*\u0010%J\u0017\u0010+\u001a\u00020\u00052\u0006\u0010\u001e\u001a\u00020\u001dH\u0002\u00a2\u0006\u0004\u0008+\u0010,J\u0017\u0010-\u001a\u00020\u00052\u0006\u0010\u001e\u001a\u00020\u001dH\u0002\u00a2\u0006\u0004\u0008-\u0010,J\u0017\u0010.\u001a\u00020\u00052\u0006\u0010\u001e\u001a\u00020\u001dH\u0002\u00a2\u0006\u0004\u0008.\u0010,R\u001d\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008/\u00100\u001a\u0004\u00081\u00102R\u001d\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0006\u00100\u001a\u0004\u00083\u00102R\u0017\u0010\u0008\u001a\u00020\u00078\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0008\u00104\u001a\u0004\u00085\u00106R%\u0010\u000c\u001a\u0010\u0012\u0004\u0012\u00020\n\u0012\u0006\u0012\u0004\u0018\u00010\u000b0\t8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u000c\u00107\u001a\u0004\u00088\u00109R\u001d\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\r0\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u000e\u00100\u001a\u0004\u0008:\u00102R#\u0010\u0010\u001a\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00050\t8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0010\u00107\u001a\u0004\u0008;\u00109R#\u0010\u0012\u001a\u000e\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u00050\t8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0012\u00107\u001a\u0004\u0008<\u00109R#\u0010\u0014\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00050\t8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0014\u00107\u001a\u0004\u0008=\u00109R \u0010@\u001a\u0008\u0012\u0004\u0012\u00020?0>8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008@\u0010A\u001a\u0004\u0008B\u0010CR\u001a\u0010E\u001a\u00020D8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008E\u0010F\u001a\u0004\u0008G\u0010HR\u0016\u0010J\u001a\u00020I8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008J\u0010K\u00a8\u0006M"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;",
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
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "linkParametersRequest",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;",
        "onLinkParametersReceived",
        "Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;",
        "onBeaconReceived",
        "Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;",
        "onInvalidProtocolVersionDetected",
        "<init>",
        "(Lay0/a;Lay0/a;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;Lay0/k;Lay0/a;Lay0/k;Lay0/k;Lay0/k;)V",
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
        "linkParametersRequestValues",
        "sendLinkParameterRequest",
        "(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;)V",
        "sendStaticInformationRequest",
        "()V",
        "sendGetBeacon",
        "beaconInformation",
        "sendUpdateBeacon",
        "(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;)V",
        "sendSmartphoneInformationResponse",
        "handleStaticInformationResponse",
        "([B)V",
        "handleLinkParameterResponse",
        "handleBeaconResponse",
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
        "getLinkParametersRequest",
        "getOnLinkParametersReceived",
        "getOnBeaconReceived",
        "getOnInvalidProtocolVersionDetected",
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
        "Ljava/util/concurrent/atomic/AtomicBoolean;",
        "versionsAreExchangedAndValid",
        "Ljava/util/concurrent/atomic/AtomicBoolean;",
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
.field private static final ADDRESSES:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler$Companion;

.field private static final beaconGetRequest:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final beaconResponse:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final beaconUpdateRequest:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final globalServiceId:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

.field private static final linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final staticInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final staticInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final version:Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;


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

.field private final linkParametersRequest:Lay0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/a;"
        }
    .end annotation
.end field

.field private final onBeaconReceived:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private final onInvalidProtocolVersionDetected:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

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

.field private versionsAreExchangedAndValid:Ljava/util/concurrent/atomic/AtomicBoolean;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->Companion:Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler$Companion;

    .line 8
    .line 9
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 10
    .line 11
    const/16 v2, 0x4c

    .line 12
    .line 13
    const/16 v3, 0x33

    .line 14
    .line 15
    const/16 v4, 0x42

    .line 16
    .line 17
    invoke-direct {v0, v4, v2, v3, v1}, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->globalServiceId:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 21
    .line 22
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 23
    .line 24
    const/4 v3, 0x2

    .line 25
    const/4 v4, 0x0

    .line 26
    invoke-direct {v2, v3, v4, v4, v1}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->version:Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 30
    .line 31
    new-instance v5, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 32
    .line 33
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;

    .line 34
    .line 35
    invoke-direct {v5, v0, v4, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 36
    .line 37
    .line 38
    sput-object v5, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 39
    .line 40
    new-instance v6, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 41
    .line 42
    const/4 v7, 0x1

    .line 43
    invoke-direct {v6, v0, v7, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 44
    .line 45
    .line 46
    sput-object v6, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 47
    .line 48
    move v8, v7

    .line 49
    new-instance v7, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 50
    .line 51
    invoke-direct {v7, v0, v3, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 52
    .line 53
    .line 54
    sput-object v7, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 55
    .line 56
    move v9, v8

    .line 57
    new-instance v8, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 58
    .line 59
    const/4 v10, 0x3

    .line 60
    invoke-direct {v8, v0, v10, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 61
    .line 62
    .line 63
    sput-object v8, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconGetRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 64
    .line 65
    move v11, v9

    .line 66
    new-instance v9, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 67
    .line 68
    const/4 v12, 0x4

    .line 69
    invoke-direct {v9, v0, v12, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 70
    .line 71
    .line 72
    sput-object v9, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconUpdateRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 73
    .line 74
    move v2, v10

    .line 75
    new-instance v10, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 76
    .line 77
    sget-object v12, Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;

    .line 78
    .line 79
    invoke-direct {v10, v0, v4, v12, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 80
    .line 81
    .line 82
    sput-object v10, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 83
    .line 84
    move v4, v11

    .line 85
    new-instance v11, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 86
    .line 87
    invoke-direct {v11, v0, v4, v12, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 88
    .line 89
    .line 90
    sput-object v11, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 91
    .line 92
    move-object v4, v12

    .line 93
    new-instance v12, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 94
    .line 95
    invoke-direct {v12, v0, v3, v4, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 96
    .line 97
    .line 98
    sput-object v12, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 99
    .line 100
    new-instance v13, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 101
    .line 102
    invoke-direct {v13, v0, v2, v4, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 103
    .line 104
    .line 105
    sput-object v13, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 106
    .line 107
    filled-new-array/range {v5 .. v13}, [Ltechnology/cariad/cat/genx/protocol/Address;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    sput-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->ADDRESSES:Ljava/util/Set;

    .line 116
    .line 117
    return-void
.end method

.method public constructor <init>(Lay0/a;Lay0/a;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;Lay0/k;Lay0/a;Lay0/k;Lay0/k;Lay0/k;)V
    .locals 19
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            "Lay0/a;",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
            "Lay0/k;",
            "Lay0/a;",
            "Lay0/k;",
            "Lay0/k;",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    move-object/from16 v5, p5

    .line 12
    .line 13
    move-object/from16 v6, p6

    .line 14
    .line 15
    move-object/from16 v7, p7

    .line 16
    .line 17
    move-object/from16 v8, p8

    .line 18
    .line 19
    const-string v9, "smartphoneInformationResponse"

    .line 20
    .line 21
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const-string v9, "onSmartphoneInformationResponseSent"

    .line 25
    .line 26
    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-string v9, "vehicleAntennaTransportIdentifier"

    .line 30
    .line 31
    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string v9, "sendMessageDispatched"

    .line 35
    .line 36
    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v9, "linkParametersRequest"

    .line 40
    .line 41
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const-string v9, "onLinkParametersReceived"

    .line 45
    .line 46
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    const-string v9, "onBeaconReceived"

    .line 50
    .line 51
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const-string v9, "onInvalidProtocolVersionDetected"

    .line 55
    .line 56
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/protocol/InternalC2PMessageHandler;-><init>()V

    .line 60
    .line 61
    .line 62
    iput-object v1, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationResponse$1:Lay0/a;

    .line 63
    .line 64
    iput-object v2, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onSmartphoneInformationResponseSent:Lay0/a;

    .line 65
    .line 66
    iput-object v3, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 67
    .line 68
    iput-object v4, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendMessageDispatched:Lay0/k;

    .line 69
    .line 70
    iput-object v5, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParametersRequest:Lay0/a;

    .line 71
    .line 72
    iput-object v6, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onLinkParametersReceived:Lay0/k;

    .line 73
    .line 74
    iput-object v7, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onBeaconReceived:Lay0/k;

    .line 75
    .line 76
    iput-object v8, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onInvalidProtocolVersionDetected:Lay0/k;

    .line 77
    .line 78
    sget-object v10, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 79
    .line 80
    sget-object v11, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 81
    .line 82
    sget-object v12, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 83
    .line 84
    sget-object v13, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconGetRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 85
    .line 86
    sget-object v14, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconUpdateRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 87
    .line 88
    sget-object v15, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 89
    .line 90
    sget-object v16, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 91
    .line 92
    sget-object v17, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 93
    .line 94
    sget-object v18, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 95
    .line 96
    filled-new-array/range {v10 .. v18}, [Ltechnology/cariad/cat/genx/protocol/Address;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    iput-object v1, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->addresses:Ljava/util/List;

    .line 105
    .line 106
    sget-object v1, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->globalServiceId:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 107
    .line 108
    iput-object v1, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->globalServiceID:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 109
    .line 110
    new-instance v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 111
    .line 112
    const/4 v2, 0x0

    .line 113
    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 114
    .line 115
    .line 116
    iput-object v1, v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->versionsAreExchangedAndValid:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 117
    .line 118
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendUpdateBeacon$lambda$0(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getADDRESSES$cp()Ljava/util/Set;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->ADDRESSES:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getBeaconGetRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconGetRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getBeaconResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getBeaconUpdateRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconUpdateRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGlobalServiceId$cp()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->globalServiceId:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getLinkParameterRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getLinkParameterResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSmartphoneInformationRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSmartphoneInformationResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getStaticInformationRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getStaticInformationResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getVersion$cp()Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->version:Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic b(JLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleMessage$lambda$0(JLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c([BLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleBeaconResponse$lambda$1([BLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d([BLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleLinkParameterResponse$lambda$1([BLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleMessage$lambda$4(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendLinkParameterRequest$lambda$1$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleMessage$lambda$1(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleStaticInformationResponse$lambda$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final handleBeaconResponse([B)V
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->versionsAreExchangedAndValid:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-string v1, "GenX"

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    invoke-static {p1}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformationKt;->toBeaconInformation([B)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onBeaconReceived:Lay0/k;

    .line 19
    .line 20
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance v0, Lo51/a;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-direct {v0, p1, p0, v3}, Lo51/a;-><init>([BLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_1
    new-instance p1, Lo51/b;

    .line 35
    .line 36
    const/4 v0, 0x6

    .line 37
    invoke-direct {p1, p0, v0}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 38
    .line 39
    .line 40
    invoke-static {p0, v1, v2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method private static final handleBeaconResponse$lambda$1([BLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "handleBeaconResponse(): Received \'BeaconConfiguration\', but data could not be decoded: "

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

.method private static final handleBeaconResponse$lambda$2(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "handleBeaconResponse(): Previous protocol versions did not match -> Ignore \'beaconConfigurationResponse\' - "

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

.method private final handleLinkParameterResponse([B)V
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->versionsAreExchangedAndValid:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-string v1, "GenX"

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    invoke-static {p1}, Ltechnology/cariad/cat/genx/protocol/data/LinkParametersKt;->toLinkParametersResponseValues([B)Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    new-instance v6, Llk/j;

    .line 19
    .line 20
    const/16 p1, 0x1b

    .line 21
    .line 22
    invoke-direct {v6, p1, v0, p0}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lt51/j;

    .line 26
    .line 27
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v8

    .line 31
    const-string p1, "getName(...)"

    .line 32
    .line 33
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v9

    .line 37
    const-string v4, "GenX"

    .line 38
    .line 39
    sget-object v5, Lt51/f;->a:Lt51/f;

    .line 40
    .line 41
    const/4 v7, 0x0

    .line 42
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onLinkParametersReceived:Lay0/k;

    .line 49
    .line 50
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_0
    new-instance v0, Lo51/a;

    .line 55
    .line 56
    const/4 v3, 0x1

    .line 57
    invoke-direct {v0, p1, p0, v3}, Lo51/a;-><init>([BLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 58
    .line 59
    .line 60
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_1
    new-instance p1, Lo51/b;

    .line 65
    .line 66
    const/4 v0, 0x2

    .line 67
    invoke-direct {p1, p0, v0}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 68
    .line 69
    .line 70
    invoke-static {p0, v1, v2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 71
    .line 72
    .line 73
    return-void
.end method

.method private static final handleLinkParameterResponse$lambda$0$0(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "handleLinkParameterResponse(): Received link parameters = "

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

.method private static final handleLinkParameterResponse$lambda$1([BLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "handleLinkParameterResponse(): Cannot decode data to \'LinkParameters\', data = "

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

.method private static final handleLinkParameterResponse$lambda$2(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "handleLinkParameterResponse(): Previous protocol versions did not match -> Ignore \'linkParameterResponse\' - "

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

.method private static final handleMessage$lambda$0(JLtechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/protocol/AddressKt;->toHexString(J)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p1, p2, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

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

.method private static final handleMessage$lambda$1(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

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

.method private static final handleMessage$lambda$2(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "handleMessage(): Received \'staticInformationResponse\' - "

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

.method private static final handleMessage$lambda$3(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

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

.method private static final handleMessage$lambda$4(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "handleMessage(): Received \'beaconResponse\' - "

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

.method private final handleStaticInformationResponse([B)V
    .locals 4

    .line 1
    invoke-static {p1}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersionKt;->toProtocolVersion([B)Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const-string v0, "GenX"

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    new-instance p1, Lo51/b;

    .line 11
    .line 12
    const/16 v2, 0xd

    .line 13
    .line 14
    invoke-direct {p1, p0, v2}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0, v0, v1, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    sget-object v2, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->version:Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 22
    .line 23
    invoke-virtual {p1, v2}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->versionsAreExchangedAndValid:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 30
    .line 31
    const/4 v0, 0x1

    .line 32
    invoke-virtual {p1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParametersRequest:Lay0/a;

    .line 36
    .line 37
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendLinkParameterRequest(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendGetBeacon()V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    new-instance v2, Llk/j;

    .line 51
    .line 52
    const/16 v3, 0x1d

    .line 53
    .line 54
    invoke-direct {v2, v3, p1, p0}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-static {p0, v0, v1, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 58
    .line 59
    .line 60
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->versionsAreExchangedAndValid:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 61
    .line 62
    const/4 v1, 0x0

    .line 63
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 64
    .line 65
    .line 66
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onInvalidProtocolVersionDetected:Lay0/k;

    .line 67
    .line 68
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method private static final handleStaticInformationResponse$lambda$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "handleStaticInformationResponse(): Version could not be extracted from received bytearray - "

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

.method private static final handleStaticInformationResponse$lambda$1(Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->version:Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 2
    .line 3
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "handleStaticInformationResponse(): Version did not match, expected = "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", received = "

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, " - "

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public static synthetic i(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleLinkParameterResponse$lambda$0$0(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendSmartphoneInformationResponse$lambda$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendLinkParameterRequest$lambda$0(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleLinkParameterResponse$lambda$2(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic m(Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleStaticInformationResponse$lambda$1(Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendSmartphoneInformationResponse$lambda$1(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic o(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleMessage$lambda$3(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic p(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendStaticInformationRequest$lambda$1$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic q(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendStaticInformationRequest$lambda$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic r(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleMessage$lambda$2(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic s(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendGetBeacon$lambda$1$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final sendGetBeacon$lambda$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "sendGetBeacon() - "

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

.method private static final sendGetBeacon$lambda$1$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "sendGetBeacon(): Failed to send message - "

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

.method private static final sendLinkParameterRequest$lambda$0(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

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

.method private static final sendLinkParameterRequest$lambda$1$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

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
    new-instance v3, Lo51/b;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {v3, p0, v0}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendMessageDispatched:Lay0/k;

    .line 31
    .line 32
    new-instance v1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 33
    .line 34
    sget-object v2, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 35
    .line 36
    sget-object v3, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 37
    .line 38
    iget-object v4, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationResponse$1:Lay0/a;

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
    new-instance v11, Lo51/b;

    .line 64
    .line 65
    const/4 v0, 0x1

    .line 66
    invoke-direct {v11, p0, v0}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onSmartphoneInformationResponseSent:Lay0/a;

    .line 91
    .line 92
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    return-void
.end method

.method private static final sendSmartphoneInformationResponse$lambda$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

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

.method private static final sendSmartphoneInformationResponse$lambda$1(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

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

.method private static final sendStaticInformationRequest$lambda$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "sendStaticInformationRequest() - "

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

.method private static final sendStaticInformationRequest$lambda$1$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "sendStaticInformationRequest(): Failed to send message - "

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

.method private static final sendUpdateBeacon$lambda$0(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "sendUpdateBeacon(): send "

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

.method private static final sendUpdateBeacon$lambda$1$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    const-string v0, "sendUpdateBeacon(): Failed to send message - "

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

.method public static synthetic t(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendGetBeacon$lambda$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic u(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendUpdateBeacon$lambda$1$0(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic v(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleBeaconResponse$lambda$2(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->addresses:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getGlobalServiceID()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->globalServiceID:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLinkParametersRequest()Lay0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/a;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParametersRequest:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOnBeaconReceived()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onBeaconReceived:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOnInvalidProtocolVersionDetected()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onInvalidProtocolVersionDetected:Lay0/k;

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onLinkParametersReceived:Lay0/k;

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->onSmartphoneInformationResponseSent:Lay0/a;

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendMessageDispatched:Lay0/k;

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationResponse$1:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVehicleAntennaTransportIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->vehicleAntennaTransportIdentifier:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public handleMessage(JBZ[B)Z
    .locals 8

    .line 1
    const-string p3, "data"

    .line 2
    .line 3
    invoke-static {p5, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

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
    const/4 p4, 0x1

    .line 15
    if-eqz p3, :cond_5

    .line 16
    .line 17
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 18
    .line 19
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    cmp-long p3, p1, v0

    .line 24
    .line 25
    if-eqz p3, :cond_5

    .line 26
    .line 27
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 28
    .line 29
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 30
    .line 31
    .line 32
    move-result-wide v0

    .line 33
    cmp-long p3, p1, v0

    .line 34
    .line 35
    if-eqz p3, :cond_5

    .line 36
    .line 37
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconGetRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 38
    .line 39
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 40
    .line 41
    .line 42
    move-result-wide v0

    .line 43
    cmp-long p3, p1, v0

    .line 44
    .line 45
    if-eqz p3, :cond_5

    .line 46
    .line 47
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconUpdateRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 48
    .line 49
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 50
    .line 51
    .line 52
    move-result-wide v0

    .line 53
    cmp-long p3, p1, v0

    .line 54
    .line 55
    if-nez p3, :cond_0

    .line 56
    .line 57
    goto/16 :goto_0

    .line 58
    .line 59
    :cond_0
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->smartphoneInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 60
    .line 61
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 62
    .line 63
    .line 64
    move-result-wide v0

    .line 65
    cmp-long p3, p1, v0

    .line 66
    .line 67
    const-string v0, "getName(...)"

    .line 68
    .line 69
    sget-object v3, Lt51/d;->a:Lt51/d;

    .line 70
    .line 71
    if-nez p3, :cond_1

    .line 72
    .line 73
    new-instance v4, Lo51/b;

    .line 74
    .line 75
    const/4 p1, 0x4

    .line 76
    invoke-direct {v4, p0, p1}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 77
    .line 78
    .line 79
    new-instance v1, Lt51/j;

    .line 80
    .line 81
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v7

    .line 89
    const-string v2, "GenX"

    .line 90
    .line 91
    const/4 v5, 0x0

    .line 92
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 96
    .line 97
    .line 98
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendSmartphoneInformationResponse()V

    .line 99
    .line 100
    .line 101
    return p4

    .line 102
    :cond_1
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 103
    .line 104
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 105
    .line 106
    .line 107
    move-result-wide v1

    .line 108
    cmp-long p3, p1, v1

    .line 109
    .line 110
    if-nez p3, :cond_2

    .line 111
    .line 112
    new-instance v4, Lo51/b;

    .line 113
    .line 114
    const/4 p1, 0x5

    .line 115
    invoke-direct {v4, p0, p1}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 116
    .line 117
    .line 118
    new-instance v1, Lt51/j;

    .line 119
    .line 120
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v7

    .line 128
    const-string v2, "GenX"

    .line 129
    .line 130
    const/4 v5, 0x0

    .line 131
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 135
    .line 136
    .line 137
    invoke-direct {p0, p5}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleStaticInformationResponse([B)V

    .line 138
    .line 139
    .line 140
    return p4

    .line 141
    :cond_2
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 142
    .line 143
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 144
    .line 145
    .line 146
    move-result-wide v1

    .line 147
    cmp-long p3, p1, v1

    .line 148
    .line 149
    if-nez p3, :cond_3

    .line 150
    .line 151
    new-instance v4, Lo51/b;

    .line 152
    .line 153
    const/4 p1, 0x7

    .line 154
    invoke-direct {v4, p0, p1}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 155
    .line 156
    .line 157
    new-instance v1, Lt51/j;

    .line 158
    .line 159
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v6

    .line 163
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v7

    .line 167
    const-string v2, "GenX"

    .line 168
    .line 169
    const/4 v5, 0x0

    .line 170
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 174
    .line 175
    .line 176
    invoke-direct {p0, p5}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleLinkParameterResponse([B)V

    .line 177
    .line 178
    .line 179
    return p4

    .line 180
    :cond_3
    sget-object p3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconResponse:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 181
    .line 182
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 183
    .line 184
    .line 185
    move-result-wide v1

    .line 186
    cmp-long p1, p1, v1

    .line 187
    .line 188
    if-nez p1, :cond_4

    .line 189
    .line 190
    new-instance v4, Lo51/b;

    .line 191
    .line 192
    const/16 p1, 0x8

    .line 193
    .line 194
    invoke-direct {v4, p0, p1}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 195
    .line 196
    .line 197
    new-instance v1, Lt51/j;

    .line 198
    .line 199
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v6

    .line 203
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v7

    .line 207
    const-string v2, "GenX"

    .line 208
    .line 209
    const/4 v5, 0x0

    .line 210
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 214
    .line 215
    .line 216
    invoke-direct {p0, p5}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->handleBeaconResponse([B)V

    .line 217
    .line 218
    .line 219
    return p4

    .line 220
    :cond_4
    const/4 p0, 0x0

    .line 221
    return p0

    .line 222
    :cond_5
    :goto_0
    new-instance p3, Lh2/u2;

    .line 223
    .line 224
    const/4 p5, 0x2

    .line 225
    invoke-direct {p3, p1, p2, p0, p5}, Lh2/u2;-><init>(JLjava/lang/Object;I)V

    .line 226
    .line 227
    .line 228
    const/4 p1, 0x0

    .line 229
    const-string p2, "GenX"

    .line 230
    .line 231
    invoke-static {p0, p2, p1, p3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 232
    .line 233
    .line 234
    return p4
.end method

.method public final sendGetBeacon()V
    .locals 15

    .line 1
    new-instance v3, Lo51/b;

    .line 2
    .line 3
    const/16 v0, 0xb

    .line 4
    .line 5
    invoke-direct {v3, p0, v0}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v7, "getName(...)"

    .line 15
    .line 16
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendMessageDispatched:Lay0/k;

    .line 32
    .line 33
    new-instance v1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 34
    .line 35
    sget-object v2, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconGetRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 36
    .line 37
    sget-object v3, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 38
    .line 39
    const/4 v4, 0x1

    .line 40
    new-array v5, v4, [B

    .line 41
    .line 42
    const/4 v6, 0x0

    .line 43
    aput-byte v4, v5, v6

    .line 44
    .line 45
    invoke-direct {v1, v2, v3, v4, v5}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 46
    .line 47
    .line 48
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    move-object v12, v0

    .line 53
    check-cast v12, Ltechnology/cariad/cat/genx/GenXError;

    .line 54
    .line 55
    if-eqz v12, :cond_0

    .line 56
    .line 57
    new-instance v11, Lo51/b;

    .line 58
    .line 59
    const/16 v0, 0xc

    .line 60
    .line 61
    invoke-direct {v11, p0, v0}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 62
    .line 63
    .line 64
    new-instance v8, Lt51/j;

    .line 65
    .line 66
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v13

    .line 70
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v14

    .line 74
    const-string v9, "GenX"

    .line 75
    .line 76
    sget-object v10, Lt51/e;->a:Lt51/e;

    .line 77
    .line 78
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 82
    .line 83
    .line 84
    :cond_0
    return-void
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
    const/4 v0, 0x0

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
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendMessageDispatched:Lay0/k;

    .line 36
    .line 37
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 38
    .line 39
    sget-object v3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->linkParameterRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 40
    .line 41
    sget-object v4, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

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
    new-instance v4, Lo51/b;

    .line 61
    .line 62
    const/16 p1, 0xe

    .line 63
    .line 64
    invoke-direct {v4, p0, p1}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 65
    .line 66
    .line 67
    new-instance v1, Lt51/j;

    .line 68
    .line 69
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    const-string v2, "GenX"

    .line 78
    .line 79
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 80
    .line 81
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 85
    .line 86
    .line 87
    :cond_0
    return-void
.end method

.method public final sendStaticInformationRequest()V
    .locals 15

    .line 1
    new-instance v3, Lo51/b;

    .line 2
    .line 3
    const/16 v0, 0x9

    .line 4
    .line 5
    invoke-direct {v3, p0, v0}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v7, "getName(...)"

    .line 15
    .line 16
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendMessageDispatched:Lay0/k;

    .line 32
    .line 33
    new-instance v1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 34
    .line 35
    sget-object v2, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->staticInformationRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 36
    .line 37
    sget-object v3, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 38
    .line 39
    const/4 v4, 0x1

    .line 40
    new-array v5, v4, [B

    .line 41
    .line 42
    const/4 v6, 0x0

    .line 43
    aput-byte v4, v5, v6

    .line 44
    .line 45
    invoke-direct {v1, v2, v3, v4, v5}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 46
    .line 47
    .line 48
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    move-object v12, v0

    .line 53
    check-cast v12, Ltechnology/cariad/cat/genx/GenXError;

    .line 54
    .line 55
    if-eqz v12, :cond_0

    .line 56
    .line 57
    new-instance v11, Lo51/b;

    .line 58
    .line 59
    const/16 v0, 0xa

    .line 60
    .line 61
    invoke-direct {v11, p0, v0}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 62
    .line 63
    .line 64
    new-instance v8, Lt51/j;

    .line 65
    .line 66
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v13

    .line 70
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v14

    .line 74
    const-string v9, "GenX"

    .line 75
    .line 76
    sget-object v10, Lt51/e;->a:Lt51/e;

    .line 77
    .line 78
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 82
    .line 83
    .line 84
    :cond_0
    return-void
.end method

.method public final sendUpdateBeacon(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;)V
    .locals 8

    .line 1
    const-string v0, "beaconInformation"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Llk/j;

    .line 7
    .line 8
    const/16 v0, 0x1c

    .line 9
    .line 10
    invoke-direct {v4, v0, p1, p0}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    new-instance v1, Lt51/j;

    .line 14
    .line 15
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v0, "getName(...)"

    .line 20
    .line 21
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    const-string v2, "GenX"

    .line 26
    .line 27
    sget-object v3, Lt51/d;->a:Lt51/d;

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->sendMessageDispatched:Lay0/k;

    .line 37
    .line 38
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 39
    .line 40
    sget-object v3, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->beaconUpdateRequest:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 41
    .line 42
    sget-object v4, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 43
    .line 44
    const/4 v5, 0x1

    .line 45
    invoke-static {p1}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformationKt;->toByteArray(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;)[B

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-direct {v2, v3, v4, v5, p1}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    move-object v5, p1

    .line 57
    check-cast v5, Ltechnology/cariad/cat/genx/GenXError;

    .line 58
    .line 59
    if-eqz v5, :cond_0

    .line 60
    .line 61
    new-instance v4, Lo51/b;

    .line 62
    .line 63
    const/4 p1, 0x3

    .line 64
    invoke-direct {v4, p0, p1}, Lo51/b;-><init>(Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;I)V

    .line 65
    .line 66
    .line 67
    new-instance v1, Lt51/j;

    .line 68
    .line 69
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    const-string v2, "GenX"

    .line 78
    .line 79
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 80
    .line 81
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 85
    .line 86
    .line 87
    :cond_0
    return-void
.end method

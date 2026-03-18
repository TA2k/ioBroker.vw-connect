.class public final Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0013\n\u0002\u0010\"\n\u0002\u0008\u0003\u0008\u0080\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0011\u0010\u000c\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000e\u0010\u000fR\u0011\u0010\u0010\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u000fR\u0011\u0010\u0012\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u000fR\u0011\u0010\u0014\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0015\u0010\u000fR\u0011\u0010\u0016\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0017\u0010\u000fR\u0011\u0010\u0018\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0019\u0010\u000fR\u0011\u0010\u001a\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001b\u0010\u000fR\u0011\u0010\u001c\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001d\u0010\u000fR\u0011\u0010\u001e\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001f\u0010\u000fR\u0017\u0010 \u001a\u0008\u0012\u0004\u0012\u00020\r0!\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\"\u0010#\u00a8\u0006$"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler$Companion;",
        "",
        "<init>",
        "()V",
        "globalServiceId",
        "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "getGlobalServiceId",
        "()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "version",
        "Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;",
        "getVersion",
        "()Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;",
        "staticInformationRequest",
        "Ltechnology/cariad/cat/genx/protocol/Address;",
        "getStaticInformationRequest",
        "()Ltechnology/cariad/cat/genx/protocol/Address;",
        "linkParameterRequest",
        "getLinkParameterRequest",
        "smartphoneInformationResponse",
        "getSmartphoneInformationResponse",
        "beaconGetRequest",
        "getBeaconGetRequest",
        "beaconUpdateRequest",
        "getBeaconUpdateRequest",
        "staticInformationResponse",
        "getStaticInformationResponse",
        "linkParameterResponse",
        "getLinkParameterResponse",
        "smartphoneInformationRequest",
        "getSmartphoneInformationRequest",
        "beaconResponse",
        "getBeaconResponse",
        "ADDRESSES",
        "",
        "getADDRESSES",
        "()Ljava/util/Set;",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final getADDRESSES()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getADDRESSES$cp()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getBeaconGetRequest()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getBeaconGetRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getBeaconResponse()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getBeaconResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getBeaconUpdateRequest()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getBeaconUpdateRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getGlobalServiceId()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getGlobalServiceId$cp()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getLinkParameterRequest()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getLinkParameterRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getLinkParameterResponse()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getLinkParameterResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getSmartphoneInformationRequest()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getSmartphoneInformationRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getSmartphoneInformationResponse()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getSmartphoneInformationResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getStaticInformationRequest()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getStaticInformationRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getStaticInformationResponse()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getStaticInformationResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getVersion()Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->access$getVersion$cp()Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

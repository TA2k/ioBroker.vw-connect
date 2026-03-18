.class public final Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u000f\n\u0002\u0010\"\n\u0002\u0008\u0003\u0008\u0080\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0011\u0010\u000c\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000bR\u0011\u0010\u000e\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u000bR\u0011\u0010\u0010\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u000bR\u0011\u0010\u0012\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u000bR\u0011\u0010\u0014\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0015\u0010\u000bR\u0011\u0010\u0016\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0017\u0010\u000bR\u0017\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\t0\u0019\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001a\u0010\u001b\u00a8\u0006\u001c"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;",
        "",
        "<init>",
        "()V",
        "GLOBAL_SERVICE_ID",
        "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "getGLOBAL_SERVICE_ID",
        "()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "STATIC_INFO_REQUEST",
        "Ltechnology/cariad/cat/genx/protocol/Address;",
        "getSTATIC_INFO_REQUEST",
        "()Ltechnology/cariad/cat/genx/protocol/Address;",
        "OUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST",
        "getOUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST",
        "OUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND",
        "getOUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND",
        "OUTER_ANTENNA_KEY_EXCHANGE_QPM1",
        "getOUTER_ANTENNA_KEY_EXCHANGE_QPM1",
        "STATIC_INFO_RESPONSE",
        "getSTATIC_INFO_RESPONSE",
        "OUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE",
        "getOUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE",
        "OUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED",
        "getOUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;-><init>()V

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
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getADDRESSES$cp()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getGLOBAL_SERVICE_ID()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getGLOBAL_SERVICE_ID$cp()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getOUTER_ANTENNA_KEY_EXCHANGE_QPM1()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getOUTER_ANTENNA_KEY_EXCHANGE_QPM1$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getOUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getOUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getOUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getOUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getOUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getOUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getOUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getOUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getSTATIC_INFO_REQUEST()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getSTATIC_INFO_REQUEST$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getSTATIC_INFO_RESPONSE()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getSTATIC_INFO_RESPONSE$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.class public final Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/protocol/AddressDirection;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0005\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0011\u0010\u0008\u001a\u00020\u0005*\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u0011\u0010\u0008\u001a\u00020\u0005*\u00020\t\u00a2\u0006\u0004\u0008\u0008\u0010\u0007\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;",
        "",
        "<init>",
        "()V",
        "Llx0/s;",
        "Ltechnology/cariad/cat/genx/protocol/AddressDirection;",
        "asAddressDirection-7apg3OU",
        "(B)Ltechnology/cariad/cat/genx/protocol/AddressDirection;",
        "asAddressDirection",
        "",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final asAddressDirection(B)Ltechnology/cariad/cat/genx/protocol/AddressDirection;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;->asAddressDirection-7apg3OU(B)Ltechnology/cariad/cat/genx/protocol/AddressDirection;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final asAddressDirection-7apg3OU(B)Ltechnology/cariad/cat/genx/protocol/AddressDirection;
    .locals 1

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->getRawValue-w2LRezQ$genx_release()B

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    sget-object p0, Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;

    .line 11
    .line 12
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->getRawValue-w2LRezQ$genx_release()B

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-ne p1, v0, :cond_1

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_1
    new-instance p0, Ltechnology/cariad/cat/genx/protocol/AddressDirection$Other;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/genx/protocol/AddressDirection$Other;-><init>(BLkotlin/jvm/internal/g;)V

    .line 23
    .line 24
    .line 25
    return-object p0
.end method

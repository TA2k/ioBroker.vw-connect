.class public final Ltechnology/cariad/cat/genx/Car2PhoneModeKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\"\u001a\u0010\u0000\u001a\u0004\u0018\u00010\u0001*\u00020\u00028@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "car2PhoneMode",
        "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "",
        "getCar2PhoneMode",
        "(I)Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final getCar2PhoneMode(I)Ltechnology/cariad/cat/genx/Car2PhoneMode;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->Companion:Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;->getInvalid()Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/Car2PhoneMode;->getRawValue()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-ne p0, v0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    return-object p0

    .line 15
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 16
    .line 17
    invoke-direct {v0, p0}, Ltechnology/cariad/cat/genx/Car2PhoneMode;-><init>(I)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

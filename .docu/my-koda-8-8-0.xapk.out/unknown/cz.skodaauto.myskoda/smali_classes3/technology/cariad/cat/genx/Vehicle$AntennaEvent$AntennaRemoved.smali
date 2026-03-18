.class public final Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaRemoved;
.super Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "AntennaRemoved"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaRemoved;",
        "Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;",
        "antenna",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "<init>",
        "(Ltechnology/cariad/cat/genx/Antenna;)V",
        "getAntenna",
        "()Ltechnology/cariad/cat/genx/Antenna;",
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


# instance fields
.field private final antenna:Ltechnology/cariad/cat/genx/Antenna;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/Antenna;)V
    .locals 1

    .line 1
    const-string v0, "antenna"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;-><init>(Lkotlin/jvm/internal/g;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaRemoved;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final getAntenna()Ltechnology/cariad/cat/genx/Antenna;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaRemoved;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 2
    .line 3
    return-object p0
.end method

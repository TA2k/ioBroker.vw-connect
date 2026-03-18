.class final Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;->invoke()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic $existingVehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

.field final synthetic $newVehicleInformation:Ltechnology/cariad/cat/genx/Vehicle$Information;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Vehicle$Information;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$3;->$existingVehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$3;->$newVehicleInformation:Ltechnology/cariad/cat/genx/Vehicle$Information;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$3;->invoke()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final invoke()Ljava/lang/String;
    .locals 3

    .line 2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$3;->$existingVehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    invoke-interface {v0}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    move-result-object v0

    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1$1$3;->$newVehicleInformation:Ltechnology/cariad/cat/genx/Vehicle$Information;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "registerVehicles(): Failed to update outer antenna of "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, " with "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

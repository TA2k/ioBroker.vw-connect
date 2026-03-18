.class public abstract Lkp/x9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;ZLs71/h;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->getHasOpenDoorsOrFlaps$remoteparkassistcoremeb_release()Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    move-object v9, v1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v9, v0

    .line 15
    :goto_0
    const/4 v1, 0x1

    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isVehicleLocked$remoteparkassistcoremeb_release()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    xor-int/2addr v2, v1

    .line 23
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    move-object v8, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move-object v8, v0

    .line 30
    :goto_1
    if-eqz p0, :cond_2

    .line 31
    .line 32
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getGearStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    goto :goto_2

    .line 37
    :cond_2
    move-object p0, v0

    .line 38
    :goto_2
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;->P:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;

    .line 39
    .line 40
    if-ne p0, v2, :cond_3

    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_3
    const/4 v1, 0x0

    .line 44
    :goto_3
    if-eqz p1, :cond_4

    .line 45
    .line 46
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->getHasOpenWindows$remoteparkassistcoremeb_release()Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    :cond_4
    move-object v5, v0

    .line 55
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 56
    .line 57
    const/4 v6, 0x0

    .line 58
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 59
    .line 60
    .line 61
    move-result-object v7

    .line 62
    move v4, p2

    .line 63
    move-object v3, p3

    .line 64
    invoke-direct/range {v2 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;-><init>(Ls71/h;ZLjava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 65
    .line 66
    .line 67
    return-object v2
.end method

.method public static varargs b([Lh0/m;)Lh0/m;
    .locals 2

    .line 1
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    new-instance p0, Lh0/o;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v1, 0x1

    .line 22
    if-ne v0, v1, :cond_1

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Lh0/m;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_1
    new-instance v0, Lh0/n;

    .line 33
    .line 34
    invoke-direct {v0, p0}, Lh0/n;-><init>(Ljava/util/List;)V

    .line 35
    .line 36
    .line 37
    return-object v0
.end method

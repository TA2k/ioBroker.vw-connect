.class public Lorg/altbeacon/beacon/AltBeacon$Builder;
.super Lorg/altbeacon/beacon/Beacon$Builder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/AltBeacon;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/Beacon$Builder;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public build()Lorg/altbeacon/beacon/Beacon;
    .locals 1

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/AltBeacon;

    .line 2
    .line 3
    invoke-super {p0}, Lorg/altbeacon/beacon/Beacon$Builder;->build()Lorg/altbeacon/beacon/Beacon;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/AltBeacon;-><init>(Lorg/altbeacon/beacon/Beacon;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public setMfgReserved(I)Lorg/altbeacon/beacon/AltBeacon$Builder;
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon$Builder;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 2
    .line 3
    iget-object v0, v0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon$Builder;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 12
    .line 13
    new-instance v1, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v1, v0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 19
    .line 20
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon$Builder;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 21
    .line 22
    iget-object v0, v0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 23
    .line 24
    int-to-long v1, p1

    .line 25
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    return-object p0
.end method

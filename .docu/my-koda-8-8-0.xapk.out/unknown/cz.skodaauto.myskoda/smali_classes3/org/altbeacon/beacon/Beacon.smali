.class public Lorg/altbeacon/beacon/Beacon;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;
.implements Ljava/io/Serializable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/Beacon$Builder;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lorg/altbeacon/beacon/Beacon;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljava/lang/Deprecated;
    .end annotation
.end field

.field private static final TAG:Ljava/lang/String; = "Beacon"

.field private static final UNMODIFIABLE_LIST_OF_IDENTIFIER:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Identifier;",
            ">;"
        }
    .end annotation
.end field

.field private static final UNMODIFIABLE_LIST_OF_LONG:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field protected static beaconDataFactory:Lorg/altbeacon/beacon/client/BeaconDataFactory;

.field protected static sDistanceCalculator:Lorg/altbeacon/beacon/distance/DistanceCalculator;

.field protected static sHardwareEqualityEnforced:Z


# instance fields
.field protected mBeaconTypeCode:I

.field protected mBluetoothAddress:Ljava/lang/String;

.field protected mBluetoothName:Ljava/lang/String;

.field protected mDataFields:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field protected mDistance:Ljava/lang/Double;

.field protected mExtraDataFields:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field protected mFirstCycleDetectionTimestamp:J

.field protected mIdentifiers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Identifier;",
            ">;"
        }
    .end annotation
.end field

.field protected mLastCycleDetectionTimestamp:J

.field protected mLastPacketRawBytes:[B

.field protected mManufacturer:I

.field protected mMultiFrameBeacon:Z

.field private mPacketCount:I

.field protected mParserIdentifier:Ljava/lang/String;

.field protected mRssi:I

.field private mRssiMeasurementCount:I

.field private mRunningAverageRssi:Ljava/lang/Double;

.field protected mServiceUuid:I

.field protected mServiceUuid128Bit:[B

.field protected mTxPower:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lorg/altbeacon/beacon/Beacon;->UNMODIFIABLE_LIST_OF_LONG:Ljava/util/List;

    .line 11
    .line 12
    new-instance v0, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lorg/altbeacon/beacon/Beacon;->UNMODIFIABLE_LIST_OF_IDENTIFIER:Ljava/util/List;

    .line 22
    .line 23
    const/4 v0, 0x0

    .line 24
    sput-boolean v0, Lorg/altbeacon/beacon/Beacon;->sHardwareEqualityEnforced:Z

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    sput-object v0, Lorg/altbeacon/beacon/Beacon;->sDistanceCalculator:Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 28
    .line 29
    new-instance v0, Lorg/altbeacon/beacon/client/NullBeaconDataFactory;

    .line 30
    .line 31
    invoke-direct {v0}, Lorg/altbeacon/beacon/client/NullBeaconDataFactory;-><init>()V

    .line 32
    .line 33
    .line 34
    sput-object v0, Lorg/altbeacon/beacon/Beacon;->beaconDataFactory:Lorg/altbeacon/beacon/client/BeaconDataFactory;

    .line 35
    .line 36
    new-instance v0, Lorg/altbeacon/beacon/Beacon$1;

    .line 37
    .line 38
    invoke-direct {v0}, Lorg/altbeacon/beacon/Beacon$1;-><init>()V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lorg/altbeacon/beacon/Beacon;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 42
    .line 43
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 74
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 75
    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    .line 76
    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    const/4 v1, 0x0

    .line 77
    iput-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    const/4 v1, -0x1

    .line 78
    iput v1, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    .line 79
    new-array v1, v0, [B

    iput-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    .line 80
    iput-boolean v0, p0, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    const-wide/16 v1, 0x0

    .line 81
    iput-wide v1, p0, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 82
    iput-wide v1, p0, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 83
    new-array v0, v0, [B

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    .line 84
    new-instance v0, Ljava/util/ArrayList;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 85
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 86
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 7
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    .line 3
    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    const/4 v1, 0x0

    .line 4
    iput-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    const/4 v2, -0x1

    .line 5
    iput v2, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    .line 6
    new-array v2, v0, [B

    iput-object v2, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    .line 7
    iput-boolean v0, p0, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    const-wide/16 v2, 0x0

    .line 8
    iput-wide v2, p0, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 9
    iput-wide v2, p0, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 10
    new-array v2, v0, [B

    iput-object v2, p0, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    .line 11
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v2

    .line 12
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v3, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    move v3, v0

    :goto_0
    if-ge v3, v2, :cond_0

    .line 13
    iget-object v4, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v5}, Lorg/altbeacon/beacon/Identifier;->parse(Ljava/lang/String;)Lorg/altbeacon/beacon/Identifier;

    move-result-object v5

    invoke-interface {v4, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p1}, Landroid/os/Parcel;->readDouble()D

    move-result-wide v2

    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v2

    iput-object v2, p0, Lorg/altbeacon/beacon/Beacon;->mDistance:Ljava/lang/Double;

    .line 15
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v2

    iput v2, p0, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    .line 16
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v2

    iput v2, p0, Lorg/altbeacon/beacon/Beacon;->mTxPower:I

    .line 17
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v2

    iput-object v2, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothAddress:Ljava/lang/String;

    .line 18
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v2

    iput v2, p0, Lorg/altbeacon/beacon/Beacon;->mBeaconTypeCode:I

    .line 19
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v2

    iput v2, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    .line 20
    invoke-virtual {p1}, Landroid/os/Parcel;->readBoolean()Z

    move-result v2

    if-eqz v2, :cond_1

    const/16 v2, 0x10

    .line 21
    new-array v3, v2, [B

    iput-object v3, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    move v3, v0

    :goto_1
    if-ge v3, v2, :cond_1

    .line 22
    iget-object v4, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v5

    aput-byte v5, v4, v3

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    .line 23
    :cond_1
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v2

    .line 24
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v3, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    move v3, v0

    :goto_2
    if-ge v3, v2, :cond_2

    .line 25
    iget-object v4, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v5

    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v5

    invoke-interface {v4, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_2

    .line 26
    :cond_2
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v2

    .line 27
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v3, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    move v3, v0

    :goto_3
    if-ge v3, v2, :cond_3

    .line 28
    iget-object v4, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v5

    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v5

    invoke-interface {v4, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_3

    .line 29
    :cond_3
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v2

    iput v2, p0, Lorg/altbeacon/beacon/Beacon;->mManufacturer:I

    .line 30
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v2

    iput-object v2, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothName:Ljava/lang/String;

    .line 31
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v2

    iput-object v2, p0, Lorg/altbeacon/beacon/Beacon;->mParserIdentifier:Ljava/lang/String;

    .line 32
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v2

    const/4 v3, 0x1

    if-eqz v2, :cond_4

    move v2, v3

    goto :goto_4

    :cond_4
    move v2, v0

    :goto_4
    iput-boolean v2, p0, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    .line 33
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Double;

    iput-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    .line 34
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v1

    iput v1, p0, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    .line 35
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v1

    iput v1, p0, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    .line 36
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v1

    iput-wide v1, p0, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 37
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v1

    iput-wide v1, p0, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 38
    invoke-static {v3}, Lorg/altbeacon/beacon/BeaconManager;->setDebug(Z)V

    const/16 v1, 0x3e

    .line 39
    new-array v2, v1, [B

    .line 40
    :try_start_0
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->readByteArray([B)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_6

    :catch_0
    :goto_5
    if-ge v0, v1, :cond_5

    .line 41
    :try_start_1
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v3

    .line 42
    aput-byte v3, v2, v3
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    add-int/lit8 v0, v0, 0x1

    goto :goto_5

    .line 43
    :catch_1
    :cond_5
    :goto_6
    iput-object v2, p0, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    return-void
.end method

.method public constructor <init>(Lorg/altbeacon/beacon/Beacon;)V
    .locals 3

    .line 44
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 45
    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    .line 46
    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    const/4 v1, 0x0

    .line 47
    iput-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    const/4 v1, -0x1

    .line 48
    iput v1, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    .line 49
    new-array v1, v0, [B

    iput-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    .line 50
    iput-boolean v0, p0, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    const-wide/16 v1, 0x0

    .line 51
    iput-wide v1, p0, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 52
    iput-wide v1, p0, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 53
    new-array v0, v0, [B

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    .line 54
    new-instance v0, Ljava/util/ArrayList;

    iget-object v1, p1, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 55
    new-instance v0, Ljava/util/ArrayList;

    iget-object v1, p1, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 56
    new-instance v0, Ljava/util/ArrayList;

    iget-object v1, p1, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    .line 57
    iget-object v0, p1, Lorg/altbeacon/beacon/Beacon;->mDistance:Ljava/lang/Double;

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mDistance:Ljava/lang/Double;

    .line 58
    iget-object v0, p1, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    .line 59
    iget v0, p1, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    .line 60
    iget v0, p1, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    .line 61
    iget v0, p1, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    .line 62
    iget v0, p1, Lorg/altbeacon/beacon/Beacon;->mTxPower:I

    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mTxPower:I

    .line 63
    iget-object v0, p1, Lorg/altbeacon/beacon/Beacon;->mBluetoothAddress:Ljava/lang/String;

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothAddress:Ljava/lang/String;

    .line 64
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getBeaconTypeCode()I

    move-result v0

    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mBeaconTypeCode:I

    .line 65
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getServiceUuid()I

    move-result v0

    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    .line 66
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getServiceUuid128Bit()[B

    move-result-object v0

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    .line 67
    iget-object v0, p1, Lorg/altbeacon/beacon/Beacon;->mBluetoothName:Ljava/lang/String;

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothName:Ljava/lang/String;

    .line 68
    iget-object v0, p1, Lorg/altbeacon/beacon/Beacon;->mParserIdentifier:Ljava/lang/String;

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mParserIdentifier:Ljava/lang/String;

    .line 69
    iget-boolean v0, p1, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    iput-boolean v0, p0, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    .line 70
    iget v0, p1, Lorg/altbeacon/beacon/Beacon;->mManufacturer:I

    iput v0, p0, Lorg/altbeacon/beacon/Beacon;->mManufacturer:I

    .line 71
    iget-wide v0, p1, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    iput-wide v0, p0, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 72
    iget-wide v0, p1, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    iput-wide v0, p0, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 73
    iget-object p1, p1, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    iput-object p1, p0, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    return-void
.end method

.method public static bridge synthetic a(Lorg/altbeacon/beacon/Beacon;Ljava/lang/Double;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    .line 2
    .line 3
    return-void
.end method

.method public static calculateDistance(ID)Ljava/lang/Double;
    .locals 1

    .line 1
    invoke-static {}, Lorg/altbeacon/beacon/Beacon;->getDistanceCalculator()Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lorg/altbeacon/beacon/Beacon;->getDistanceCalculator()Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-interface {v0, p0, p1, p2}, Lorg/altbeacon/beacon/distance/DistanceCalculator;->calculateDistance(ID)D

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    new-array p0, p0, [Ljava/lang/Object;

    .line 22
    .line 23
    const-string p1, "Beacon"

    .line 24
    .line 25
    const-string p2, "Distance calculator not set.  Distance will bet set to -1"

    .line 26
    .line 27
    invoke-static {p1, p2, p0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    const-wide/high16 p0, -0x4010000000000000L    # -1.0

    .line 31
    .line 32
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public static getDistanceCalculator()Lorg/altbeacon/beacon/distance/DistanceCalculator;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/Beacon;->sDistanceCalculator:Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 2
    .line 3
    return-object v0
.end method

.method public static getHardwareEqualityEnforced()Z
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    sget-boolean v0, Lorg/altbeacon/beacon/Beacon;->sHardwareEqualityEnforced:Z

    .line 2
    .line 3
    return v0
.end method

.method public static setDistanceCalculator(Lorg/altbeacon/beacon/distance/DistanceCalculator;)V
    .locals 0

    .line 1
    sput-object p0, Lorg/altbeacon/beacon/Beacon;->sDistanceCalculator:Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 2
    .line 3
    return-void
.end method

.method public static setDistanceCalculatorInternal(Lorg/altbeacon/beacon/distance/DistanceCalculator;)V
    .locals 0

    .line 1
    sput-object p0, Lorg/altbeacon/beacon/Beacon;->sDistanceCalculator:Lorg/altbeacon/beacon/distance/DistanceCalculator;

    .line 2
    .line 3
    return-void
.end method

.method public static setHardwareEqualityEnforced(Z)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    sput-boolean p0, Lorg/altbeacon/beacon/Beacon;->sHardwareEqualityEnforced:Z

    .line 2
    .line 3
    return-void
.end method

.method private toStringBuilder()Ljava/lang/StringBuilder;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x1

    .line 13
    move v3, v2

    .line 14
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    if-eqz v4, :cond_2

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    check-cast v4, Lorg/altbeacon/beacon/Identifier;

    .line 25
    .line 26
    if-le v3, v2, :cond_0

    .line 27
    .line 28
    const-string v5, " "

    .line 29
    .line 30
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    :cond_0
    const-string v5, "id"

    .line 34
    .line 35
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v5, ": "

    .line 42
    .line 43
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    if-nez v4, :cond_1

    .line 47
    .line 48
    const-string v4, "null"

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    invoke-virtual {v4}, Lorg/altbeacon/beacon/Identifier;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    :goto_1
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    add-int/lit8 v3, v3, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    iget-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mParserIdentifier:Ljava/lang/String;

    .line 62
    .line 63
    if-eqz v1, :cond_3

    .line 64
    .line 65
    new-instance v1, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    const-string v2, " type "

    .line 68
    .line 69
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mParserIdentifier:Ljava/lang/String;

    .line 73
    .line 74
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    :cond_3
    return-object v0
.end method


# virtual methods
.method public describeContents()I
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lorg/altbeacon/beacon/Beacon;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Lorg/altbeacon/beacon/Beacon;

    .line 8
    .line 9
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 10
    .line 11
    iget-object v2, p1, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {v0, v2}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    return v1

    .line 20
    :cond_1
    sget-boolean v0, Lorg/altbeacon/beacon/Beacon;->sHardwareEqualityEnforced:Z

    .line 21
    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Beacon;->getBluetoothAddress()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getBluetoothAddress()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

    .line 37
    :cond_2
    const/4 p0, 0x1

    .line 38
    return p0
.end method

.method public getBeaconTypeCode()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/Beacon;->mBeaconTypeCode:I

    .line 2
    .line 3
    return p0
.end method

.method public getBluetoothAddress()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothAddress:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getBluetoothName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDataFields()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lorg/altbeacon/beacon/Beacon;->UNMODIFIABLE_LIST_OF_LONG:Ljava/util/List;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 19
    .line 20
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public getDistance()D
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mDistance:Ljava/lang/Double;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget v0, p0, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    .line 6
    .line 7
    int-to-double v0, v0

    .line 8
    iget-object v2, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    .line 9
    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v2, 0x0

    .line 18
    new-array v2, v2, [Ljava/lang/Object;

    .line 19
    .line 20
    const-string v3, "Beacon"

    .line 21
    .line 22
    const-string v4, "Not using running average RSSI because it is null"

    .line 23
    .line 24
    invoke-static {v3, v4, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget v2, p0, Lorg/altbeacon/beacon/Beacon;->mTxPower:I

    .line 28
    .line 29
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/Beacon;->calculateDistance(ID)Ljava/lang/Double;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mDistance:Ljava/lang/Double;

    .line 34
    .line 35
    :cond_1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mDistance:Ljava/lang/Double;

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    .line 38
    .line 39
    .line 40
    move-result-wide v0

    .line 41
    return-wide v0
.end method

.method public getExtraDataFields()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lorg/altbeacon/beacon/Beacon;->UNMODIFIABLE_LIST_OF_LONG:Ljava/util/List;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    .line 19
    .line 20
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public getFirstCycleDetectionTimestamp()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getId1()Lorg/altbeacon/beacon/Identifier;
    .locals 1

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lorg/altbeacon/beacon/Identifier;

    .line 9
    .line 10
    return-object p0
.end method

.method public getId2()Lorg/altbeacon/beacon/Identifier;
    .locals 1

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lorg/altbeacon/beacon/Identifier;

    .line 9
    .line 10
    return-object p0
.end method

.method public getId3()Lorg/altbeacon/beacon/Identifier;
    .locals 1

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lorg/altbeacon/beacon/Identifier;

    .line 9
    .line 10
    return-object p0
.end method

.method public getIdentifier(I)Lorg/altbeacon/beacon/Identifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lorg/altbeacon/beacon/Identifier;

    .line 8
    .line 9
    return-object p0
.end method

.method public getIdentifiers()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Identifier;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lorg/altbeacon/beacon/Beacon;->UNMODIFIABLE_LIST_OF_IDENTIFIER:Ljava/util/List;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 19
    .line 20
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public getLastCycleDetectionTimestamp()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getLastPacketRawBytes()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getManufacturer()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/Beacon;->mManufacturer:I

    .line 2
    .line 3
    return p0
.end method

.method public getMeasurementCount()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    .line 2
    .line 3
    return p0
.end method

.method public getPacketCount()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    .line 2
    .line 3
    return p0
.end method

.method public getParserIdentifier()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mParserIdentifier:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRssi()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    .line 2
    .line 3
    return p0
.end method

.method public getRunningAverageRssi()D
    .locals 2

    .line 2
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    if-eqz v0, :cond_0

    .line 3
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v0

    return-wide v0

    .line 4
    :cond_0
    iget p0, p0, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    int-to-double v0, p0

    return-wide v0
.end method

.method public getRunningAverageRssi(D)D
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    iput-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    return-wide p1
.end method

.method public getServiceUuid()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    .line 2
    .line 3
    return p0
.end method

.method public getServiceUuid128Bit()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getTxPower()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/Beacon;->mTxPower:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/Beacon;->toStringBuilder()Ljava/lang/StringBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-boolean v1, Lorg/altbeacon/beacon/Beacon;->sHardwareEqualityEnforced:Z

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothAddress:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0
.end method

.method public isExtraBeaconData()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public isMultiFrameBeacon()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    .line 2
    .line 3
    return p0
.end method

.method public requestData(Lorg/altbeacon/beacon/BeaconDataNotifier;)V
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/Beacon;->beaconDataFactory:Lorg/altbeacon/beacon/client/BeaconDataFactory;

    .line 2
    .line 3
    invoke-interface {v0, p0, p1}, Lorg/altbeacon/beacon/client/BeaconDataFactory;->requestBeaconData(Lorg/altbeacon/beacon/Beacon;Lorg/altbeacon/beacon/BeaconDataNotifier;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setExtraDataFields(Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    .line 2
    .line 3
    return-void
.end method

.method public setFirstCycleDetectionTimestamp(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 2
    .line 3
    return-void
.end method

.method public setLastCycleDetectionTimestamp(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 2
    .line 3
    return-void
.end method

.method public setLastPacketRawBytes([B)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    .line 2
    .line 3
    return-void
.end method

.method public setPacketCount(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    .line 2
    .line 3
    return-void
.end method

.method public setRssi(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    .line 2
    .line 3
    return-void
.end method

.method public setRssiMeasurementCount(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    .line 2
    .line 3
    return-void
.end method

.method public setRunningAverageRssi(D)V
    .locals 0

    .line 1
    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    iput-object p1, p0, Lorg/altbeacon/beacon/Beacon;->mDistance:Ljava/lang/Double;

    .line 9
    .line 10
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/Beacon;->toStringBuilder()Ljava/lang/StringBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 8
    .line 9
    .line 10
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mIdentifiers:Ljava/util/List;

    .line 11
    .line 12
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Lorg/altbeacon/beacon/Identifier;

    .line 27
    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    invoke-virtual {v0}, Lorg/altbeacon/beacon/Identifier;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :goto_1
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Beacon;->getDistance()D

    .line 41
    .line 42
    .line 43
    move-result-wide v0

    .line 44
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeDouble(D)V

    .line 45
    .line 46
    .line 47
    iget p2, p0, Lorg/altbeacon/beacon/Beacon;->mRssi:I

    .line 48
    .line 49
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 50
    .line 51
    .line 52
    iget p2, p0, Lorg/altbeacon/beacon/Beacon;->mTxPower:I

    .line 53
    .line 54
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 55
    .line 56
    .line 57
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothAddress:Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    iget p2, p0, Lorg/altbeacon/beacon/Beacon;->mBeaconTypeCode:I

    .line 63
    .line 64
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 65
    .line 66
    .line 67
    iget p2, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid:I

    .line 68
    .line 69
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 70
    .line 71
    .line 72
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    .line 73
    .line 74
    array-length p2, p2

    .line 75
    const/4 v0, 0x0

    .line 76
    if-eqz p2, :cond_2

    .line 77
    .line 78
    const/4 p2, 0x1

    .line 79
    goto :goto_2

    .line 80
    :cond_2
    move p2, v0

    .line 81
    :goto_2
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeBoolean(Z)V

    .line 82
    .line 83
    .line 84
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    .line 85
    .line 86
    array-length p2, p2

    .line 87
    if-eqz p2, :cond_3

    .line 88
    .line 89
    move p2, v0

    .line 90
    :goto_3
    const/16 v1, 0x10

    .line 91
    .line 92
    if-ge p2, v1, :cond_3

    .line 93
    .line 94
    iget-object v1, p0, Lorg/altbeacon/beacon/Beacon;->mServiceUuid128Bit:[B

    .line 95
    .line 96
    aget-byte v1, v1, p2

    .line 97
    .line 98
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeByte(B)V

    .line 99
    .line 100
    .line 101
    add-int/lit8 p2, p2, 0x1

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_3
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 105
    .line 106
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 107
    .line 108
    .line 109
    move-result p2

    .line 110
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 111
    .line 112
    .line 113
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mDataFields:Ljava/util/List;

    .line 114
    .line 115
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 116
    .line 117
    .line 118
    move-result-object p2

    .line 119
    :goto_4
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    if-eqz v1, :cond_4

    .line 124
    .line 125
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    check-cast v1, Ljava/lang/Long;

    .line 130
    .line 131
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 132
    .line 133
    .line 134
    move-result-wide v1

    .line 135
    invoke-virtual {p1, v1, v2}, Landroid/os/Parcel;->writeLong(J)V

    .line 136
    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_4
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    .line 140
    .line 141
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 142
    .line 143
    .line 144
    move-result p2

    .line 145
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 146
    .line 147
    .line 148
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mExtraDataFields:Ljava/util/List;

    .line 149
    .line 150
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 151
    .line 152
    .line 153
    move-result-object p2

    .line 154
    :goto_5
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    if-eqz v1, :cond_5

    .line 159
    .line 160
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    check-cast v1, Ljava/lang/Long;

    .line 165
    .line 166
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 167
    .line 168
    .line 169
    move-result-wide v1

    .line 170
    invoke-virtual {p1, v1, v2}, Landroid/os/Parcel;->writeLong(J)V

    .line 171
    .line 172
    .line 173
    goto :goto_5

    .line 174
    :cond_5
    iget p2, p0, Lorg/altbeacon/beacon/Beacon;->mManufacturer:I

    .line 175
    .line 176
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 177
    .line 178
    .line 179
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mBluetoothName:Ljava/lang/String;

    .line 180
    .line 181
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mParserIdentifier:Ljava/lang/String;

    .line 185
    .line 186
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    iget-boolean p2, p0, Lorg/altbeacon/beacon/Beacon;->mMultiFrameBeacon:Z

    .line 190
    .line 191
    int-to-byte p2, p2

    .line 192
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeByte(B)V

    .line 193
    .line 194
    .line 195
    iget-object p2, p0, Lorg/altbeacon/beacon/Beacon;->mRunningAverageRssi:Ljava/lang/Double;

    .line 196
    .line 197
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeValue(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    iget p2, p0, Lorg/altbeacon/beacon/Beacon;->mRssiMeasurementCount:I

    .line 201
    .line 202
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 203
    .line 204
    .line 205
    iget p2, p0, Lorg/altbeacon/beacon/Beacon;->mPacketCount:I

    .line 206
    .line 207
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 208
    .line 209
    .line 210
    iget-wide v1, p0, Lorg/altbeacon/beacon/Beacon;->mFirstCycleDetectionTimestamp:J

    .line 211
    .line 212
    invoke-virtual {p1, v1, v2}, Landroid/os/Parcel;->writeLong(J)V

    .line 213
    .line 214
    .line 215
    iget-wide v1, p0, Lorg/altbeacon/beacon/Beacon;->mLastCycleDetectionTimestamp:J

    .line 216
    .line 217
    invoke-virtual {p1, v1, v2}, Landroid/os/Parcel;->writeLong(J)V

    .line 218
    .line 219
    .line 220
    iget-object p0, p0, Lorg/altbeacon/beacon/Beacon;->mLastPacketRawBytes:[B

    .line 221
    .line 222
    array-length p2, p0

    .line 223
    const/16 v1, 0x3e

    .line 224
    .line 225
    if-le p2, v1, :cond_6

    .line 226
    .line 227
    move p2, v1

    .line 228
    :cond_6
    invoke-virtual {p1, p0, v0, p2}, Landroid/os/Parcel;->writeByteArray([BII)V

    .line 229
    .line 230
    .line 231
    :goto_6
    if-ge p2, v1, :cond_7

    .line 232
    .line 233
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeByte(B)V

    .line 234
    .line 235
    .line 236
    add-int/lit8 p2, p2, 0x1

    .line 237
    .line 238
    goto :goto_6

    .line 239
    :cond_7
    return-void
.end method

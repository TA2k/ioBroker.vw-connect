.class public Lorg/altbeacon/beacon/service/StartRMData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;
.implements Landroid/os/Parcelable;


# static fields
.field private static final BACKGROUND_FLAG_KEY:Ljava/lang/String; = "backgroundFlag"

.field private static final BETWEEN_SCAN_PERIOD_KEY:Ljava/lang/String; = "betweenScanPeriod"

.field private static final CALLBACK_PACKAGE_NAME_KEY:Ljava/lang/String; = "callbackPackageName"

.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lorg/altbeacon/beacon/service/StartRMData;",
            ">;"
        }
    .end annotation
.end field

.field private static final REGION_KEY:Ljava/lang/String; = "region"

.field private static final SCAN_PERIOD_KEY:Ljava/lang/String; = "scanPeriod"


# instance fields
.field private mBackgroundFlag:Z

.field private mBetweenScanPeriod:J

.field private mCallbackPackageName:Ljava/lang/String;

.field private mRegion:Lorg/altbeacon/beacon/Region;

.field private mScanPeriod:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/service/StartRMData$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/altbeacon/beacon/service/StartRMData$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/service/StartRMData;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(JJZ)V
    .locals 0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-wide p1, p0, Lorg/altbeacon/beacon/service/StartRMData;->mScanPeriod:J

    .line 8
    iput-wide p3, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBetweenScanPeriod:J

    .line 9
    iput-boolean p5, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBackgroundFlag:Z

    return-void
.end method

.method private constructor <init>(Landroid/os/Parcel;)V
    .locals 2

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    const-class v0, Lorg/altbeacon/beacon/service/StartRMData;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Lorg/altbeacon/beacon/Region;

    iput-object v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 18
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mCallbackPackageName:Ljava/lang/String;

    .line 19
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mScanPeriod:J

    .line 20
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBetweenScanPeriod:J

    .line 21
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBackgroundFlag:Z

    return-void
.end method

.method public synthetic constructor <init>(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/service/StartRMData;-><init>(Landroid/os/Parcel;)V

    return-void
.end method

.method public constructor <init>(Lorg/altbeacon/beacon/Region;Ljava/lang/String;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lorg/altbeacon/beacon/service/StartRMData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 5
    iput-object p2, p0, Lorg/altbeacon/beacon/service/StartRMData;->mCallbackPackageName:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Lorg/altbeacon/beacon/Region;Ljava/lang/String;JJZ)V
    .locals 0

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-wide p3, p0, Lorg/altbeacon/beacon/service/StartRMData;->mScanPeriod:J

    .line 12
    iput-wide p5, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBetweenScanPeriod:J

    .line 13
    iput-object p1, p0, Lorg/altbeacon/beacon/service/StartRMData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 14
    iput-object p2, p0, Lorg/altbeacon/beacon/service/StartRMData;->mCallbackPackageName:Ljava/lang/String;

    .line 15
    iput-boolean p7, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBackgroundFlag:Z

    return-void
.end method

.method public static fromBundle(Landroid/os/Bundle;)Lorg/altbeacon/beacon/service/StartRMData;
    .locals 5

    .line 1
    const-class v0, Lorg/altbeacon/beacon/Region;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Lorg/altbeacon/beacon/service/StartRMData;

    .line 11
    .line 12
    invoke-direct {v0}, Lorg/altbeacon/beacon/service/StartRMData;-><init>()V

    .line 13
    .line 14
    .line 15
    const-string v1, "region"

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/4 v3, 0x1

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0, v1}, Landroid/os/Bundle;->getSerializable(Ljava/lang/String;)Ljava/io/Serializable;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lorg/altbeacon/beacon/Region;

    .line 29
    .line 30
    iput-object v1, v0, Lorg/altbeacon/beacon/service/StartRMData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 31
    .line 32
    move v1, v3

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v1, 0x0

    .line 35
    :goto_0
    const-string v2, "scanPeriod"

    .line 36
    .line 37
    invoke-virtual {p0, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_1

    .line 42
    .line 43
    invoke-virtual {p0, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Ljava/lang/Long;

    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    iput-wide v1, v0, Lorg/altbeacon/beacon/service/StartRMData;->mScanPeriod:J

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    move v3, v1

    .line 57
    :goto_1
    const-string v1, "betweenScanPeriod"

    .line 58
    .line 59
    invoke-virtual {p0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_2

    .line 64
    .line 65
    invoke-virtual {p0, v1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    check-cast v1, Ljava/lang/Long;

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 72
    .line 73
    .line 74
    move-result-wide v1

    .line 75
    iput-wide v1, v0, Lorg/altbeacon/beacon/service/StartRMData;->mBetweenScanPeriod:J

    .line 76
    .line 77
    :cond_2
    const-string v1, "backgroundFlag"

    .line 78
    .line 79
    invoke-virtual {p0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    if-eqz v2, :cond_3

    .line 84
    .line 85
    invoke-virtual {p0, v1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    check-cast v1, Ljava/lang/Boolean;

    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    iput-boolean v1, v0, Lorg/altbeacon/beacon/service/StartRMData;->mBackgroundFlag:Z

    .line 96
    .line 97
    :cond_3
    const-string v1, "callbackPackageName"

    .line 98
    .line 99
    invoke-virtual {p0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    if-eqz v2, :cond_4

    .line 104
    .line 105
    invoke-virtual {p0, v1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    check-cast p0, Ljava/lang/String;

    .line 110
    .line 111
    iput-object p0, v0, Lorg/altbeacon/beacon/service/StartRMData;->mCallbackPackageName:Ljava/lang/String;

    .line 112
    .line 113
    :cond_4
    if-eqz v3, :cond_5

    .line 114
    .line 115
    return-object v0

    .line 116
    :cond_5
    const/4 p0, 0x0

    .line 117
    return-object p0
.end method


# virtual methods
.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public getBackgroundFlag()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBackgroundFlag:Z

    .line 2
    .line 3
    return p0
.end method

.method public getBetweenScanPeriod()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBetweenScanPeriod:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getCallbackPackageName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mCallbackPackageName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRegionData()Lorg/altbeacon/beacon/Region;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 2
    .line 3
    return-object p0
.end method

.method public getScanPeriod()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mScanPeriod:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public toBundle()Landroid/os/Bundle;
    .locals 4

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "scanPeriod"

    .line 7
    .line 8
    iget-wide v2, p0, Lorg/altbeacon/beacon/service/StartRMData;->mScanPeriod:J

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2, v3}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 11
    .line 12
    .line 13
    const-string v1, "betweenScanPeriod"

    .line 14
    .line 15
    iget-wide v2, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBetweenScanPeriod:J

    .line 16
    .line 17
    invoke-virtual {v0, v1, v2, v3}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 18
    .line 19
    .line 20
    const-string v1, "backgroundFlag"

    .line 21
    .line 22
    iget-boolean v2, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBackgroundFlag:Z

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v1, "callbackPackageName"

    .line 28
    .line 29
    iget-object v2, p0, Lorg/altbeacon/beacon/service/StartRMData;->mCallbackPackageName:Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v0, v1, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 35
    .line 36
    if-eqz p0, :cond_0

    .line 37
    .line 38
    const-string v1, "region"

    .line 39
    .line 40
    invoke-virtual {v0, v1, p0}, Landroid/os/Bundle;->putSerializable(Ljava/lang/String;Ljava/io/Serializable;)V

    .line 41
    .line 42
    .line 43
    :cond_0
    return-object v0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 2
    .line 3
    invoke-virtual {p1, v0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Lorg/altbeacon/beacon/service/StartRMData;->mCallbackPackageName:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mScanPeriod:J

    .line 12
    .line 13
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 14
    .line 15
    .line 16
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBetweenScanPeriod:J

    .line 17
    .line 18
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 19
    .line 20
    .line 21
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/StartRMData;->mBackgroundFlag:Z

    .line 22
    .line 23
    int-to-byte p0, p0

    .line 24
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeByte(B)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

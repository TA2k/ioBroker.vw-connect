.class public Lorg/altbeacon/beacon/distance/AndroidModel;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "AndroidModel"


# instance fields
.field mBuildNumber:Ljava/lang/String;

.field mManufacturer:Ljava/lang/String;

.field mModel:Ljava/lang/String;

.field mVersion:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mVersion:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mBuildNumber:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mModel:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mManufacturer:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method

.method public static forThisDevice()Lorg/altbeacon/beacon/distance/AndroidModel;
    .locals 5

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/distance/AndroidModel;

    .line 2
    .line 3
    sget-object v1, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 4
    .line 5
    sget-object v2, Landroid/os/Build;->ID:Ljava/lang/String;

    .line 6
    .line 7
    sget-object v3, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 8
    .line 9
    sget-object v4, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, v4}, Lorg/altbeacon/beacon/distance/AndroidModel;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method


# virtual methods
.method public getBuildNumber()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mBuildNumber:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getManufacturer()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mManufacturer:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getModel()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mModel:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVersion()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public matchScore(Lorg/altbeacon/beacon/distance/AndroidModel;)I
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mManufacturer:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p1, Lorg/altbeacon/beacon/distance/AndroidModel;->mManufacturer:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x2

    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    iget-object v1, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mModel:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lorg/altbeacon/beacon/distance/AndroidModel;->mModel:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    move v0, v2

    .line 24
    :cond_0
    const/4 v1, 0x3

    .line 25
    if-ne v0, v2, :cond_1

    .line 26
    .line 27
    iget-object v2, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mBuildNumber:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v3, p1, Lorg/altbeacon/beacon/distance/AndroidModel;->mBuildNumber:Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    move v0, v1

    .line 38
    :cond_1
    if-ne v0, v1, :cond_2

    .line 39
    .line 40
    iget-object v1, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mVersion:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v2, p1, Lorg/altbeacon/beacon/distance/AndroidModel;->mVersion:Ljava/lang/String;

    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_2

    .line 49
    .line 50
    const/4 v0, 0x4

    .line 51
    :cond_2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {p0}, Lorg/altbeacon/beacon/distance/AndroidModel;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    filled-new-array {v1, p0, p1}, [Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    const-string p1, "AndroidModel"

    .line 64
    .line 65
    const-string v1, "Score is %s for %s compared to %s"

    .line 66
    .line 67
    invoke-static {p1, v1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    return v0
.end method

.method public setBuildNumber(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mBuildNumber:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setManufacturer(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mManufacturer:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setModel(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mModel:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setVersion(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mManufacturer:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ";"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v2, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mModel:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    iget-object v2, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mBuildNumber:Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lorg/altbeacon/beacon/distance/AndroidModel;->mVersion:Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

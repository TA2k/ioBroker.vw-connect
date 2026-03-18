.class public Lorg/altbeacon/beacon/service/MonitoringData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final INSIDE_KEY:Ljava/lang/String; = "inside"

.field private static final REGION_KEY:Ljava/lang/String; = "region"

.field private static final TAG:Ljava/lang/String; = "MonitoringData"


# instance fields
.field private final mInside:Z

.field private final mRegion:Lorg/altbeacon/beacon/Region;


# direct methods
.method public constructor <init>(ZLorg/altbeacon/beacon/Region;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/MonitoringData;->mInside:Z

    .line 5
    .line 6
    iput-object p2, p0, Lorg/altbeacon/beacon/service/MonitoringData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 7
    .line 8
    return-void
.end method

.method public static fromBundle(Landroid/os/Bundle;)Lorg/altbeacon/beacon/service/MonitoringData;
    .locals 2

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
    const-string v0, "region"

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Landroid/os/Bundle;->getSerializable(Ljava/lang/String;)Ljava/io/Serializable;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lorg/altbeacon/beacon/Region;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x0

    .line 26
    :goto_0
    const-string v1, "inside"

    .line 27
    .line 28
    invoke-virtual {p0, v1}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    new-instance v1, Lorg/altbeacon/beacon/service/MonitoringData;

    .line 33
    .line 34
    invoke-direct {v1, p0, v0}, Lorg/altbeacon/beacon/service/MonitoringData;-><init>(ZLorg/altbeacon/beacon/Region;)V

    .line 35
    .line 36
    .line 37
    return-object v1
.end method


# virtual methods
.method public getRegion()Lorg/altbeacon/beacon/Region;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/MonitoringData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 2
    .line 3
    return-object p0
.end method

.method public isInside()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/MonitoringData;->mInside:Z

    .line 2
    .line 3
    return p0
.end method

.method public toBundle()Landroid/os/Bundle;
    .locals 3

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "region"

    .line 7
    .line 8
    iget-object v2, p0, Lorg/altbeacon/beacon/service/MonitoringData;->mRegion:Lorg/altbeacon/beacon/Region;

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Landroid/os/Bundle;->putSerializable(Ljava/lang/String;Ljava/io/Serializable;)V

    .line 11
    .line 12
    .line 13
    const-string v1, "inside"

    .line 14
    .line 15
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/MonitoringData;->mInside:Z

    .line 16
    .line 17
    invoke-virtual {v0, v1, p0}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

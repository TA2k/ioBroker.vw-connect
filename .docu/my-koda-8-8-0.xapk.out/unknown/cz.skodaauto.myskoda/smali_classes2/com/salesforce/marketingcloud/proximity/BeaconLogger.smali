.class public final Lcom/salesforce/marketingcloud/proximity/BeaconLogger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/logging/Logger;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation


# static fields
.field private static final TAG:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "BeaconLogger"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public varargs d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p2, p3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs d(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p1, p3, p4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p2, p3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs e(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p1, p3, p4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p2, p3}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs i(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p1, p3, p4}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs v(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p2, p3}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs v(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p1, p3, p4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p2, p3}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs w(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/BeaconLogger;->TAG:Ljava/lang/String;

    invoke-static {p0, p1, p3, p4}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

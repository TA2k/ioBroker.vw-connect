.class public abstract Lcom/salesforce/marketingcloud/proximity/e;
.super Lcom/salesforce/marketingcloud/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/proximity/e$a;
    }
.end annotation


# static fields
.field public static final d:Ljava/lang/String; = "com.salesforce.marketingcloud.proximity.BEACON_REGION_ENTERED"

.field public static final e:Ljava/lang/String; = "com.salesforce.marketingcloud.proximity.BEACON_REGION_EXITED"

.field public static final f:Ljava/lang/String; = "beaconRegion"

.field private static final g:Ljava/lang/String; = "ProximityManager"

.field protected static final h:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "ProximityManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/f;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static a(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Lcom/salesforce/marketingcloud/proximity/e;
    .locals 6

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/proximity/e;->a(Landroid/content/Context;)Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz v0, :cond_1

    .line 2
    invoke-static {}, Lcom/salesforce/marketingcloud/util/b;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 3
    :try_start_0
    new-instance v0, Lcom/salesforce/marketingcloud/proximity/b;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions()Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    move-result-object v3

    invoke-direct {v0, p0, v3}, Lcom/salesforce/marketingcloud/proximity/b;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    .line 4
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    .line 5
    sget-object v3, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const-string v4, "ProximityManager"

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    const-string v5, "Unable to create real instance of %s"

    invoke-static {v3, p0, v5, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 6
    :cond_0
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 7
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const/4 v3, 0x0

    new-array v3, v3, [Ljava/lang/Object;

    const-string v4, "If you wish to use proximity messenger then you need to add the AltBeacon dependency."

    invoke-static {v0, v4, v3}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    move-object v0, v2

    move-object v2, p0

    goto :goto_0

    :cond_1
    move-object v0, v2

    .line 8
    :goto_0
    new-instance p0, Lcom/salesforce/marketingcloud/proximity/d;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled()Z

    move-result v3

    .line 9
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled()Z

    move-result p1

    invoke-static {p1, v1, v2, v0}, Lcom/salesforce/marketingcloud/proximity/e;->a(ZLjava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object p1

    invoke-direct {p0, v3, p1}, Lcom/salesforce/marketingcloud/proximity/d;-><init>(ZLorg/json/JSONObject;)V

    return-object p0
.end method

.method public static a()Lorg/json/JSONObject;
    .locals 2

    .line 17
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    const/4 v1, 0x1

    .line 18
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/proximity/e;->a(Lorg/json/JSONObject;Z)Lorg/json/JSONObject;

    return-object v0
.end method

.method private static a(Lorg/json/JSONObject;Z)Lorg/json/JSONObject;
    .locals 1

    .line 19
    const-string v0, "proximityEnabled"

    invoke-virtual {p0, v0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    return-object p0
.end method

.method public static a(ZLjava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/String;)Lorg/json/JSONObject;
    .locals 1

    .line 11
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 12
    :try_start_0
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/proximity/e;->a(Lorg/json/JSONObject;Z)Lorg/json/JSONObject;

    move-result-object v0

    .line 13
    const-string p0, "hardwareAvailable"

    invoke-virtual {v0, p0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 14
    const-string p0, "libraryDeclared"

    invoke-virtual {v0, p0, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    if-eqz p3, :cond_0

    .line 15
    const-string p0, "serviceMissing"

    invoke-virtual {v0, p0, p3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    goto :goto_0

    :cond_0
    return-object v0

    .line 16
    :goto_0
    sget-object p1, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "Error creating fake ProximityManager state."

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v0
.end method

.method public static a(Landroid/content/Context;)Z
    .locals 1

    .line 10
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object p0

    const-string v0, "android.hardware.bluetooth_le"

    invoke-virtual {p0, v0}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    move-result p0

    return p0
.end method


# virtual methods
.method public abstract a(Lcom/salesforce/marketingcloud/proximity/e$a;)V
.end method

.method public abstract a(Ljava/util/List;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;)V"
        }
    .end annotation
.end method

.method public abstract b(Lcom/salesforce/marketingcloud/proximity/e$a;)V
.end method

.method public abstract b(Ljava/util/List;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;)V"
        }
    .end annotation
.end method

.method public b()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    return p0
.end method

.method public abstract c()V
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "ProximityManager"

    .line 2
    .line 3
    return-object p0
.end method

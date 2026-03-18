.class public abstract Lcom/salesforce/marketingcloud/location/f;
.super Lcom/salesforce/marketingcloud/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field public static final d:Ljava/lang/String; = "NO_GPS_HARDWARE"

.field public static final e:Ljava/lang/String; = "RECEIVER_NOT_DECLARED_IN_MANIFEST"

.field public static final f:I = -0x1

.field protected static final g:Ljava/lang/String; = "com.salesforce.marketingcloud.location.LOCATION_UPDATE"

.field protected static final h:Ljava/lang/String; = "com.salesforce.marketingcloud.location.GEOFENCE_ERROR"

.field protected static final i:Ljava/lang/String; = "com.salesforce.marketingcloud.location.GEOFENCE_EVENT"

.field protected static final j:Ljava/lang/String; = "extra_location"

.field protected static final k:Ljava/lang/String; = "extra_transition"

.field protected static final l:Ljava/lang/String; = "extra_fence_ids"

.field protected static final m:Ljava/lang/String; = "extra_error_code"

.field protected static final n:Ljava/lang/String; = "extra_error_message"

.field private static final o:Ljava/lang/String; = "LocationManager"

.field static final p:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "LocationManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

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

.method public static a(ILjava/lang/String;)Landroid/content/Intent;
    .locals 2

    .line 9
    new-instance v0, Landroid/content/Intent;

    const-string v1, "com.salesforce.marketingcloud.location.GEOFENCE_ERROR"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    const-string v1, "extra_error_code"

    invoke-virtual {v0, v1, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    move-result-object p0

    .line 10
    const-string v0, "extra_error_message"

    invoke-virtual {p0, v0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p0

    return-object p0
.end method

.method public static a(ILjava/util/List;Landroid/location/Location;)Landroid/content/Intent;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Landroid/location/Location;",
            ")",
            "Landroid/content/Intent;"
        }
    .end annotation

    .line 3
    new-instance v0, Landroid/content/Intent;

    const-string v1, "com.salesforce.marketingcloud.location.GEOFENCE_EVENT"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 4
    const-string v1, "extra_transition"

    invoke-virtual {v0, v1, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 5
    instance-of p0, p1, Ljava/util/ArrayList;

    const-string v1, "extra_fence_ids"

    if-eqz p0, :cond_0

    .line 6
    check-cast p1, Ljava/util/ArrayList;

    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putStringArrayListExtra(Ljava/lang/String;Ljava/util/ArrayList;)Landroid/content/Intent;

    goto :goto_0

    .line 7
    :cond_0
    new-instance p0, Ljava/util/ArrayList;

    invoke-direct {p0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v0, v1, p0}, Landroid/content/Intent;->putStringArrayListExtra(Ljava/lang/String;Ljava/util/ArrayList;)Landroid/content/Intent;

    :goto_0
    if-eqz p2, :cond_1

    .line 8
    const-string p0, "extra_location"

    invoke-virtual {v0, p0, p2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    :cond_1
    return-object v0
.end method

.method public static a(Landroid/location/Location;)Landroid/content/Intent;
    .locals 2

    .line 2
    new-instance v0, Landroid/content/Intent;

    const-string v1, "com.salesforce.marketingcloud.location.LOCATION_UPDATE"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    const-string v1, "extra_location"

    invoke-virtual {v0, v1, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    move-result-object p0

    return-object p0
.end method

.method public static a(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Lcom/salesforce/marketingcloud/location/f;
    .locals 5

    .line 11
    invoke-static {}, Lcom/salesforce/marketingcloud/util/b;->b()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    .line 12
    invoke-static {p0}, Lcom/salesforce/marketingcloud/location/LocationReceiver;->a(Landroid/content/Context;)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    if-eqz v2, :cond_0

    .line 13
    :try_start_0
    new-instance v1, Lcom/salesforce/marketingcloud/location/h;

    invoke-direct {v1, p0, p1}, Lcom/salesforce/marketingcloud/location/h;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v1

    :catch_0
    move-exception p0

    move-object v1, p0

    .line 14
    sget-object p0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const-string v2, "LocationManager"

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    const-string v4, "Unable to create real instance of %s"

    invoke-static {p0, v1, v4, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    move-object p0, v1

    move-object v1, v3

    goto :goto_0

    .line 15
    :cond_1
    sget-object p0, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "GooglePlayServices Location dependency missing from build."

    invoke-static {p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    move-object p0, v1

    .line 16
    :goto_0
    new-instance v2, Lcom/salesforce/marketingcloud/location/a;

    invoke-direct {v2, p1, v1, v0, p0}, Lcom/salesforce/marketingcloud/location/a;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/Boolean;ZLjava/lang/Exception;)V

    return-object v2
.end method

.method private static a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Lorg/json/JSONObject;
    .locals 4

    .line 26
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 27
    :try_start_0
    const-string v1, "geofencingEnabled"

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled()Z

    move-result v2

    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 28
    const-string v1, "proximityEnabled"

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled()Z

    move-result p0

    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    .line 29
    sget-object v1, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    const-string v3, "Error creating LocationManager state."

    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v0
.end method

.method public static a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;ILjava/lang/String;)Lorg/json/JSONObject;
    .locals 2

    .line 22
    invoke-static {p0}, Lcom/salesforce/marketingcloud/location/f;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Lorg/json/JSONObject;

    move-result-object p0

    .line 23
    :try_start_0
    const-string v0, "apiCode"

    invoke-virtual {p0, v0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 24
    const-string p1, "apiMessage"

    invoke-virtual {p0, p1, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p1

    .line 25
    sget-object p2, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Error creating LocationManager state."

    invoke-static {p2, p1, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/Boolean;ZLjava/lang/Exception;)Lorg/json/JSONObject;
    .locals 1

    .line 17
    invoke-static {p0}, Lcom/salesforce/marketingcloud/location/f;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Lorg/json/JSONObject;

    move-result-object p0

    .line 18
    :try_start_0
    const-string v0, "serviceAvailable"

    invoke-virtual {p0, v0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 19
    const-string p1, "gmsLocationDependencyAvailable"

    invoke-virtual {p0, p1, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    if-eqz p3, :cond_0

    .line 20
    const-string p1, "exceptionMessage"

    invoke-virtual {p3}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p1

    goto :goto_0

    :cond_0
    return-object p0

    .line 21
    :goto_0
    sget-object p2, Lcom/salesforce/marketingcloud/location/f;->p:Ljava/lang/String;

    const/4 p3, 0x0

    new-array p3, p3, [Ljava/lang/Object;

    const-string v0, "Error creating LocationManager state."

    invoke-static {p2, p1, v0, p3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object p0
.end method


# virtual methods
.method public abstract a(Lcom/salesforce/marketingcloud/location/c;)V
.end method

.method public abstract a(Lcom/salesforce/marketingcloud/location/e;)V
.end method

.method public abstract a(Ljava/util/List;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation
.end method

.method public varargs abstract a([Lcom/salesforce/marketingcloud/location/b;)V
.end method

.method public a()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    return p0
.end method

.method public abstract b()V
.end method

.method public abstract b(Lcom/salesforce/marketingcloud/location/c;)V
.end method

.method public abstract b(Lcom/salesforce/marketingcloud/location/e;)V
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "LocationManager"

    .line 2
    .line 3
    return-object p0
.end method

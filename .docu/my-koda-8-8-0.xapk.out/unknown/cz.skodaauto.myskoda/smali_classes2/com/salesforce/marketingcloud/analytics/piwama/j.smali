.class abstract Lcom/salesforce/marketingcloud/analytics/piwama/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final c:Ljava/lang/String; = "YXBpX2tleQ=="

.field static final d:Ljava/lang/String; = "app_id"

.field static final e:Ljava/lang/String; = "app_name"

.field static final f:Ljava/lang/String; = "user_info"

.field static final g:Ljava/lang/String; = "payload"

.field static final h:Ljava/lang/String; = "849f26e2-2df6-11e4-ab12-14109fdc48df"

.field private static final i:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final j:Ljava/lang/String; = "device"

.field private static final k:Ljava/lang/String; = "details"

.field private static final l:Ljava/lang/String; = "manufacturer"

.field private static final m:Ljava/lang/String; = "device_id"

.field private static final n:Ljava/lang/String; = "push_enabled"

.field private static final o:Ljava/lang/String; = "location"

.field private static final p:Ljava/lang/String; = "latitude"

.field private static final q:Ljava/lang/String; = "longitude"

.field private static final r:Ljava/lang/String; = "platform"

.field private static final s:Ljava/lang/String; = "platform_version"

.field private static final t:Ljava/lang/String; = "device_type"

.field private static final u:Ljava/lang/String; = "email"

.field private static final v:Ljava/lang/String; = "events"


# instance fields
.field final a:Lcom/salesforce/marketingcloud/storage/h;

.field final b:Lcom/salesforce/marketingcloud/MarketingCloudConfig;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/j$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/analytics/piwama/j$a;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->i:Ljava/util/Map;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->b:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a:Lcom/salesforce/marketingcloud/storage/h;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/registration/RegistrationManager;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/messages/RegionMessageManager;Ljava/util/List;)Lcom/salesforce/marketingcloud/http/c;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager;",
            "Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;",
            "Lcom/salesforce/marketingcloud/messages/RegionMessageManager;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;)",
            "Lcom/salesforce/marketingcloud/http/c;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->j:Lcom/salesforce/marketingcloud/http/b;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->b:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object v2

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/j;->b()[Ljava/lang/Object;

    move-result-object v3

    const/4 v4, 0x0

    .line 2
    invoke-interface {p4, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lcom/salesforce/marketingcloud/analytics/b;

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object v4

    .line 3
    invoke-virtual {p0, p1, p2, p3, v4}, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a(Lcom/salesforce/marketingcloud/registration/RegistrationManager;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/messages/RegionMessageManager;Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a(Lorg/json/JSONObject;)Lorg/json/JSONObject;

    move-result-object p1

    invoke-virtual {p0, p1, p4}, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a(Lorg/json/JSONObject;Ljava/util/List;)Ljava/lang/String;

    move-result-object v4

    sget-object v5, Lcom/salesforce/marketingcloud/analytics/piwama/j;->i:Ljava/util/Map;

    .line 4
    invoke-virtual/range {v0 .. v5}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;[Ljava/lang/Object;Ljava/lang/String;Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    return-object p0
.end method

.method public a(Lorg/json/JSONObject;Ljava/util/List;)Ljava/lang/String;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/json/JSONObject;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 5
    const-string p0, "events"

    const-string v0, "payload"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v0

    .line 6
    const-string v1, "{}"

    if-eqz v0, :cond_2

    .line 7
    new-instance v2, Lorg/json/JSONArray;

    invoke-direct {v2}, Lorg/json/JSONArray;-><init>()V

    .line 8
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_0
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    const/4 v4, 0x0

    if-eqz v3, :cond_1

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/analytics/b;

    .line 9
    :try_start_0
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->e()Ljava/lang/String;

    move-result-object v5

    if-eqz v5, :cond_0

    .line 10
    new-instance v5, Lorg/json/JSONObject;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->e()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v5, v3}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v5}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v3

    .line 11
    sget-object v5, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    new-array v4, v4, [Ljava/lang/Object;

    const-string v6, "Failed to add the PI AnalyticItem Event to the event list."

    invoke-static {v5, v3, v6, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 12
    :cond_1
    invoke-virtual {v2}, Lorg/json/JSONArray;->length()I

    move-result p2

    if-lez p2, :cond_2

    .line 13
    :try_start_1
    invoke-virtual {v0, p0, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 14
    invoke-virtual {p1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_1

    :catch_1
    move-exception p1

    .line 15
    sget-object p2, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    new-array v2, v4, [Ljava/lang/Object;

    const-string v3, "Failed to add the PI AnalyticItem Events to the payload."

    invoke-static {p2, p1, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    :goto_1
    invoke-virtual {v0, p0}, Lorg/json/JSONObject;->remove(Ljava/lang/String;)Ljava/lang/Object;

    :cond_2
    return-object v1
.end method

.method public a()Lorg/json/JSONObject;
    .locals 2

    .line 26
    new-instance p0, Lorg/json/JSONObject;

    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 27
    sget-object v0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    const-string v1, "manufacturer"

    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 28
    const-string v0, "platform"

    const-string v1, "Android"

    invoke-virtual {p0, v0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 29
    sget-object v0, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    const-string v1, "platform_version"

    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 30
    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;

    const-string v1, "device_type"

    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/RegionMessageManager;)Lorg/json/JSONObject;
    .locals 3

    .line 31
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/messages/RegionMessageManager;->isGeofenceMessagingEnabled()Z

    move-result v0

    if-nez v0, :cond_0

    .line 32
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/messages/RegionMessageManager;->isProximityMessagingEnabled()Z

    move-result p1

    if-eqz p1, :cond_1

    .line 33
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->m()Lcom/salesforce/marketingcloud/storage/g;

    move-result-object p1

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/storage/g;->e(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object p0

    if-eqz p0, :cond_1

    .line 34
    new-instance p1, Lorg/json/JSONObject;

    invoke-direct {p1}, Lorg/json/JSONObject;-><init>()V

    .line 35
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/LatLon;->latitude()D

    move-result-wide v0

    const-string v2, "latitude"

    invoke-virtual {p1, v2, v0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;

    .line 36
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/location/LatLon;->longitude()D

    move-result-wide v0

    const-string p0, "longitude"

    invoke-virtual {p1, p0, v0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;

    return-object p1

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;)Lorg/json/JSONObject;
    .locals 1

    .line 37
    new-instance p0, Lorg/json/JSONObject;

    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 38
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->isPushEnabled()Z

    move-result p1

    const-string v0, "push_enabled"

    invoke-virtual {p0, v0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/registration/RegistrationManager;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/messages/RegionMessageManager;Ljava/lang/String;)Lorg/json/JSONObject;
    .locals 2

    .line 17
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 18
    :try_start_0
    const-string v1, "device_id"

    invoke-interface {p1}, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->getDeviceId()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, v1, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 19
    invoke-static {p4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p1

    if-nez p1, :cond_0

    .line 20
    const-string p1, "email"

    invoke-virtual {v0, p1, p4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 21
    :cond_0
    :goto_0
    const-string p1, "details"

    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;)Lorg/json/JSONObject;

    move-result-object p2

    invoke-virtual {v0, p1, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 22
    invoke-virtual {p0, p3}, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a(Lcom/salesforce/marketingcloud/messages/RegionMessageManager;)Lorg/json/JSONObject;

    move-result-object p1

    if-eqz p1, :cond_1

    .line 23
    const-string p2, "location"

    invoke-virtual {v0, p2, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 24
    :cond_1
    const-string p1, "device"

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a()Lorg/json/JSONObject;

    move-result-object p0

    invoke-virtual {v0, p1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    .line 25
    :goto_1
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "Could not create User Info object."

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v0
.end method

.method public abstract a(Lorg/json/JSONObject;)Lorg/json/JSONObject;
.end method

.method public abstract b()[Ljava/lang/Object;
.end method

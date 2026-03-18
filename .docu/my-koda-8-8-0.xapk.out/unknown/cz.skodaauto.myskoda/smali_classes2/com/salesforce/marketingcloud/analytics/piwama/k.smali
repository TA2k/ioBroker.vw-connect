.class Lcom/salesforce/marketingcloud/analytics/piwama/k;
.super Lcom/salesforce/marketingcloud/analytics/piwama/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/piwama/j;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public a(Lorg/json/JSONObject;)Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance v1, Lorg/json/JSONObject;

    .line 7
    .line 8
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 9
    .line 10
    .line 11
    const-string v2, "app_name"

    .line 12
    .line 13
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->b:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 14
    .line 15
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-virtual {v1, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 20
    .line 21
    .line 22
    const-string v2, "app_id"

    .line 23
    .line 24
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->b:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 25
    .line 26
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-virtual {v1, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a:Lcom/salesforce/marketingcloud/storage/h;

    .line 34
    .line 35
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string v2, "et_user_id_cache"

    .line 40
    .line 41
    const/4 v3, 0x0

    .line 42
    invoke-interface {p0, v2, v3}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    if-nez v2, :cond_0

    .line 51
    .line 52
    const-string v2, "user_id"

    .line 53
    .line 54
    invoke-virtual {p1, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 55
    .line 56
    .line 57
    :cond_0
    const-string p0, "user_info"

    .line 58
    .line 59
    invoke-virtual {v1, p0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 60
    .line 61
    .line 62
    const-string p0, "payload"

    .line 63
    .line 64
    invoke-virtual {v0, p0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 65
    .line 66
    .line 67
    return-object v0

    .line 68
    :catch_0
    move-exception p0

    .line 69
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    .line 70
    .line 71
    const/4 v0, 0x0

    .line 72
    new-array v0, v0, [Ljava/lang/Object;

    .line 73
    .line 74
    const-string v1, "Failed to construct PiWama payload JSON Object."

    .line 75
    .line 76
    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    new-instance p0, Lorg/json/JSONObject;

    .line 80
    .line 81
    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 82
    .line 83
    .line 84
    return-object p0
.end method

.method public b()[Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "?session_id="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a:Lcom/salesforce/marketingcloud/storage/h;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v1, "et_session_id_cache"

    .line 15
    .line 16
    const-string v2, ""

    .line 17
    .line 18
    invoke-interface {p0, v1, v2}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

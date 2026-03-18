.class public final Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/messages/Region;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    .locals 24

    move-object/from16 v0, p1

    const-string v1, "message"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "region"

    move-object/from16 v5, p2

    invoke-static {v5, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    sget-object v3, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;->CLOUD_PAGE:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 38
    new-instance v4, Llx0/l;

    invoke-direct {v4, v3, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    .line 39
    :cond_0
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    if-eqz v1, :cond_1

    sget-object v3, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;->OPEN_DIRECT:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 40
    new-instance v4, Llx0/l;

    invoke-direct {v4, v3, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    .line 41
    :cond_1
    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;->OTHER:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 42
    new-instance v4, Llx0/l;

    invoke-direct {v4, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 43
    :goto_0
    iget-object v1, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 44
    move-object v11, v1

    check-cast v11, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 45
    iget-object v1, v4, Llx0/l;->e:Ljava/lang/Object;

    .line 46
    move-object v13, v1

    check-cast v13, Ljava/lang/String;

    .line 47
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    move-object/from16 v3, p0

    invoke-virtual {v3, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;->a(Ljava/lang/String;)Llx0/l;

    move-result-object v1

    .line 48
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 49
    move-object v7, v3

    check-cast v7, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 50
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 51
    move-object v8, v1

    check-cast v8, Ljava/lang/String;

    .line 52
    iget v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    const/4 v3, 0x5

    if-ne v1, v3, :cond_2

    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->BEACON:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    :goto_1
    move-object v12, v1

    goto :goto_2

    :cond_2
    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->GEOFENCE:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    goto :goto_1

    .line 53
    :goto_2
    iget-object v3, v0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 54
    iget-object v9, v0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 55
    iget-object v6, v0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 56
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    if-eqz v1, :cond_3

    new-instance v1, Ljava/util/HashMap;

    iget-object v4, v0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    invoke-direct {v1, v4}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    :goto_3
    move-object/from16 v16, v1

    goto :goto_4

    :cond_3
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    goto :goto_3

    .line 57
    :goto_4
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 58
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    if-eqz v0, :cond_4

    iget-object v4, v0, Lcom/salesforce/marketingcloud/messages/Message$Media;->url:Ljava/lang/String;

    move-object v14, v4

    goto :goto_5

    :cond_4
    move-object v14, v2

    :goto_5
    if-eqz v0, :cond_5

    .line 59
    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/Message$Media;->altText:Ljava/lang/String;

    :cond_5
    move-object v15, v2

    .line 60
    new-instance v2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    const v22, 0x78082

    const/16 v23, 0x0

    const/4 v4, 0x0

    const/4 v10, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    move-object/from16 v17, v1

    invoke-direct/range {v2 .. v23}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;IILkotlin/jvm/internal/g;)V

    return-object v2
.end method

.method public final a(Ljava/util/Map;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    .locals 27
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage;"
        }
    .end annotation

    move-object/from16 v0, p1

    const-string v1, "data"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    const-string v1, "_x"

    invoke-interface {v0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    sget-object v2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;->CLOUD_PAGE:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    .line 3
    new-instance v4, Llx0/l;

    invoke-direct {v4, v2, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    .line 4
    :cond_0
    const-string v1, "_od"

    invoke-interface {v0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    sget-object v2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;->OPEN_DIRECT:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    .line 5
    new-instance v4, Llx0/l;

    invoke-direct {v4, v2, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    .line 6
    :cond_1
    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;->OTHER:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 7
    new-instance v4, Llx0/l;

    invoke-direct {v4, v1, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 8
    :goto_0
    iget-object v1, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 9
    move-object v14, v1

    check-cast v14, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 10
    iget-object v1, v4, Llx0/l;->e:Ljava/lang/Object;

    .line 11
    move-object/from16 v16, v1

    check-cast v16, Ljava/lang/String;

    .line 12
    const-string v1, "sound"

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    move-object/from16 v2, p0

    invoke-virtual {v2, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;->a(Ljava/lang/String;)Llx0/l;

    move-result-object v1

    .line 13
    iget-object v2, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 14
    move-object v10, v2

    check-cast v10, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 15
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 16
    move-object v11, v1

    check-cast v11, Ljava/lang/String;

    .line 17
    const-string v1, "_m"

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_7

    move-object v6, v1

    check-cast v6, Ljava/lang/String;

    .line 18
    const-string v1, "_r"

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object v7, v1

    check-cast v7, Ljava/lang/String;

    .line 19
    const-string v1, "title"

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object v12, v1

    check-cast v12, Ljava/lang/String;

    .line 20
    const-string v1, "subtitle"

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object v13, v1

    check-cast v13, Ljava/lang/String;

    .line 21
    const-string v1, "alert"

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_6

    move-object v9, v1

    check-cast v9, Ljava/lang/String;

    .line 22
    const-string v1, "_mediaUrl"

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object/from16 v17, v1

    check-cast v17, Ljava/lang/String;

    .line 23
    const-string v1, "_mediaAlt"

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object/from16 v18, v1

    check-cast v18, Ljava/lang/String;

    .line 24
    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1, v0}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 25
    new-instance v2, Ljava/util/LinkedHashMap;

    invoke-direct {v2}, Ljava/util/LinkedHashMap;-><init>()V

    .line 26
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_4

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/Map$Entry;

    .line 27
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/String;

    .line 28
    sget-object v15, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->Companion:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;

    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;->a()[Ljava/lang/String;

    move-result-object v15

    invoke-static {v8, v15}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_3

    const-string v15, ".google"

    const/4 v3, 0x0

    .line 29
    invoke-static {v8, v15, v3}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_3

    :cond_2
    :goto_2
    const/4 v3, 0x0

    goto :goto_1

    .line 30
    :cond_3
    :goto_3
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {v2, v3, v5}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_2

    .line 31
    :cond_4
    sget-object v15, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->PUSH:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 32
    const-string v3, "_pb"

    invoke-interface {v0, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object/from16 v23, v3

    check-cast v23, Ljava/lang/String;

    .line 33
    const-string v3, "_rf"

    invoke-interface {v0, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_5

    sget-object v3, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->Companion:Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;

    invoke-virtual {v3, v0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    move-result-object v3

    move-object/from16 v22, v3

    goto :goto_4

    :cond_5
    const/16 v22, 0x0

    .line 34
    :goto_4
    new-instance v5, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    const v25, 0x44004

    const/16 v26, 0x0

    const/4 v8, 0x0

    const/16 v20, 0x0

    const/16 v24, 0x0

    move-object/from16 v21, v1

    move-object/from16 v19, v2

    invoke-direct/range {v5 .. v26}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;IILkotlin/jvm/internal/g;)V

    return-object v5

    .line 35
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "alert missing"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 36
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "message id missing"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    .locals 26

    move-object/from16 v0, p1

    const-string v1, "json"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    const-string v1, "sound"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "optString(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_0

    const-string v1, ""

    :cond_0
    move-object/from16 v3, p0

    invoke-virtual {v3, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;->a(Ljava/lang/String;)Llx0/l;

    move-result-object v1

    .line 62
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 63
    move-object v9, v3

    check-cast v9, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 64
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 65
    move-object v10, v1

    check-cast v10, Ljava/lang/String;

    .line 66
    const-string v1, "id"

    .line 67
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    if-eqz v5, :cond_7

    .line 68
    const-string v1, "requestId"

    .line 69
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    .line 70
    const-string v1, "alert"

    .line 71
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    if-eqz v8, :cond_6

    .line 72
    const-string v1, "title"

    .line 73
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    .line 74
    const-string v1, "subtitle"

    .line 75
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    .line 76
    sget-object v13, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;->OTHER:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 77
    sget-object v14, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->DOWNLOAD:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 78
    const-string v1, "url"

    .line 79
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v15

    .line 80
    const-string v1, "media"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v3

    const/4 v4, 0x0

    if-eqz v3, :cond_1

    const-string v7, "androidUrl"

    invoke-virtual {v3, v7}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-static {v3}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    move-object/from16 v16, v3

    goto :goto_0

    :cond_1
    move-object/from16 v16, v4

    .line 81
    :goto_0
    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v1

    if-eqz v1, :cond_2

    const-string v3, "alt"

    invoke-virtual {v1, v3}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_2

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    move-object/from16 v17, v1

    goto :goto_1

    :cond_2
    move-object/from16 v17, v4

    .line 82
    :goto_1
    const-string v1, "keys"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v1

    if-eqz v1, :cond_4

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->b(Lorg/json/JSONArray;)Ljava/util/Map;

    move-result-object v1

    if-nez v1, :cond_3

    goto :goto_3

    :cond_3
    :goto_2
    move-object/from16 v18, v1

    goto :goto_4

    :cond_4
    :goto_3
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    goto :goto_2

    .line 83
    :goto_4
    const-string v1, "custom"

    .line 84
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v19

    .line 85
    const-string v1, "richFeatures"

    .line 86
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_5

    .line 87
    sget-object v1, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->Companion:Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;

    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/push/data/RichFeatures$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    move-result-object v4

    :cond_5
    move-object/from16 v21, v4

    .line 88
    new-instance v4, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    const v24, 0x68004

    const/16 v25, 0x0

    const/4 v7, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    invoke-direct/range {v4 .. v25}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;IILkotlin/jvm/internal/g;)V

    return-object v4

    .line 89
    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "alert is required and cannot be null or empty"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 90
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "id is required and cannot be null or empty"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final a(Ljava/lang/String;)Llx0/l;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Llx0/l;"
        }
    .end annotation

    const/4 p0, 0x0

    if-eqz p1, :cond_2

    .line 115
    const-string v0, "none"

    .line 116
    invoke-virtual {p1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 117
    :cond_0
    const-string v0, "default"

    .line 118
    invoke-virtual {p1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_1

    .line 119
    sget-object p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;->DEFAULT:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 120
    new-instance v0, Llx0/l;

    invoke-direct {v0, p1, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object v0

    .line 121
    :cond_1
    sget-object p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;->CUSTOM:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 122
    new-instance v0, Llx0/l;

    invoke-direct {v0, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object v0

    .line 123
    :cond_2
    :goto_0
    sget-object p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;->NONE:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 124
    new-instance v0, Llx0/l;

    invoke-direct {v0, p1, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final a()[Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->access$getKNOWN_KEYS$cp()[Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

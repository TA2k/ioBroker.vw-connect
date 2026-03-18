.class public final Lcom/salesforce/marketingcloud/registration/Registration;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation


# instance fields
.field public final appId:Ljava/lang/String;

.field public final appVersion:Ljava/lang/String;

.field public final attributes:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field public final contactKey:Ljava/lang/String;

.field public final deviceId:Ljava/lang/String;

.field public final dst:Z

.field public final hwid:Ljava/lang/String;

.field private id:I

.field public final locale:Ljava/lang/String;

.field public final locationEnabled:Z

.field public final platform:Ljava/lang/String;

.field public final platformVersion:Ljava/lang/String;

.field public final proximityEnabled:Z

.field public final pushEnabled:Z

.field public final sdkVersion:Ljava/lang/String;

.field public final signedString:Ljava/lang/String;

.field public final systemToken:Ljava/lang/String;

.field public final tags:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field public final timeZone:I

.field private final uuid:Ljava/lang/String;


# direct methods
.method public constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)V
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "ZZZ",
            "Ljava/lang/String;",
            "ZI",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    move-object/from16 v0, p6

    move-object/from16 v1, p7

    move-object/from16 v2, p11

    move-object/from16 v3, p15

    move-object/from16 v4, p16

    move-object/from16 v5, p17

    move-object/from16 v6, p18

    move-object/from16 v7, p19

    move-object/from16 v8, p20

    const-string v9, "uuid"

    invoke-static {p2, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "deviceId"

    invoke-static {p4, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "sdkVersion"

    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "appVersion"

    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "platformVersion"

    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "platform"

    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "hwid"

    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "appId"

    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "locale"

    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "tags"

    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "attributes"

    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    move-object p1, p5

    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    .line 7
    iput-object v0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    .line 8
    iput-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    move/from16 p1, p8

    .line 9
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    move/from16 p1, p9

    .line 10
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    move/from16 p1, p10

    .line 11
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    .line 12
    iput-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    move/from16 p1, p12

    .line 13
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    move/from16 p1, p13

    .line 14
    iput p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    move-object/from16 p1, p14

    .line 15
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    .line 16
    iput-object v3, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    .line 17
    iput-object v4, p0, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    .line 18
    iput-object v5, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    .line 19
    iput-object v6, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    .line 20
    iput-object v7, p0, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    .line 21
    iput-object v8, p0, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;ILkotlin/jvm/internal/g;)V
    .locals 23

    move/from16 v0, p21

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    const/4 v1, 0x0

    move v3, v1

    goto :goto_0

    :cond_0
    move/from16 v3, p1

    :goto_0
    and-int/lit8 v1, v0, 0x10

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    move-object v7, v2

    goto :goto_1

    :cond_1
    move-object/from16 v7, p5

    :goto_1
    and-int/lit16 v0, v0, 0x2000

    if-eqz v0, :cond_2

    move-object/from16 v16, v2

    move-object/from16 v4, p2

    move-object/from16 v5, p3

    move-object/from16 v6, p4

    move-object/from16 v8, p6

    move-object/from16 v9, p7

    move/from16 v10, p8

    move/from16 v11, p9

    move/from16 v12, p10

    move-object/from16 v13, p11

    move/from16 v14, p12

    move/from16 v15, p13

    move-object/from16 v17, p15

    move-object/from16 v18, p16

    move-object/from16 v19, p17

    move-object/from16 v20, p18

    move-object/from16 v21, p19

    move-object/from16 v22, p20

    move-object/from16 v2, p0

    goto :goto_2

    :cond_2
    move-object/from16 v16, p14

    move-object/from16 v2, p0

    move-object/from16 v4, p2

    move-object/from16 v5, p3

    move-object/from16 v6, p4

    move-object/from16 v8, p6

    move-object/from16 v9, p7

    move/from16 v10, p8

    move/from16 v11, p9

    move/from16 v12, p10

    move-object/from16 v13, p11

    move/from16 v14, p12

    move/from16 v15, p13

    move-object/from16 v17, p15

    move-object/from16 v18, p16

    move-object/from16 v19, p17

    move-object/from16 v20, p18

    move-object/from16 v21, p19

    move-object/from16 v22, p20

    .line 22
    :goto_2
    invoke-direct/range {v2 .. v22}, Lcom/salesforce/marketingcloud/registration/Registration;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)V

    return-void
.end method

.method public constructor <init>(Lorg/json/JSONObject;)V
    .locals 28

    move-object/from16 v0, p1

    const-string v1, "json"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    const-string v1, "uuid"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    const-string v1, "getString(...)"

    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    const-string v2, "signedString"

    const-string v3, "optString(...)"

    invoke-static {v0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    .line 25
    const-string v2, "deviceID"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    const-string v2, "device_Token"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    .line 27
    const-string v2, "sdk_Version"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    invoke-static {v8, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    const-string v2, "app_Version"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9

    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    const-string v2, "dST"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getBoolean(Ljava/lang/String;)Z

    move-result v10

    .line 30
    const-string v2, "location_Enabled"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getBoolean(Ljava/lang/String;)Z

    move-result v11

    .line 31
    const-string v2, "proximity_Enabled"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getBoolean(Ljava/lang/String;)Z

    move-result v12

    .line 32
    const-string v2, "platform_Version"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    const-string v2, "push_Enabled"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getBoolean(Ljava/lang/String;)Z

    move-result v14

    .line 34
    const-string v2, "timeZone"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v15

    .line 35
    const-string v2, "subscriberKey"

    .line 36
    invoke-static {v0, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v16

    .line 37
    const-string v2, "platform"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    const-string v3, "hwid"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v17, v2

    .line 39
    const-string v2, "etAppId"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v19, v2

    .line 40
    const-string v2, "locale"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    const-string v1, "tags"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v1

    move-object/from16 v20, v2

    const-string v2, "getJSONArray(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v18, v3

    .line 42
    invoke-virtual {v1}, Lorg/json/JSONArray;->length()I

    move-result v3

    move-object/from16 v21, v4

    const/4 v4, 0x0

    invoke-static {v4, v3}, Lkp/r9;->m(II)Lgy0/j;

    move-result-object v3

    .line 43
    new-instance v4, Ljava/util/ArrayList;

    move-object/from16 v22, v5

    const/16 v5, 0xa

    invoke-static {v3, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 44
    invoke-virtual {v3}, Lgy0/h;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    move-object v5, v3

    check-cast v5, Lgy0/i;

    .line 45
    iget-boolean v5, v5, Lgy0/i;->f:Z

    if-eqz v5, :cond_9

    .line 46
    move-object v5, v3

    check-cast v5, Lmx0/w;

    invoke-virtual {v5}, Lmx0/w;->nextInt()I

    move-result v5

    move-object/from16 v23, v3

    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    move-object/from16 v24, v6

    const-class v6, Ljava/lang/String;

    move-object/from16 v25, v7

    invoke-virtual {v3, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    move-object/from16 v26, v8

    .line 48
    const-class v8, Lorg/json/JSONObject;

    .line 49
    invoke-virtual {v3, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v8

    .line 50
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    move/from16 v27, v8

    const-string v8, "null cannot be cast to non-null type kotlin.String"

    if-eqz v27, :cond_1

    invoke-virtual {v1, v5}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    move-result-object v3

    if-eqz v3, :cond_0

    check-cast v3, Ljava/lang/String;

    move-object/from16 v27, v9

    goto/16 :goto_1

    :cond_0
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v8}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    move-object/from16 v27, v9

    .line 51
    sget-object v9, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 52
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 53
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_2

    invoke-virtual {v1, v5}, Lorg/json/JSONArray;->getInt(I)I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    goto :goto_1

    .line 54
    :cond_2
    sget-object v9, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 55
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 56
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_3

    invoke-virtual {v1, v5}, Lorg/json/JSONArray;->getDouble(I)D

    move-result-wide v5

    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    goto :goto_1

    .line 57
    :cond_3
    sget-object v9, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 58
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 59
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_4

    invoke-virtual {v1, v5}, Lorg/json/JSONArray;->getLong(I)J

    move-result-wide v5

    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    goto :goto_1

    .line 60
    :cond_4
    sget-object v9, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 61
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v9

    .line 62
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_5

    invoke-virtual {v1, v5}, Lorg/json/JSONArray;->getBoolean(I)Z

    move-result v3

    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    goto :goto_1

    .line 63
    :cond_5
    invoke-virtual {v3, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 64
    invoke-static {v7, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_7

    invoke-virtual {v1, v5}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    move-result-object v3

    if-eqz v3, :cond_6

    goto :goto_1

    :cond_6
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v8}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 65
    :cond_7
    invoke-virtual {v1, v5}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    move-result-object v3

    if-eqz v3, :cond_8

    check-cast v3, Ljava/lang/String;

    .line 66
    :goto_1
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v3, v23

    move-object/from16 v6, v24

    move-object/from16 v7, v25

    move-object/from16 v8, v26

    move-object/from16 v9, v27

    goto/16 :goto_0

    .line 67
    :cond_8
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v8}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_9
    move-object/from16 v24, v6

    move-object/from16 v25, v7

    move-object/from16 v26, v8

    move-object/from16 v27, v9

    .line 68
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 69
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_a
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_b

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    move-object v5, v4

    check-cast v5, Ljava/lang/String;

    .line 70
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v5

    if-nez v5, :cond_a

    .line 71
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    .line 72
    :cond_b
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v1

    .line 73
    const-string v3, "attributes"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v0

    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/o;->b(Lorg/json/JSONArray;)Ljava/util/Map;

    move-result-object v0

    const/4 v3, 0x0

    move-object/from16 v2, p0

    move-object/from16 v4, v21

    move-object/from16 v5, v22

    move-object/from16 v6, v24

    move-object/from16 v7, v25

    move-object/from16 v8, v26

    move-object/from16 v9, v27

    move-object/from16 v22, v0

    move-object/from16 v21, v1

    .line 74
    invoke-direct/range {v2 .. v22}, Lcom/salesforce/marketingcloud/registration/Registration;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)V

    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/registration/Registration;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/registration/Registration;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    move/from16 v1, p21

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget v2, v0, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    goto :goto_0

    :cond_0
    move/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-object v3, v0, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget-object v4, v0, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    goto :goto_2

    :cond_2
    move-object/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget-object v5, v0, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget-object v6, v0, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    goto :goto_4

    :cond_4
    move-object/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget-object v7, v0, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    goto :goto_5

    :cond_5
    move-object/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget-object v8, v0, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    goto :goto_6

    :cond_6
    move-object/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget-boolean v9, v0, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    goto :goto_7

    :cond_7
    move/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget-boolean v10, v0, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    goto :goto_8

    :cond_8
    move/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget-boolean v11, v0, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    goto :goto_9

    :cond_9
    move/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v1, 0x400

    if-eqz v12, :cond_a

    iget-object v12, v0, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    goto :goto_a

    :cond_a
    move-object/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v1, 0x800

    if-eqz v13, :cond_b

    iget-boolean v13, v0, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    goto :goto_b

    :cond_b
    move/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v1, 0x1000

    if-eqz v14, :cond_c

    iget v14, v0, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    goto :goto_c

    :cond_c
    move/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v1, 0x2000

    if-eqz v15, :cond_d

    iget-object v15, v0, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    goto :goto_d

    :cond_d
    move-object/from16 v15, p14

    :goto_d
    move/from16 p1, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-object v2, v0, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    goto :goto_e

    :cond_e
    move-object/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    goto :goto_f

    :cond_f
    move-object/from16 v1, p16

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p21, v16

    move-object/from16 p2, v1

    if-eqz v16, :cond_10

    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    goto :goto_10

    :cond_10
    move-object/from16 v1, p17

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p21, v16

    move-object/from16 p3, v1

    if-eqz v16, :cond_11

    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    goto :goto_11

    :cond_11
    move-object/from16 v1, p18

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p21, v16

    move-object/from16 p4, v1

    if-eqz v16, :cond_12

    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    goto :goto_12

    :cond_12
    move-object/from16 v1, p19

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p21, v16

    if-eqz v16, :cond_13

    move-object/from16 p5, v1

    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    move-object/from16 p20, p5

    move-object/from16 p21, v1

    :goto_13
    move-object/from16 p17, p2

    move-object/from16 p18, p3

    move-object/from16 p19, p4

    move-object/from16 p16, v2

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move-object/from16 p5, v5

    move-object/from16 p6, v6

    move-object/from16 p7, v7

    move-object/from16 p8, v8

    move/from16 p9, v9

    move/from16 p10, v10

    move/from16 p11, v11

    move-object/from16 p12, v12

    move/from16 p13, v13

    move/from16 p14, v14

    move-object/from16 p15, v15

    move/from16 p2, p1

    move-object/from16 p1, v0

    goto :goto_14

    :cond_13
    move-object/from16 p21, p20

    move-object/from16 p20, v1

    goto :goto_13

    :goto_14
    invoke-virtual/range {p1 .. p21}, Lcom/salesforce/marketingcloud/registration/Registration;->copy(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)Lcom/salesforce/marketingcloud/registration/Registration;

    move-result-object v0

    return-object v0
.end method


# virtual methods
.method public final appId()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final appVersion()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final attributes()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    .line 2
    .line 3
    return p0
.end method

.method public final component10()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component11()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component13()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    .line 2
    .line 3
    return p0
.end method

.method public final component14()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component15()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component16()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component17()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component18()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component19()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component20()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component9()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final contactKey()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)Lcom/salesforce/marketingcloud/registration/Registration;
    .locals 22
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "ZZZ",
            "Ljava/lang/String;",
            "ZI",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/registration/Registration;"
        }
    .end annotation

    .line 1
    const-string v0, "uuid"

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "deviceId"

    .line 9
    .line 10
    move-object/from16 v5, p4

    .line 11
    .line 12
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "sdkVersion"

    .line 16
    .line 17
    move-object/from16 v7, p6

    .line 18
    .line 19
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "appVersion"

    .line 23
    .line 24
    move-object/from16 v8, p7

    .line 25
    .line 26
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-string v0, "platformVersion"

    .line 30
    .line 31
    move-object/from16 v12, p11

    .line 32
    .line 33
    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v0, "platform"

    .line 37
    .line 38
    move-object/from16 v1, p15

    .line 39
    .line 40
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const-string v0, "hwid"

    .line 44
    .line 45
    move-object/from16 v2, p16

    .line 46
    .line 47
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v0, "appId"

    .line 51
    .line 52
    move-object/from16 v4, p17

    .line 53
    .line 54
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string v0, "locale"

    .line 58
    .line 59
    move-object/from16 v6, p18

    .line 60
    .line 61
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-string v0, "tags"

    .line 65
    .line 66
    move-object/from16 v9, p19

    .line 67
    .line 68
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const-string v0, "attributes"

    .line 72
    .line 73
    move-object/from16 v10, p20

    .line 74
    .line 75
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    new-instance v1, Lcom/salesforce/marketingcloud/registration/Registration;

    .line 79
    .line 80
    move/from16 v11, p10

    .line 81
    .line 82
    move/from16 v13, p12

    .line 83
    .line 84
    move/from16 v14, p13

    .line 85
    .line 86
    move-object/from16 v15, p14

    .line 87
    .line 88
    move-object/from16 v16, p15

    .line 89
    .line 90
    move-object/from16 v17, v2

    .line 91
    .line 92
    move-object/from16 v18, v4

    .line 93
    .line 94
    move-object/from16 v19, v6

    .line 95
    .line 96
    move-object/from16 v20, v9

    .line 97
    .line 98
    move-object/from16 v21, v10

    .line 99
    .line 100
    move/from16 v2, p1

    .line 101
    .line 102
    move-object/from16 v4, p3

    .line 103
    .line 104
    move-object/from16 v6, p5

    .line 105
    .line 106
    move/from16 v9, p8

    .line 107
    .line 108
    move/from16 v10, p9

    .line 109
    .line 110
    invoke-direct/range {v1 .. v21}, Lcom/salesforce/marketingcloud/registration/Registration;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)V

    .line 111
    .line 112
    .line 113
    return-object v1
.end method

.method public final deviceId()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final dst()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    .line 2
    .line 3
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/registration/Registration;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/salesforce/marketingcloud/registration/Registration;

    .line 12
    .line 13
    iget v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    .line 14
    .line 15
    iget v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    .line 65
    .line 66
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    .line 76
    .line 77
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-nez v1, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    .line 87
    .line 88
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    .line 89
    .line 90
    if-eq v1, v3, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    .line 94
    .line 95
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    .line 96
    .line 97
    if-eq v1, v3, :cond_a

    .line 98
    .line 99
    return v2

    .line 100
    :cond_a
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    .line 101
    .line 102
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    .line 103
    .line 104
    if-eq v1, v3, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    .line 108
    .line 109
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    .line 110
    .line 111
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-nez v1, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    .line 119
    .line 120
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    .line 121
    .line 122
    if-eq v1, v3, :cond_d

    .line 123
    .line 124
    return v2

    .line 125
    :cond_d
    iget v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    .line 126
    .line 127
    iget v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    .line 128
    .line 129
    if-eq v1, v3, :cond_e

    .line 130
    .line 131
    return v2

    .line 132
    :cond_e
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    .line 133
    .line 134
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    .line 135
    .line 136
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    if-nez v1, :cond_f

    .line 141
    .line 142
    return v2

    .line 143
    :cond_f
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    .line 144
    .line 145
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    .line 146
    .line 147
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-nez v1, :cond_10

    .line 152
    .line 153
    return v2

    .line 154
    :cond_10
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    .line 155
    .line 156
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    .line 157
    .line 158
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v1

    .line 162
    if-nez v1, :cond_11

    .line 163
    .line 164
    return v2

    .line 165
    :cond_11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    .line 166
    .line 167
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    .line 168
    .line 169
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    if-nez v1, :cond_12

    .line 174
    .line 175
    return v2

    .line 176
    :cond_12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    .line 177
    .line 178
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    .line 179
    .line 180
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v1

    .line 184
    if-nez v1, :cond_13

    .line 185
    .line 186
    return v2

    .line 187
    :cond_13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    .line 188
    .line 189
    iget-object v3, p1, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    .line 190
    .line 191
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result v1

    .line 195
    if-nez v1, :cond_14

    .line 196
    .line 197
    return v2

    .line 198
    :cond_14
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    .line 199
    .line 200
    iget-object p1, p1, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    .line 201
    .line 202
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result p0

    .line 206
    if-nez p0, :cond_15

    .line 207
    .line 208
    return v2

    .line 209
    :cond_15
    return v0
.end method

.method public final getId$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    .line 2
    .line 3
    return p0
.end method

.method public final getUuid$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    move v2, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    :goto_0
    add-int/2addr v0, v2

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    .line 36
    .line 37
    if-nez v2, :cond_1

    .line 38
    .line 39
    move v2, v3

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    :goto_1
    add-int/2addr v0, v2

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    .line 54
    .line 55
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    .line 60
    .line 61
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    .line 66
    .line 67
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    .line 72
    .line 73
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    .line 84
    .line 85
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    iget v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    .line 90
    .line 91
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    .line 96
    .line 97
    if-nez v2, :cond_2

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_2
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    :goto_2
    add-int/2addr v0, v3

    .line 105
    mul-int/2addr v0, v1

    .line 106
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    .line 107
    .line 108
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    .line 113
    .line 114
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    .line 119
    .line 120
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    .line 125
    .line 126
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    .line 131
    .line 132
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    add-int/2addr v2, v0

    .line 137
    mul-int/2addr v2, v1

    .line 138
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    .line 139
    .line 140
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    add-int/2addr p0, v2

    .line 145
    return p0
.end method

.method public final hwid()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final locale()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final locationEnabled()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final platform()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final platformVersion()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final proximityEnabled()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final pushEnabled()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final sdkVersion()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setId$sdk_release(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    .line 2
    .line 3
    return-void
.end method

.method public final signedString()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final systemToken()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final tags()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public final timeZone()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    .line 2
    .line 3
    return p0
.end method

.method public final toJson$sdk_release()Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "uuid"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    .line 14
    .line 15
    const-string v2, "signedString"

    .line 16
    .line 17
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    .line 21
    .line 22
    const-string v2, "deviceID"

    .line 23
    .line 24
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    .line 28
    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    const-string v2, "device_Token"

    .line 32
    .line 33
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 34
    .line 35
    .line 36
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    .line 37
    .line 38
    const-string v2, "sdk_Version"

    .line 39
    .line 40
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 41
    .line 42
    .line 43
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    .line 44
    .line 45
    const-string v2, "app_Version"

    .line 46
    .line 47
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 48
    .line 49
    .line 50
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    .line 51
    .line 52
    const-string v2, "dST"

    .line 53
    .line 54
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 55
    .line 56
    .line 57
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    .line 58
    .line 59
    const-string v2, "location_Enabled"

    .line 60
    .line 61
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 62
    .line 63
    .line 64
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    .line 65
    .line 66
    const-string v2, "proximity_Enabled"

    .line 67
    .line 68
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 69
    .line 70
    .line 71
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    .line 72
    .line 73
    const-string v2, "platform_Version"

    .line 74
    .line 75
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 76
    .line 77
    .line 78
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    .line 79
    .line 80
    const-string v2, "push_Enabled"

    .line 81
    .line 82
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 83
    .line 84
    .line 85
    iget v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    .line 86
    .line 87
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    const-string v2, "timeZone"

    .line 92
    .line 93
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    .line 97
    .line 98
    if-eqz v1, :cond_1

    .line 99
    .line 100
    const-string v2, "subscriberKey"

    .line 101
    .line 102
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 103
    .line 104
    .line 105
    :cond_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    .line 106
    .line 107
    const-string v2, "platform"

    .line 108
    .line 109
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 110
    .line 111
    .line 112
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    .line 113
    .line 114
    const-string v2, "hwid"

    .line 115
    .line 116
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 117
    .line 118
    .line 119
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    .line 120
    .line 121
    const-string v2, "etAppId"

    .line 122
    .line 123
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 124
    .line 125
    .line 126
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    .line 127
    .line 128
    const-string v2, "locale"

    .line 129
    .line 130
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 131
    .line 132
    .line 133
    new-instance v1, Lorg/json/JSONArray;

    .line 134
    .line 135
    new-instance v2, Ljava/util/TreeSet;

    .line 136
    .line 137
    iget-object v3, p0, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    .line 138
    .line 139
    invoke-direct {v2, v3}, Ljava/util/TreeSet;-><init>(Ljava/util/Collection;)V

    .line 140
    .line 141
    .line 142
    invoke-direct {v1, v2}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    .line 143
    .line 144
    .line 145
    const-string v2, "tags"

    .line 146
    .line 147
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 148
    .line 149
    .line 150
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    .line 151
    .line 152
    const-string v1, "<this>"

    .line 153
    .line 154
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    new-instance v1, Ljava/util/TreeMap;

    .line 158
    .line 159
    invoke-direct {v1, p0}, Ljava/util/TreeMap;-><init>(Ljava/util/Map;)V

    .line 160
    .line 161
    .line 162
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Map;)Lorg/json/JSONArray;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    const-string v1, "attributes"

    .line 167
    .line 168
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 169
    .line 170
    .line 171
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lcom/salesforce/marketingcloud/registration/Registration;->id:I

    .line 4
    .line 5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/registration/Registration;->uuid:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, v0, Lcom/salesforce/marketingcloud/registration/Registration;->signedString:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, v0, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, v0, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken:Ljava/lang/String;

    .line 12
    .line 13
    iget-object v6, v0, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v7, v0, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion:Ljava/lang/String;

    .line 16
    .line 17
    iget-boolean v8, v0, Lcom/salesforce/marketingcloud/registration/Registration;->dst:Z

    .line 18
    .line 19
    iget-boolean v9, v0, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled:Z

    .line 20
    .line 21
    iget-boolean v10, v0, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled:Z

    .line 22
    .line 23
    iget-object v11, v0, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion:Ljava/lang/String;

    .line 24
    .line 25
    iget-boolean v12, v0, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled:Z

    .line 26
    .line 27
    iget v13, v0, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone:I

    .line 28
    .line 29
    iget-object v14, v0, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v15, v0, Lcom/salesforce/marketingcloud/registration/Registration;->platform:Ljava/lang/String;

    .line 32
    .line 33
    move-object/from16 v16, v15

    .line 34
    .line 35
    iget-object v15, v0, Lcom/salesforce/marketingcloud/registration/Registration;->hwid:Ljava/lang/String;

    .line 36
    .line 37
    move-object/from16 v17, v15

    .line 38
    .line 39
    iget-object v15, v0, Lcom/salesforce/marketingcloud/registration/Registration;->appId:Ljava/lang/String;

    .line 40
    .line 41
    move-object/from16 v18, v15

    .line 42
    .line 43
    iget-object v15, v0, Lcom/salesforce/marketingcloud/registration/Registration;->locale:Ljava/lang/String;

    .line 44
    .line 45
    move-object/from16 v19, v15

    .line 46
    .line 47
    iget-object v15, v0, Lcom/salesforce/marketingcloud/registration/Registration;->tags:Ljava/util/Set;

    .line 48
    .line 49
    iget-object v0, v0, Lcom/salesforce/marketingcloud/registration/Registration;->attributes:Ljava/util/Map;

    .line 50
    .line 51
    move-object/from16 p0, v0

    .line 52
    .line 53
    const-string v0, ", uuid="

    .line 54
    .line 55
    move-object/from16 v20, v15

    .line 56
    .line 57
    const-string v15, ", signedString="

    .line 58
    .line 59
    move-object/from16 v21, v14

    .line 60
    .line 61
    const-string v14, "Registration(id="

    .line 62
    .line 63
    invoke-static {v14, v1, v0, v2, v15}, Lf2/m0;->o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    const-string v1, ", deviceId="

    .line 68
    .line 69
    const-string v2, ", systemToken="

    .line 70
    .line 71
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    const-string v1, ", sdkVersion="

    .line 75
    .line 76
    const-string v2, ", appVersion="

    .line 77
    .line 78
    invoke-static {v0, v5, v1, v6, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string v1, ", dst="

    .line 82
    .line 83
    const-string v2, ", locationEnabled="

    .line 84
    .line 85
    invoke-static {v7, v1, v2, v0, v8}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 86
    .line 87
    .line 88
    const-string v1, ", proximityEnabled="

    .line 89
    .line 90
    const-string v2, ", platformVersion="

    .line 91
    .line 92
    invoke-static {v0, v9, v1, v10, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    const-string v1, ", pushEnabled="

    .line 96
    .line 97
    const-string v2, ", timeZone="

    .line 98
    .line 99
    invoke-static {v11, v1, v2, v0, v12}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v1, ", contactKey="

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    move-object/from16 v1, v21

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string v1, ", platform="

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    const-string v1, ", hwid="

    .line 121
    .line 122
    const-string v2, ", appId="

    .line 123
    .line 124
    move-object/from16 v3, v16

    .line 125
    .line 126
    move-object/from16 v4, v17

    .line 127
    .line 128
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    const-string v1, ", locale="

    .line 132
    .line 133
    const-string v2, ", tags="

    .line 134
    .line 135
    move-object/from16 v3, v18

    .line 136
    .line 137
    move-object/from16 v4, v19

    .line 138
    .line 139
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    move-object/from16 v1, v20

    .line 143
    .line 144
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    const-string v1, ", attributes="

    .line 148
    .line 149
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    move-object/from16 v1, p0

    .line 153
    .line 154
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    const-string v1, ")"

    .line 158
    .line 159
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    return-object v0
.end method

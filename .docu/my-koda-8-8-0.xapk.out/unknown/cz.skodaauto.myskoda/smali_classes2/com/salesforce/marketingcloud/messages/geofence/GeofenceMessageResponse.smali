.class public final Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/messages/MessageResponse;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation


# instance fields
.field public final fences:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Region;",
            ">;"
        }
    .end annotation
.end field

.field private final refreshCenter:Lcom/salesforce/marketingcloud/location/LatLon;

.field private final refreshRadius:I


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/location/LatLon;ILjava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/location/LatLon;",
            "I",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Region;",
            ">;)V"
        }
    .end annotation

    const-string v0, "refreshCenter"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fences"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->refreshCenter:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 3
    iput p2, p0, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->refreshRadius:I

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->fences:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(Lorg/json/JSONObject;)V
    .locals 9

    const-string v0, "json"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/location/LatLon;

    move-result-object v0

    .line 6
    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/a;->b(Lorg/json/JSONObject;)I

    move-result v1

    .line 7
    const-string v2, "fences"

    invoke-virtual {p1, v2}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object p1

    if-eqz p1, :cond_b

    .line 8
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v2

    const/4 v3, 0x0

    invoke-static {v3, v2}, Lkp/r9;->m(II)Lgy0/j;

    move-result-object v2

    .line 9
    new-instance v3, Ljava/util/ArrayList;

    const/16 v4, 0xa

    invoke-static {v2, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 10
    invoke-virtual {v2}, Lgy0/h;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    move-object v4, v2

    check-cast v4, Lgy0/i;

    .line 11
    iget-boolean v4, v4, Lgy0/i;->f:Z

    if-eqz v4, :cond_9

    .line 12
    move-object v4, v2

    check-cast v4, Lmx0/w;

    invoke-virtual {v4}, Lmx0/w;->nextInt()I

    move-result v4

    .line 13
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    const-class v6, Lorg/json/JSONObject;

    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 14
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 15
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    const-string v8, "null cannot be cast to non-null type org.json.JSONObject"

    if-eqz v6, :cond_1

    invoke-virtual {p1, v4}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    move-result-object v4

    if-eqz v4, :cond_0

    goto/16 :goto_1

    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    invoke-direct {p0, v8}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 16
    :cond_1
    sget-object v6, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 17
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 18
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    invoke-virtual {p1, v4}, Lorg/json/JSONArray;->getInt(I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    check-cast v4, Lorg/json/JSONObject;

    goto :goto_1

    .line 19
    :cond_2
    sget-object v6, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 20
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 21
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3

    invoke-virtual {p1, v4}, Lorg/json/JSONArray;->getDouble(I)D

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    check-cast v4, Lorg/json/JSONObject;

    goto :goto_1

    .line 22
    :cond_3
    sget-object v6, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 23
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 24
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_4

    invoke-virtual {p1, v4}, Lorg/json/JSONArray;->getLong(I)J

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    check-cast v4, Lorg/json/JSONObject;

    goto :goto_1

    .line 25
    :cond_4
    sget-object v6, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 26
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v6

    .line 27
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_5

    invoke-virtual {p1, v4}, Lorg/json/JSONArray;->getBoolean(I)Z

    move-result v4

    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    check-cast v4, Lorg/json/JSONObject;

    goto :goto_1

    .line 28
    :cond_5
    const-class v6, Ljava/lang/String;

    .line 29
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    .line 30
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_7

    invoke-virtual {p1, v4}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    move-result-object v4

    if-eqz v4, :cond_6

    check-cast v4, Lorg/json/JSONObject;

    goto :goto_1

    :cond_6
    new-instance p0, Ljava/lang/NullPointerException;

    invoke-direct {p0, v8}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 31
    :cond_7
    invoke-virtual {p1, v4}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_8

    check-cast v4, Lorg/json/JSONObject;

    .line 32
    :goto_1
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    .line 33
    :cond_8
    new-instance p0, Ljava/lang/NullPointerException;

    invoke-direct {p0, v8}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 34
    :cond_9
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 35
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_a
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_c

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    .line 36
    check-cast v3, Lorg/json/JSONObject;

    .line 37
    :try_start_0
    new-instance v4, Lcom/salesforce/marketingcloud/messages/Region;

    invoke-direct {v4, v3}, Lcom/salesforce/marketingcloud/messages/Region;-><init>(Lorg/json/JSONObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_3

    :catch_0
    move-exception v3

    .line 38
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/messages/Region;->Companion:Lcom/salesforce/marketingcloud/messages/Region$Companion;

    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/messages/Region$Companion;->getTAG$sdk_release()Ljava/lang/String;

    move-result-object v5

    sget-object v6, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse$a;->b:Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse$a;

    invoke-virtual {v4, v5, v3, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    const/4 v4, 0x0

    :goto_3
    if-eqz v4, :cond_a

    .line 39
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    .line 40
    :cond_b
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 41
    :cond_c
    invoke-direct {p0, v0, v1, p1}, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;-><init>(Lcom/salesforce/marketingcloud/location/LatLon;ILjava/util/List;)V

    return-void
.end method


# virtual methods
.method public final fences()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Region;",
            ">;"
        }
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->fences:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRefreshCenter()Lcom/salesforce/marketingcloud/location/LatLon;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->refreshCenter:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRefreshRadius()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->refreshRadius:I

    .line 2
    .line 3
    return p0
.end method

.method public final refreshCenter()Lcom/salesforce/marketingcloud/location/LatLon;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->getRefreshCenter()Lcom/salesforce/marketingcloud/location/LatLon;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final refreshRadius()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/geofence/GeofenceMessageResponse;->getRefreshRadius()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

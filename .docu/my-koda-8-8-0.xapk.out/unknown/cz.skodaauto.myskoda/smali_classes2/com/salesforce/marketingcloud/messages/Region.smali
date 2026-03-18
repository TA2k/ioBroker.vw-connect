.class public final Lcom/salesforce/marketingcloud/messages/Region;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;
.implements Ljava/lang/Comparable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/Region$Companion;,
        Lcom/salesforce/marketingcloud/messages/Region$RegionType;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Landroid/os/Parcelable;",
        "Ljava/lang/Comparable<",
        "Lcom/salesforce/marketingcloud/messages/Region;",
        ">;"
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/messages/Region;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lcom/salesforce/marketingcloud/messages/Region$Companion;

.field public static final MAGIC_REGION_ID:Ljava/lang/String; = "~~m@g1c_f3nc3~~"

.field public static final REGION_TYPE_FENCE:I = 0x1

.field public static final REGION_TYPE_PROXIMITY:I = 0x3

.field private static final TAG:Ljava/lang/String;


# instance fields
.field public final center:Lcom/salesforce/marketingcloud/location/LatLon;

.field public final description:Ljava/lang/String;

.field public final id:Ljava/lang/String;

.field private isInside:Z

.field public final major:I

.field public final messages:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Message;",
            ">;"
        }
    .end annotation
.end field

.field public final minor:I

.field public final name:Ljava/lang/String;

.field public final proximityUuid:Ljava/lang/String;

.field public final radius:I

.field public final regionType:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/Region$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/messages/Region$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/Region;->Companion:Lcom/salesforce/marketingcloud/messages/Region$Companion;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/messages/Region$c;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/messages/Region$c;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/messages/Region;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    const-string v0, "Region"

    .line 17
    .line 18
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lcom/salesforce/marketingcloud/messages/Region;->TAG:Ljava/lang/String;

    .line 23
    .line 24
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/location/LatLon;",
            "I",
            "Ljava/lang/String;",
            "III",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Message;",
            ">;)V"
        }
    .end annotation

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "center"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "messages"

    invoke-static {p10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 4
    iput p3, p0, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

    .line 6
    iput p5, p0, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 7
    iput p6, p0, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 8
    iput p7, p0, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 9
    iput-object p8, p0, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 10
    iput-object p9, p0, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 11
    iput-object p10, p0, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;ILkotlin/jvm/internal/g;)V
    .locals 2

    and-int/lit8 p12, p11, 0x8

    const/4 v0, 0x0

    if-eqz p12, :cond_0

    move-object p4, v0

    :cond_0
    and-int/lit8 p12, p11, 0x10

    const/4 v1, 0x0

    if-eqz p12, :cond_1

    move p5, v1

    :cond_1
    and-int/lit8 p12, p11, 0x20

    if-eqz p12, :cond_2

    move p6, v1

    :cond_2
    and-int/lit16 p12, p11, 0x80

    if-eqz p12, :cond_3

    move-object p8, v0

    :cond_3
    and-int/lit16 p12, p11, 0x100

    if-eqz p12, :cond_4

    move-object p9, v0

    :cond_4
    and-int/lit16 p11, p11, 0x200

    if-eqz p11, :cond_5

    .line 12
    sget-object p10, Lmx0/s;->d:Lmx0/s;

    .line 13
    :cond_5
    invoke-direct/range {p0 .. p10}, Lcom/salesforce/marketingcloud/messages/Region;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    return-void
.end method

.method public constructor <init>(Lorg/json/JSONObject;)V
    .locals 18

    move-object/from16 v0, p1

    sget-object v1, Lmx0/s;->d:Lmx0/s;

    const-class v2, Lorg/json/JSONObject;

    const-string v3, "json"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    const-string v3, "id"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    const-string v3, "getString(...)"

    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    new-instance v6, Lcom/salesforce/marketingcloud/location/LatLon;

    const-string v3, "center"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v3

    const-string v4, "getJSONObject(...)"

    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v6, v3}, Lcom/salesforce/marketingcloud/location/LatLon;-><init>(Lorg/json/JSONObject;)V

    .line 16
    const-string v3, "radius"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    move-result v7

    .line 17
    const-string v3, "proximityUuid"

    const-string v4, "optString(...)"

    invoke-static {v0, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    .line 18
    const-string v3, "major"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    move-result v9

    .line 19
    const-string v3, "minor"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    move-result v10

    .line 20
    const-string v3, "locationType"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v11

    .line 21
    const-string v3, "name"

    .line 22
    invoke-static {v0, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    .line 23
    const-string v3, "description"

    .line 24
    invoke-static {v0, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    .line 25
    :try_start_0
    const-string v3, "messages"

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v0

    if-eqz v0, :cond_e

    .line 26
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    move-result v3

    const/4 v4, 0x0

    invoke-static {v4, v3}, Lkp/r9;->m(II)Lgy0/j;

    move-result-object v3

    .line 27
    new-instance v4, Ljava/util/ArrayList;

    const/16 v14, 0xa

    invoke-static {v3, v14}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v14

    invoke-direct {v4, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 28
    invoke-virtual {v3}, Lgy0/h;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    move-object v14, v3

    check-cast v14, Lgy0/i;

    .line 29
    iget-boolean v14, v14, Lgy0/i;->f:Z

    if-eqz v14, :cond_9

    .line 30
    move-object v14, v3

    check-cast v14, Lmx0/w;

    invoke-virtual {v14}, Lmx0/w;->nextInt()I

    move-result v14

    .line 31
    sget-object v15, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_1

    move-object/from16 v16, v1

    :try_start_1
    invoke-virtual {v15, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v1

    move-object/from16 p1, v3

    .line 32
    invoke-virtual {v15, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 33
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3
    :try_end_1
    .catch Lorg/json/JSONException; {:try_start_1 .. :try_end_1} :catch_0

    move-object/from16 v17, v2

    const-string v2, "null cannot be cast to non-null type org.json.JSONObject"

    if-eqz v3, :cond_1

    :try_start_2
    invoke-virtual {v0, v14}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    move-result-object v1

    if-eqz v1, :cond_0

    goto/16 :goto_1

    :cond_0
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    :catch_0
    move-exception v0

    goto/16 :goto_6

    .line 34
    :cond_1
    sget-object v3, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 35
    invoke-virtual {v15, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 36
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-virtual {v0, v14}, Lorg/json/JSONArray;->getInt(I)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    check-cast v1, Lorg/json/JSONObject;

    goto :goto_1

    .line 37
    :cond_2
    sget-object v3, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 38
    invoke-virtual {v15, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-virtual {v0, v14}, Lorg/json/JSONArray;->getDouble(I)D

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    check-cast v1, Lorg/json/JSONObject;

    goto :goto_1

    .line 40
    :cond_3
    sget-object v3, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 41
    invoke-virtual {v15, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 42
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-virtual {v0, v14}, Lorg/json/JSONArray;->getLong(I)J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    check-cast v1, Lorg/json/JSONObject;

    goto :goto_1

    .line 43
    :cond_4
    sget-object v3, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 44
    invoke-virtual {v15, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-virtual {v0, v14}, Lorg/json/JSONArray;->getBoolean(I)Z

    move-result v1

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    check-cast v1, Lorg/json/JSONObject;

    goto :goto_1

    .line 46
    :cond_5
    const-class v3, Ljava/lang/String;

    .line 47
    invoke-virtual {v15, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 48
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    invoke-virtual {v0, v14}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_6

    check-cast v1, Lorg/json/JSONObject;

    goto :goto_1

    .line 49
    :cond_6
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 50
    :cond_7
    invoke-virtual {v0, v14}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_8

    check-cast v1, Lorg/json/JSONObject;

    .line 51
    :goto_1
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v3, p1

    move-object/from16 v1, v16

    move-object/from16 v2, v17

    goto/16 :goto_0

    .line 52
    :cond_8
    new-instance v0, Ljava/lang/NullPointerException;

    invoke-direct {v0, v2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    :catch_1
    move-exception v0

    move-object/from16 v16, v1

    goto :goto_6

    :cond_9
    move-object/from16 v16, v1

    .line 53
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 54
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_a
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_b

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    .line 55
    check-cast v0, Lorg/json/JSONObject;
    :try_end_2
    .catch Lorg/json/JSONException; {:try_start_2 .. :try_end_2} :catch_0

    .line 56
    :try_start_3
    new-instance v3, Lcom/salesforce/marketingcloud/messages/Message;

    invoke-direct {v3, v0}, Lcom/salesforce/marketingcloud/messages/Message;-><init>(Lorg/json/JSONObject;)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_2

    goto :goto_3

    :catch_2
    move-exception v0

    .line 57
    :try_start_4
    sget-object v3, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v4, Lcom/salesforce/marketingcloud/messages/Region;->TAG:Ljava/lang/String;

    sget-object v14, Lcom/salesforce/marketingcloud/messages/Region$a;->b:Lcom/salesforce/marketingcloud/messages/Region$a;

    invoke-virtual {v3, v4, v0, v14}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    const/4 v3, 0x0

    :goto_3
    if-eqz v3, :cond_a

    .line 58
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    .line 59
    :cond_b
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 60
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_c
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_d

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Lcom/salesforce/marketingcloud/messages/Message;

    .line 61
    invoke-static {v3}, Lcom/salesforce/marketingcloud/messages/b;->a(Lcom/salesforce/marketingcloud/messages/Message;)Z

    move-result v3

    if-eqz v3, :cond_c

    .line 62
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_4
    .catch Lorg/json/JSONException; {:try_start_4 .. :try_end_4} :catch_0

    goto :goto_4

    :cond_d
    move-object/from16 v4, p0

    move-object v14, v0

    goto :goto_7

    :cond_e
    move-object/from16 v16, v1

    :goto_5
    move-object/from16 v4, p0

    move-object/from16 v14, v16

    goto :goto_7

    .line 63
    :goto_6
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v2, Lcom/salesforce/marketingcloud/messages/Region;->TAG:Ljava/lang/String;

    sget-object v3, Lcom/salesforce/marketingcloud/messages/Region$b;->b:Lcom/salesforce/marketingcloud/messages/Region$b;

    invoke-virtual {v1, v2, v0, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    goto :goto_5

    .line 64
    :goto_7
    invoke-direct/range {v4 .. v14}, Lcom/salesforce/marketingcloud/messages/Region;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    return-void
.end method

.method public static final synthetic access$getTAG$cp()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/Region;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/messages/Region;
    .locals 0

    .line 1
    and-int/lit8 p12, p11, 0x1

    .line 2
    .line 3
    if-eqz p12, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p12, p11, 0x2

    .line 8
    .line 9
    if-eqz p12, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p12, p11, 0x4

    .line 14
    .line 15
    if-eqz p12, :cond_2

    .line 16
    .line 17
    iget p3, p0, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p12, p11, 0x8

    .line 20
    .line 21
    if-eqz p12, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p12, p11, 0x10

    .line 26
    .line 27
    if-eqz p12, :cond_4

    .line 28
    .line 29
    iget p5, p0, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p12, p11, 0x20

    .line 32
    .line 33
    if-eqz p12, :cond_5

    .line 34
    .line 35
    iget p6, p0, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p12, p11, 0x40

    .line 38
    .line 39
    if-eqz p12, :cond_6

    .line 40
    .line 41
    iget p7, p0, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 42
    .line 43
    :cond_6
    and-int/lit16 p12, p11, 0x80

    .line 44
    .line 45
    if-eqz p12, :cond_7

    .line 46
    .line 47
    iget-object p8, p0, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 48
    .line 49
    :cond_7
    and-int/lit16 p12, p11, 0x100

    .line 50
    .line 51
    if-eqz p12, :cond_8

    .line 52
    .line 53
    iget-object p9, p0, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 54
    .line 55
    :cond_8
    and-int/lit16 p11, p11, 0x200

    .line 56
    .line 57
    if-eqz p11, :cond_9

    .line 58
    .line 59
    iget-object p10, p0, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    .line 60
    .line 61
    :cond_9
    move-object p11, p9

    .line 62
    move-object p12, p10

    .line 63
    move p9, p7

    .line 64
    move-object p10, p8

    .line 65
    move p7, p5

    .line 66
    move p8, p6

    .line 67
    move p5, p3

    .line 68
    move-object p6, p4

    .line 69
    move-object p3, p1

    .line 70
    move-object p4, p2

    .line 71
    move-object p2, p0

    .line 72
    invoke-virtual/range {p2 .. p12}, Lcom/salesforce/marketingcloud/messages/Region;->copy(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;)Lcom/salesforce/marketingcloud/messages/Region;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

.method public static synthetic isInside$sdk_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final center()Lcom/salesforce/marketingcloud/location/LatLon;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 2
    .line 3
    return-object p0
.end method

.method public compareTo(Lcom/salesforce/marketingcloud/messages/Region;)I
    .locals 1

    const-string v0, "other"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    iget-object p1, p1, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lcom/salesforce/marketingcloud/messages/Region;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/Region;->compareTo(Lcom/salesforce/marketingcloud/messages/Region;)I

    move-result p0

    return p0
.end method

.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Message;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcom/salesforce/marketingcloud/location/LatLon;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 2
    .line 3
    return p0
.end method

.method public final component6()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 2
    .line 3
    return p0
.end method

.method public final component7()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 2
    .line 3
    return p0
.end method

.method public final component8()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;)Lcom/salesforce/marketingcloud/messages/Region;
    .locals 11
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/location/LatLon;",
            "I",
            "Ljava/lang/String;",
            "III",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Message;",
            ">;)",
            "Lcom/salesforce/marketingcloud/messages/Region;"
        }
    .end annotation

    .line 1
    const-string p0, "id"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "center"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "messages"

    .line 12
    .line 13
    move-object/from16 v10, p10

    .line 14
    .line 15
    invoke-static {v10, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    new-instance v0, Lcom/salesforce/marketingcloud/messages/Region;

    .line 19
    .line 20
    move-object v1, p1

    .line 21
    move-object v2, p2

    .line 22
    move v3, p3

    .line 23
    move-object v4, p4

    .line 24
    move/from16 v5, p5

    .line 25
    .line 26
    move/from16 v6, p6

    .line 27
    .line 28
    move/from16 v7, p7

    .line 29
    .line 30
    move-object/from16 v8, p8

    .line 31
    .line 32
    move-object/from16 v9, p9

    .line 33
    .line 34
    invoke-direct/range {v0 .. v10}, Lcom/salesforce/marketingcloud/messages/Region;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 35
    .line 36
    .line 37
    return-object v0
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final description()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/messages/Region;

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
    check-cast p1, Lcom/salesforce/marketingcloud/messages/Region;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 36
    .line 37
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

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
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 54
    .line 55
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 61
    .line 62
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 68
    .line 69
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 77
    .line 78
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-nez v1, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 86
    .line 87
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 88
    .line 89
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    .line 97
    .line 98
    iget-object p1, p1, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    .line 99
    .line 100
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    if-nez p0, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    return v0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 11
    .line 12
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/location/LatLon;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 19
    .line 20
    invoke-static {v0, v2, v1}, Lc1/j0;->g(III)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    if-nez v2, :cond_0

    .line 28
    .line 29
    move v2, v3

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    :goto_0
    add-int/2addr v0, v2

    .line 36
    mul-int/2addr v0, v1

    .line 37
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 38
    .line 39
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 44
    .line 45
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 50
    .line 51
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 56
    .line 57
    if-nez v2, :cond_1

    .line 58
    .line 59
    move v2, v3

    .line 60
    goto :goto_1

    .line 61
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    :goto_1
    add-int/2addr v0, v2

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 68
    .line 69
    if-nez v2, :cond_2

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_2
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    :goto_2
    add-int/2addr v0, v3

    .line 77
    mul-int/2addr v0, v1

    .line 78
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    .line 79
    .line 80
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    add-int/2addr p0, v0

    .line 85
    return p0
.end method

.method public final id()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isInside$sdk_release()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->isInside:Z

    .line 2
    .line 3
    return p0
.end method

.method public final major()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 2
    .line 3
    return p0
.end method

.method public final messages()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Message;",
            ">;"
        }
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final minor()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 2
    .line 3
    return p0
.end method

.method public final name()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final proximityUuid()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final radius()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 2
    .line 3
    return p0
.end method

.method public final regionType()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 2
    .line 3
    return p0
.end method

.method public final setInside$sdk_release(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/Region;->isInside:Z

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 11

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 4
    .line 5
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 6
    .line 7
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

    .line 8
    .line 9
    iget v4, p0, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 10
    .line 11
    iget v5, p0, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 12
    .line 13
    iget v6, p0, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 14
    .line 15
    iget-object v7, p0, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v8, p0, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 18
    .line 19
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    .line 20
    .line 21
    new-instance v9, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string v10, "Region(id="

    .line 24
    .line 25
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v0, ", center="

    .line 32
    .line 33
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v9, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v0, ", radius="

    .line 40
    .line 41
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v9, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v0, ", proximityUuid="

    .line 48
    .line 49
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v9, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v0, ", major="

    .line 56
    .line 57
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v0, ", minor="

    .line 61
    .line 62
    const-string v1, ", regionType="

    .line 63
    .line 64
    invoke-static {v9, v4, v0, v5, v1}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v0, ", name="

    .line 71
    .line 72
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v9, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string v0, ", description="

    .line 79
    .line 80
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v0, ", messages="

    .line 87
    .line 88
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v9, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string p0, ")"

    .line 95
    .line 96
    invoke-virtual {v9, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 1

    .line 1
    const-string v0, "out"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->id:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->center:Lcom/salesforce/marketingcloud/location/LatLon;

    .line 12
    .line 13
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/location/LatLon;->writeToParcel(Landroid/os/Parcel;I)V

    .line 14
    .line 15
    .line 16
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->radius:I

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->proximityUuid:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->major:I

    .line 27
    .line 28
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 29
    .line 30
    .line 31
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->minor:I

    .line 32
    .line 33
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 34
    .line 35
    .line 36
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->regionType:I

    .line 37
    .line 38
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 39
    .line 40
    .line 41
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->name:Ljava/lang/String;

    .line 42
    .line 43
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Region;->description:Ljava/lang/String;

    .line 47
    .line 48
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Region;->messages:Ljava/util/List;

    .line 52
    .line 53
    invoke-static {p0, p1}, Lvj/b;->p(Ljava/util/List;Landroid/os/Parcel;)Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_0

    .line 62
    .line 63
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    check-cast v0, Lcom/salesforce/marketingcloud/messages/Message;

    .line 68
    .line 69
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/messages/Message;->writeToParcel(Landroid/os/Parcel;I)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_0
    return-void
.end method

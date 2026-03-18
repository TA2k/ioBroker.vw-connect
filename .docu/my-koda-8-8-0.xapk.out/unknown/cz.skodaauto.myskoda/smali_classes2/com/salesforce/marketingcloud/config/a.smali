.class public final Lcom/salesforce/marketingcloud/config/a;
.super Lcom/salesforce/marketingcloud/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/k$f;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/config/a$a;
    }
.end annotation


# static fields
.field private static final A:Ljava/lang/String; = "maxDisplay"

.field private static final B:Ljava/lang/String; = "timeBetweenDisplaySec"

.field private static final C:Ljava/lang/String; = "invalidConfigurationKey"

.field private static final D:Ljava/lang/String; = "invalidConfigurationValue"

.field private static final E:Ljava/lang/String; = "event"

.field private static final F:Ljava/lang/String; = "activeEvents"

.field private static final G:Ljava/lang/String; = "enableEngagementEvents"

.field private static final H:Ljava/lang/String; = "enableSystemEvents"

.field private static final I:Ljava/lang/String; = "enableAppEvents"

.field private static final J:Ljava/lang/String; = "enableIdentityEvents"

.field private static final K:Ljava/lang/String; = "enableDebugInfo"

.field private static final L:Ljava/lang/String; = "enableTelemetryInfo"

.field private static final M:Ljava/lang/String; = "endpoints"

.field private static final N:Ljava/lang/String; = "deliveryReceipt"

.field private static final O:Ljava/lang/String; = "deliveryReceiptStatus"

.field private static final P:Ljava/lang/String; = "gateDeliveryReceiptProcessingMs"

.field private static final Q:Ljava/lang/String; = "dataTypes"

.field private static final R:I = 0x3e7

.field private static final S:Ljava/lang/String; = "version"

.field private static T:Lcom/salesforce/marketingcloud/config/a; = null

.field public static final d:Lcom/salesforce/marketingcloud/config/a$a;

.field public static final e:Ljava/lang/String; = "correlationIds"

.field public static final f:Ljava/lang/String; = "gateEventProcessingMs"

.field public static final g:I = 0x0

.field public static final h:Ljava/lang/String; = "eventName"

.field public static final i:Ljava/lang/String; = "endpoint"

.field public static final j:Ljava/lang/String; = "path"

.field public static final k:Ljava/lang/String; = "maxBatchSize"

.field public static final l:I = 0x0

.field public static final m:I = 0x1

.field public static final n:I = 0x2710

.field private static final o:Ljava/util/EnumSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/k$e;",
            ">;"
        }
    .end annotation
.end field

.field private static final p:Ljava/lang/Object;

.field private static final q:Ljava/lang/String; = "~!ConfigComponent"

.field private static final r:I = 0x1

.field private static final s:Z = true

.field private static final t:Z = false

.field private static final u:Z = false

.field private static final v:Z = false

.field private static final w:Z = false

.field private static final x:Z = false

.field private static final y:Ljava/lang/String; = "items"

.field private static final z:Ljava/lang/String; = "inApp"


# instance fields
.field private final U:Lcom/salesforce/marketingcloud/k;

.field private final V:Lcom/salesforce/marketingcloud/storage/h;

.field private final W:Lcom/salesforce/marketingcloud/analytics/m;

.field private X:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/config/b;",
            ">;"
        }
    .end annotation
.end field

.field private Y:Ljava/lang/Boolean;

.field private Z:Ljava/lang/Boolean;

.field private a0:Ljava/lang/Boolean;

.field private b0:Ljava/lang/Boolean;

.field private c0:Ljava/lang/Boolean;

.field private d0:Ljava/lang/Boolean;

.field private e0:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private f0:Ljava/lang/Integer;

.field private g0:Ljava/lang/Integer;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/config/a$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/config/a$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/config/a;->d:Lcom/salesforce/marketingcloud/config/a$a;

    .line 8
    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->f:Lcom/salesforce/marketingcloud/k$e;

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "of(...)"

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lcom/salesforce/marketingcloud/config/a;->o:Ljava/util/EnumSet;

    .line 21
    .line 22
    new-instance v0, Ljava/lang/Object;

    .line 23
    .line 24
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/analytics/m;)V
    .locals 1

    .line 1
    const-string v0, "syncRouteComponent"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "storage"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "triggerAnalytics"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/f;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/config/a;->U:Lcom/salesforce/marketingcloud/k;

    .line 20
    .line 21
    iput-object p2, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 22
    .line 23
    iput-object p3, p0, Lcom/salesforce/marketingcloud/config/a;->W:Lcom/salesforce/marketingcloud/analytics/m;

    .line 24
    .line 25
    sput-object p0, Lcom/salesforce/marketingcloud/config/a;->T:Lcom/salesforce/marketingcloud/config/a;

    .line 26
    .line 27
    return-void
.end method

.method public static final synthetic a()Lcom/salesforce/marketingcloud/config/a;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->T:Lcom/salesforce/marketingcloud/config/a;

    return-object v0
.end method

.method public static final synthetic a(Lcom/salesforce/marketingcloud/config/a;)V
    .locals 0

    .line 2
    sput-object p0, Lcom/salesforce/marketingcloud/config/a;->T:Lcom/salesforce/marketingcloud/config/a;

    return-void
.end method

.method private final a(Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 50
    :try_start_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/config/a;->j()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 51
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 52
    const-string v1, "invalidConfigurationKey"

    invoke-virtual {v0, v1, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 53
    const-string v1, "invalidConfigurationValue"

    invoke-virtual {v0, v1, p2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 54
    iget-object p0, p0, Lcom/salesforce/marketingcloud/config/a;->W:Lcom/salesforce/marketingcloud/analytics/m;

    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/analytics/m;->a(Lorg/json/JSONObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    goto :goto_0

    :cond_0
    return-void

    .line 55
    :goto_0
    sget-object p2, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    new-instance v0, Lcom/salesforce/marketingcloud/config/a$k;

    invoke-direct {v0, p1}, Lcom/salesforce/marketingcloud/config/a$k;-><init>(Ljava/lang/String;)V

    const-string p1, "~!ConfigComponent"

    invoke-virtual {p2, p1, p0, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    return-void
.end method

.method private final a(Lorg/json/JSONArray;)V
    .locals 3

    .line 43
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    monitor-enter v0

    .line 44
    :try_start_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/config/a;->b(Lorg/json/JSONArray;)Ljava/util/Map;

    move-result-object v1

    iput-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->X:Ljava/util/Map;

    .line 45
    iget-object p0, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p0

    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    const-string v1, "endpoints"

    invoke-virtual {p1}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-interface {p0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    .line 46
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :catch_0
    move-exception p0

    .line 47
    :try_start_1
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    const-string v1, "~!ConfigComponent"

    sget-object v2, Lcom/salesforce/marketingcloud/config/a$d;->b:Lcom/salesforce/marketingcloud/config/a$d;

    invoke-virtual {p1, v1, p0, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 48
    :goto_0
    monitor-exit v0

    return-void

    .line 49
    :goto_1
    monitor-exit v0

    throw p0
.end method

.method private final a(Lorg/json/JSONObject;)V
    .locals 6

    .line 25
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    monitor-enter v0

    .line 26
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v1

    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v1

    .line 27
    const-string v2, "deliveryReceiptStatus"

    const/4 v3, 0x0

    .line 28
    invoke-virtual {p1, v2, v3}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    const/4 v5, 0x0

    if-ltz v2, :cond_0

    goto :goto_0

    :cond_0
    move-object v4, v5

    :goto_0
    if-eqz v4, :cond_1

    .line 29
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v3

    goto :goto_1

    :catchall_0
    move-exception p0

    goto :goto_4

    :catch_0
    move-exception p0

    goto :goto_2

    .line 30
    :cond_1
    :goto_1
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    .line 31
    const-string v4, "deliveryReceiptStatus"

    invoke-interface {v1, v4, v3}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 32
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->f0:Ljava/lang/Integer;

    .line 33
    const-string v2, "gateDeliveryReceiptProcessingMs"

    const/16 v3, 0x2710

    .line 34
    invoke-virtual {p1, v2, v3}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    if-le p1, v3, :cond_2

    move-object v5, v2

    :cond_2
    if-eqz v5, :cond_3

    .line 35
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v3

    .line 36
    :cond_3
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    .line 37
    const-string v2, "gateDeliveryReceiptProcessingMs"

    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 38
    iput-object p1, p0, Lcom/salesforce/marketingcloud/config/a;->g0:Ljava/lang/Integer;

    .line 39
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_3

    .line 40
    :goto_2
    :try_start_1
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    const-string v1, "~!ConfigComponent"

    sget-object v2, Lcom/salesforce/marketingcloud/config/a$c;->b:Lcom/salesforce/marketingcloud/config/a$c;

    invoke-virtual {p1, v1, p0, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    :goto_3
    monitor-exit v0

    return-void

    .line 42
    :goto_4
    monitor-exit v0

    throw p0
.end method

.method public static final synthetic b()Ljava/lang/Object;
    .locals 1

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    return-object v0
.end method

.method private final b(Lorg/json/JSONArray;)Ljava/util/Map;
    .locals 13
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/json/JSONArray;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/config/b;",
            ">;"
        }
    .end annotation

    .line 10
    new-instance p0, Ljava/util/LinkedHashMap;

    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 11
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v0

    if-nez v0, :cond_0

    goto/16 :goto_6

    .line 12
    :cond_0
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_5

    .line 13
    :try_start_0
    invoke-virtual {p1, v3}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    move-result-object v0

    const-string v4, "null cannot be cast to non-null type org.json.JSONObject"

    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Lorg/json/JSONObject;

    .line 14
    const-string v4, "dataTypes"

    invoke-virtual {v0, v4}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v4

    if-eqz v4, :cond_4

    .line 15
    invoke-virtual {v4}, Lorg/json/JSONArray;->length()I

    move-result v5

    move v6, v2

    :goto_1
    if-ge v6, v5, :cond_4

    .line 16
    invoke-virtual {v4, v6}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    move-result-object v7

    const-string v8, "null cannot be cast to non-null type kotlin.String"

    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v7, Ljava/lang/String;

    .line 17
    const-string v8, "EVENTS"

    .line 18
    invoke-virtual {v7, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_3

    .line 19
    sget-object v8, Lcom/salesforce/marketingcloud/config/b;->d:Lcom/salesforce/marketingcloud/config/b$a;

    .line 20
    const-string v9, "path"

    invoke-static {v0, v9}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9

    .line 21
    const-string v10, "maxBatchSize"

    invoke-static {v0, v10}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getIntOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/Integer;

    move-result-object v10

    const/16 v11, 0x3e7

    if-eqz v10, :cond_2

    .line 22
    invoke-virtual {v10}, Ljava/lang/Number;->intValue()I

    move-result v12

    if-gt v12, v11, :cond_1

    goto :goto_2

    :cond_1
    const/4 v10, 0x0

    :goto_2
    if-eqz v10, :cond_2

    .line 23
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    move-result v11

    goto :goto_3

    :catch_0
    move-exception v0

    goto :goto_5

    .line 24
    :cond_2
    :goto_3
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    .line 25
    invoke-virtual {v8, v7, v9, v10}, Lcom/salesforce/marketingcloud/config/b$a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)Lcom/salesforce/marketingcloud/config/b;

    move-result-object v8

    .line 26
    invoke-interface {p0, v7, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_4

    :cond_3
    move-object v8, v7

    .line 27
    sget-object v7, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    move-object v9, v8

    const-string v8, "~!ConfigComponent"

    new-instance v10, Lcom/salesforce/marketingcloud/config/a$g;

    invoke-direct {v10, v9}, Lcom/salesforce/marketingcloud/config/a$g;-><init>(Ljava/lang/String;)V

    const/4 v11, 0x2

    const/4 v12, 0x0

    const/4 v9, 0x0

    invoke-static/range {v7 .. v12}, Lcom/salesforce/marketingcloud/g;->e(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :goto_4
    add-int/lit8 v6, v6, 0x1

    goto :goto_1

    .line 28
    :goto_5
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/config/a$h;->b:Lcom/salesforce/marketingcloud/config/a$h;

    const-string v6, "~!ConfigComponent"

    invoke-virtual {v4, v6, v0, v5}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    :cond_4
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_5
    :goto_6
    return-object p0
.end method

.method public static final b(Lcom/salesforce/marketingcloud/config/a;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->d:Lcom/salesforce/marketingcloud/config/a$a;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/config/a$a;->a(Lcom/salesforce/marketingcloud/config/a;)V

    return-void
.end method

.method private final b(Lorg/json/JSONObject;)V
    .locals 6

    .line 29
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    monitor-enter v0

    .line 30
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v1

    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v1

    const-string v2, "edit(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    const-string v2, "enableEngagementEvents"

    const/4 v3, 0x1

    .line 32
    invoke-virtual {p1, v2, v3}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    .line 33
    const-string v4, "enableEngagementEvents"

    invoke-interface {v1, v4, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 34
    iput-object v3, p0, Lcom/salesforce/marketingcloud/config/a;->Y:Ljava/lang/Boolean;

    .line 35
    const-string v2, "enableSystemEvents"

    const/4 v3, 0x0

    .line 36
    invoke-virtual {p1, v2, v3}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    .line 37
    const-string v5, "enableSystemEvents"

    invoke-interface {v1, v5, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 38
    iput-object v4, p0, Lcom/salesforce/marketingcloud/config/a;->Z:Ljava/lang/Boolean;

    .line 39
    const-string v2, "enableAppEvents"

    invoke-virtual {p1, v2, v3}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    .line 40
    const-string v5, "enableAppEvents"

    invoke-interface {v1, v5, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 41
    iput-object v4, p0, Lcom/salesforce/marketingcloud/config/a;->a0:Ljava/lang/Boolean;

    .line 42
    const-string v2, "enableIdentityEvents"

    .line 43
    invoke-virtual {p1, v2, v3}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    .line 44
    const-string v5, "enableIdentityEvents"

    invoke-interface {v1, v5, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 45
    iput-object v4, p0, Lcom/salesforce/marketingcloud/config/a;->b0:Ljava/lang/Boolean;

    .line 46
    const-string v2, "enableDebugInfo"

    invoke-virtual {p1, v2, v3}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    .line 47
    const-string v5, "enableDebugInfo"

    invoke-interface {v1, v5, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 48
    iput-object v4, p0, Lcom/salesforce/marketingcloud/config/a;->d0:Ljava/lang/Boolean;

    .line 49
    const-string v2, "enableTelemetryInfo"

    .line 50
    invoke-virtual {p1, v2, v3}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;Z)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    .line 51
    const-string v4, "enableTelemetryInfo"

    invoke-interface {v1, v4, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 52
    iput-object v3, p0, Lcom/salesforce/marketingcloud/config/a;->c0:Ljava/lang/Boolean;

    .line 53
    const-string v2, "activeEvents"

    invoke-virtual {p1, v2}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object p1

    if-nez p1, :cond_0

    new-instance p1, Lorg/json/JSONArray;

    invoke-direct {p1}, Lorg/json/JSONArray;-><init>()V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_3

    :catch_0
    move-exception p0

    goto :goto_1

    .line 54
    :cond_0
    :goto_0
    invoke-static {p1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->toMap(Lorg/json/JSONArray;)Ljava/util/Map;

    move-result-object v2

    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->e0:Ljava/util/Map;

    .line 55
    const-string p0, "activeEvents"

    invoke-virtual {p1}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-interface {v1, p0, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 56
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    .line 57
    :goto_1
    :try_start_1
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    const-string v1, "~!ConfigComponent"

    sget-object v2, Lcom/salesforce/marketingcloud/config/a$e;->b:Lcom/salesforce/marketingcloud/config/a$e;

    invoke-virtual {p1, v1, p0, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 58
    :goto_2
    monitor-exit v0

    return-void

    .line 59
    :goto_3
    monitor-exit v0

    throw p0
.end method

.method public static final synthetic c()Ljava/util/EnumSet;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->o:Ljava/util/EnumSet;

    return-object v0
.end method

.method private final c(Lorg/json/JSONObject;)V
    .locals 5

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    monitor-enter v0

    .line 3
    :try_start_0
    const-string v1, "gateEventProcessingMs"

    const/4 v2, 0x0

    .line 4
    invoke-virtual {p1, v1, v2}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v1

    .line 5
    const-string v3, "maxDisplay"

    const v4, 0x7fffffff

    invoke-virtual {p1, v3, v4}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v3

    .line 6
    const-string v4, "timeBetweenDisplaySec"

    invoke-virtual {p1, v4, v2}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result p1

    .line 7
    iget-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v2

    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v2

    const-string v4, "edit(...)"

    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    if-ltz v1, :cond_0

    .line 8
    const-string v4, "event_gate_time_mills"

    invoke-interface {v2, v4, v1}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_3

    :catch_0
    move-exception p0

    goto :goto_1

    :cond_0
    :goto_0
    if-ltz v3, :cond_1

    .line 9
    const-string v4, "event_max_display_in_session"

    invoke-interface {v2, v4, v3}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    :cond_1
    if-ltz p1, :cond_2

    .line 10
    const-string v4, "event_min_time_sec_in_session"

    invoke-interface {v2, v4, p1}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 11
    :cond_2
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    if-gez v1, :cond_3

    .line 12
    const-string v2, "gateEventProcessingMs"

    .line 13
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    .line 14
    invoke-direct {p0, v2, v1}, Lcom/salesforce/marketingcloud/config/a;->a(Ljava/lang/String;Ljava/lang/String;)V

    :cond_3
    if-gez v3, :cond_4

    .line 15
    const-string v1, "maxDisplay"

    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v2

    invoke-direct {p0, v1, v2}, Lcom/salesforce/marketingcloud/config/a;->a(Ljava/lang/String;Ljava/lang/String;)V

    :cond_4
    if-gez p1, :cond_5

    .line 16
    const-string v1, "timeBetweenDisplaySec"

    .line 17
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    .line 18
    invoke-direct {p0, v1, p1}, Lcom/salesforce/marketingcloud/config/a;->a(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    .line 19
    :goto_1
    :try_start_1
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    const-string v1, "~!ConfigComponent"

    sget-object v2, Lcom/salesforce/marketingcloud/config/a$f;->b:Lcom/salesforce/marketingcloud/config/a$f;

    invoke-virtual {p1, v1, p0, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    :cond_5
    :goto_2
    monitor-exit v0

    return-void

    .line 21
    :goto_3
    monitor-exit v0

    throw p0
.end method

.method public static final g()Lcom/salesforce/marketingcloud/config/a;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->d:Lcom/salesforce/marketingcloud/config/a$a;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/config/a$a;->a()Lcom/salesforce/marketingcloud/config/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method private final h()Ljava/util/Map;
    .locals 3
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
    new-instance v0, Lorg/json/JSONArray;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v1, Lorg/json/JSONArray;

    .line 10
    .line 11
    invoke-direct {v1}, Lorg/json/JSONArray;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const-string v2, "activeEvents"

    .line 19
    .line 20
    invoke-interface {p0, v2, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {v0, p0}, Lorg/json/JSONArray;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->toMap(Lorg/json/JSONArray;)Ljava/util/Map;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;)Lcom/salesforce/marketingcloud/config/b;
    .locals 4

    if-eqz p1, :cond_3

    if-eqz p2, :cond_3

    .line 4
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_0

    goto :goto_2

    .line 5
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    monitor-enter v0

    .line 6
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->X:Ljava/util/Map;

    if-eqz v1, :cond_1

    invoke-interface {v1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/config/b;

    if-nez v1, :cond_2

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 7
    :cond_1
    :goto_0
    new-instance v1, Lorg/json/JSONArray;

    .line 8
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p1

    .line 9
    const-string v2, "endpoints"

    .line 10
    new-instance v3, Lorg/json/JSONArray;

    invoke-direct {v3}, Lorg/json/JSONArray;-><init>()V

    invoke-virtual {v3}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    move-result-object v3

    .line 11
    invoke-interface {p1, v2, v3}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 12
    invoke-direct {v1, p1}, Lorg/json/JSONArray;-><init>(Ljava/lang/String;)V

    .line 13
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/config/a;->b(Lorg/json/JSONArray;)Ljava/util/Map;

    move-result-object p1

    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/config/a;->X:Ljava/util/Map;

    .line 15
    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    move-object v1, p0

    check-cast v1, Lcom/salesforce/marketingcloud/config/b;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    :cond_2
    monitor-exit v0

    return-object v1

    :goto_1
    monitor-exit v0

    throw p0

    :cond_3
    :goto_2
    const/4 p0, 0x0

    return-object p0
.end method

.method public final a(Ljava/lang/String;)Ljava/lang/String;
    .locals 4

    const-string v0, "eventName"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    monitor-enter v0

    .line 18
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->e0:Ljava/util/Map;

    if-eqz v1, :cond_0

    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    invoke-virtual {p1, v2}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v2

    const-string v3, "toLowerCase(...)"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    if-nez v1, :cond_1

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 19
    :cond_0
    :goto_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/config/a;->h()Ljava/util/Map;

    move-result-object v1

    .line 20
    iput-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->e0:Ljava/util/Map;

    .line 21
    sget-object p0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    invoke-virtual {p1, p0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object p0

    const-string p1, "toLowerCase(...)"

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    invoke-interface {v1, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    move-object v1, p0

    check-cast v1, Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    :cond_1
    monitor-exit v0

    return-object v1

    .line 24
    :goto_1
    monitor-exit v0

    throw p0
.end method

.method public a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 1

    const-string v0, "statusBuilder"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/config/a;->U:Lcom/salesforce/marketingcloud/k;

    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->o:Ljava/util/EnumSet;

    invoke-virtual {p1, v0, p0}, Lcom/salesforce/marketingcloud/k;->a(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/k$f;)V

    return-void
.end method

.method public final b(Ljava/lang/String;)Z
    .locals 2

    const-string v0, "eventName"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->e0:Ljava/util/Map;

    if-eqz v1, :cond_0

    sget-object p0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    invoke-virtual {p1, p0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object p0

    const-string p1, "toLowerCase(...)"

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v1, p0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result p0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 5
    :cond_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/config/a;->h()Ljava/util/Map;

    move-result-object v1

    .line 6
    iput-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->e0:Ljava/util/Map;

    .line 7
    sget-object p0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    invoke-virtual {p1, p0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object p0

    const-string p1, "toLowerCase(...)"

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v1, p0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    :goto_0
    monitor-exit v0

    return p0

    .line 9
    :goto_1
    monitor-exit v0

    throw p0
.end method

.method public componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "ConfigComponent"

    .line 2
    .line 3
    return-object p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 12

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v1

    .line 9
    :try_start_0
    const-string v2, "event"

    .line 10
    .line 11
    new-instance v3, Lorg/json/JSONObject;

    .line 12
    .line 13
    invoke-direct {v3}, Lorg/json/JSONObject;-><init>()V

    .line 14
    .line 15
    .line 16
    const-string v4, "enableEngagementEvents"

    .line 17
    .line 18
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 19
    .line 20
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    const-string v6, "enableEngagementEvents"

    .line 25
    .line 26
    const/4 v7, 0x1

    .line 27
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 32
    .line 33
    .line 34
    const-string v4, "enableSystemEvents"

    .line 35
    .line 36
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 37
    .line 38
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    const-string v6, "enableSystemEvents"

    .line 43
    .line 44
    const/4 v7, 0x0

    .line 45
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 50
    .line 51
    .line 52
    const-string v4, "enableAppEvents"

    .line 53
    .line 54
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 55
    .line 56
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    const-string v6, "enableAppEvents"

    .line 61
    .line 62
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 63
    .line 64
    .line 65
    move-result v5

    .line 66
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 67
    .line 68
    .line 69
    const-string v4, "enableIdentityEvents"

    .line 70
    .line 71
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 72
    .line 73
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    const-string v6, "enableIdentityEvents"

    .line 78
    .line 79
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 84
    .line 85
    .line 86
    const-string v4, "enableTelemetryInfo"

    .line 87
    .line 88
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 89
    .line 90
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    const-string v6, "enableTelemetryInfo"

    .line 95
    .line 96
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 101
    .line 102
    .line 103
    const-string v4, "enableDebugInfo"

    .line 104
    .line 105
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 106
    .line 107
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    const-string v6, "enableDebugInfo"

    .line 112
    .line 113
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 118
    .line 119
    .line 120
    iget-object v4, p0, Lcom/salesforce/marketingcloud/config/a;->e0:Ljava/util/Map;

    .line 121
    .line 122
    if-nez v4, :cond_0

    .line 123
    .line 124
    sget-object v4, Lmx0/t;->d:Lmx0/t;

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :catchall_0
    move-exception v0

    .line 128
    move-object p0, v0

    .line 129
    goto/16 :goto_3

    .line 130
    .line 131
    :cond_0
    :goto_0
    const-string v5, "activeEvents"

    .line 132
    .line 133
    new-instance v6, Lorg/json/JSONArray;

    .line 134
    .line 135
    invoke-direct {v6}, Lorg/json/JSONArray;-><init>()V

    .line 136
    .line 137
    .line 138
    invoke-interface {v4}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 139
    .line 140
    .line 141
    move-result-object v4

    .line 142
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 143
    .line 144
    .line 145
    move-result-object v4

    .line 146
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 147
    .line 148
    .line 149
    move-result v8

    .line 150
    if-eqz v8, :cond_2

    .line 151
    .line 152
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v8

    .line 156
    check-cast v8, Ljava/util/Map$Entry;

    .line 157
    .line 158
    new-instance v9, Lorg/json/JSONObject;

    .line 159
    .line 160
    invoke-direct {v9}, Lorg/json/JSONObject;-><init>()V

    .line 161
    .line 162
    .line 163
    const-string v10, "eventName"

    .line 164
    .line 165
    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v11

    .line 169
    invoke-virtual {v9, v10, v11}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 170
    .line 171
    .line 172
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v8

    .line 176
    check-cast v8, Ljava/lang/String;

    .line 177
    .line 178
    if-eqz v8, :cond_1

    .line 179
    .line 180
    const-string v10, "correlationIds"

    .line 181
    .line 182
    invoke-virtual {v9, v10, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 183
    .line 184
    .line 185
    :cond_1
    invoke-virtual {v6, v9}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;

    .line 186
    .line 187
    .line 188
    goto :goto_1

    .line 189
    :cond_2
    invoke-virtual {v3, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 190
    .line 191
    .line 192
    invoke-virtual {v0, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 193
    .line 194
    .line 195
    const-string v2, "inApp"

    .line 196
    .line 197
    new-instance v3, Lorg/json/JSONObject;

    .line 198
    .line 199
    invoke-direct {v3}, Lorg/json/JSONObject;-><init>()V

    .line 200
    .line 201
    .line 202
    const-string v4, "gateEventProcessingMs"

    .line 203
    .line 204
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 205
    .line 206
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 207
    .line 208
    .line 209
    move-result-object v5

    .line 210
    const-string v6, "gateEventProcessingMs"

    .line 211
    .line 212
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 213
    .line 214
    .line 215
    move-result v5

    .line 216
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 217
    .line 218
    .line 219
    const-string v4, "maxDisplay"

    .line 220
    .line 221
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 222
    .line 223
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 224
    .line 225
    .line 226
    move-result-object v5

    .line 227
    const-string v6, "maxDisplay"

    .line 228
    .line 229
    const v8, 0x7fffffff

    .line 230
    .line 231
    .line 232
    invoke-interface {v5, v6, v8}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 233
    .line 234
    .line 235
    move-result v5

    .line 236
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 237
    .line 238
    .line 239
    const-string v4, "timeBetweenDisplaySec"

    .line 240
    .line 241
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 242
    .line 243
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 244
    .line 245
    .line 246
    move-result-object v5

    .line 247
    const-string v6, "timeBetweenDisplaySec"

    .line 248
    .line 249
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 250
    .line 251
    .line 252
    move-result v5

    .line 253
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 254
    .line 255
    .line 256
    invoke-virtual {v0, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 257
    .line 258
    .line 259
    const-string v2, "deliveryReceipt"

    .line 260
    .line 261
    new-instance v3, Lorg/json/JSONObject;

    .line 262
    .line 263
    invoke-direct {v3}, Lorg/json/JSONObject;-><init>()V

    .line 264
    .line 265
    .line 266
    const-string v4, "deliveryReceiptStatus"

    .line 267
    .line 268
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 269
    .line 270
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 271
    .line 272
    .line 273
    move-result-object v5

    .line 274
    const-string v6, "deliveryReceiptStatus"

    .line 275
    .line 276
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 277
    .line 278
    .line 279
    move-result v5

    .line 280
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 281
    .line 282
    .line 283
    const-string v4, "gateDeliveryReceiptProcessingMs"

    .line 284
    .line 285
    iget-object v5, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 286
    .line 287
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 288
    .line 289
    .line 290
    move-result-object v5

    .line 291
    const-string v6, "gateDeliveryReceiptProcessingMs"

    .line 292
    .line 293
    const/16 v7, 0x2710

    .line 294
    .line 295
    invoke-interface {v5, v6, v7}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 296
    .line 297
    .line 298
    move-result v5

    .line 299
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 300
    .line 301
    .line 302
    invoke-virtual {v0, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 303
    .line 304
    .line 305
    iget-object p0, p0, Lcom/salesforce/marketingcloud/config/a;->X:Ljava/util/Map;

    .line 306
    .line 307
    if-nez p0, :cond_3

    .line 308
    .line 309
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 310
    .line 311
    :cond_3
    const-string v2, "endpoints"

    .line 312
    .line 313
    invoke-static {p0}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->toJSONArray(Ljava/util/Map;)Lorg/json/JSONArray;

    .line 314
    .line 315
    .line 316
    move-result-object p0

    .line 317
    invoke-virtual {v0, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 318
    .line 319
    .line 320
    goto :goto_2

    .line 321
    :catch_0
    :try_start_1
    sget-object v2, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 322
    .line 323
    const-string v3, "~!ConfigComponent"

    .line 324
    .line 325
    sget-object v5, Lcom/salesforce/marketingcloud/config/a$b;->b:Lcom/salesforce/marketingcloud/config/a$b;

    .line 326
    .line 327
    const/4 v6, 0x2

    .line 328
    const/4 v7, 0x0

    .line 329
    const/4 v4, 0x0

    .line 330
    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/g;->e(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 331
    .line 332
    .line 333
    :goto_2
    monitor-exit v1

    .line 334
    return-object v0

    .line 335
    :goto_3
    monitor-exit v1

    .line 336
    throw p0
.end method

.method public final d()Ljava/util/Map;
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/config/a;->e0:Ljava/util/Map;

    return-object p0
.end method

.method public final d(Lorg/json/JSONObject;)V
    .locals 1

    const-string v0, "data"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    const-string v0, "items"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object p1

    if-nez p1, :cond_0

    new-instance p1, Lorg/json/JSONObject;

    invoke-direct {p1}, Lorg/json/JSONObject;-><init>()V

    .line 3
    :cond_0
    const-string v0, "event"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v0

    if-nez v0, :cond_1

    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    :cond_1
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/config/a;->b(Lorg/json/JSONObject;)V

    .line 4
    const-string v0, "inApp"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v0

    if-nez v0, :cond_2

    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    :cond_2
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/config/a;->c(Lorg/json/JSONObject;)V

    .line 5
    const-string v0, "endpoints"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v0

    if-nez v0, :cond_3

    new-instance v0, Lorg/json/JSONArray;

    invoke-direct {v0}, Lorg/json/JSONArray;-><init>()V

    :cond_3
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/config/a;->a(Lorg/json/JSONArray;)V

    .line 6
    const-string v0, "deliveryReceipt"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object p1

    if-nez p1, :cond_4

    new-instance p1, Lorg/json/JSONObject;

    invoke-direct {p1}, Lorg/json/JSONObject;-><init>()V

    .line 7
    :cond_4
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/config/a;->a(Lorg/json/JSONObject;)V

    return-void
.end method

.method public final e()I
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->g0:Ljava/lang/Integer;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "gateDeliveryReceiptProcessingMs"

    .line 22
    .line 23
    const/16 v3, 0x2710

    .line 24
    .line 25
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->g0:Ljava/lang/Integer;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    .line 35
    move p0, v1

    .line 36
    :goto_0
    monitor-exit v0

    .line 37
    return p0

    .line 38
    :goto_1
    monitor-exit v0

    .line 39
    throw p0
.end method

.method public final f()I
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->f0:Ljava/lang/Integer;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "deliveryReceiptStatus"

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->f0:Ljava/lang/Integer;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    move p0, v1

    .line 35
    :goto_0
    monitor-exit v0

    .line 36
    return p0

    .line 37
    :goto_1
    monitor-exit v0

    .line 38
    throw p0
.end method

.method public final i()Z
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->a0:Ljava/lang/Boolean;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "enableAppEvents"

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->a0:Ljava/lang/Boolean;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    move p0, v1

    .line 35
    :goto_0
    monitor-exit v0

    .line 36
    return p0

    .line 37
    :goto_1
    monitor-exit v0

    .line 38
    throw p0
.end method

.method public final j()Z
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->d0:Ljava/lang/Boolean;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "enableDebugInfo"

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->d0:Ljava/lang/Boolean;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    move p0, v1

    .line 35
    :goto_0
    monitor-exit v0

    .line 36
    return p0

    .line 37
    :goto_1
    monitor-exit v0

    .line 38
    throw p0
.end method

.method public final k()Z
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->Y:Ljava/lang/Boolean;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "enableEngagementEvents"

    .line 22
    .line 23
    const/4 v3, 0x1

    .line 24
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->Y:Ljava/lang/Boolean;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    move p0, v1

    .line 35
    :goto_0
    monitor-exit v0

    .line 36
    return p0

    .line 37
    :goto_1
    monitor-exit v0

    .line 38
    throw p0
.end method

.method public final l()Z
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->b0:Ljava/lang/Boolean;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "enableIdentityEvents"

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->b0:Ljava/lang/Boolean;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    move p0, v1

    .line 35
    :goto_0
    monitor-exit v0

    .line 36
    return p0

    .line 37
    :goto_1
    monitor-exit v0

    .line 38
    throw p0
.end method

.method public final m()Z
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->Z:Ljava/lang/Boolean;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "enableSystemEvents"

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->Z:Ljava/lang/Boolean;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    move p0, v1

    .line 35
    :goto_0
    monitor-exit v0

    .line 36
    return p0

    .line 37
    :goto_1
    monitor-exit v0

    .line 38
    throw p0
.end method

.method public final n()Z
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->p:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->c0:Ljava/lang/Boolean;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/config/a;->V:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v2, "enableTelemetryInfo"

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    iput-object v2, p0, Lcom/salesforce/marketingcloud/config/a;->c0:Ljava/lang/Boolean;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    move p0, v1

    .line 35
    :goto_0
    monitor-exit v0

    .line 36
    return p0

    .line 37
    :goto_1
    monitor-exit v0

    .line 38
    throw p0
.end method

.method public onSyncReceived(Lcom/salesforce/marketingcloud/k$e;Lorg/json/JSONObject;)V
    .locals 8

    .line 1
    const-string v0, "node"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "data"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lcom/salesforce/marketingcloud/config/a;->o:Ljava/util/EnumSet;

    .line 12
    .line 13
    invoke-virtual {v0, p1}, Ljava/util/AbstractCollection;->contains(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const-string v0, "version"

    .line 21
    .line 22
    invoke-virtual {p2, v0}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/4 v1, 0x1

    .line 27
    if-eq v0, v1, :cond_1

    .line 28
    .line 29
    sget-object v2, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 30
    .line 31
    sget-object v5, Lcom/salesforce/marketingcloud/config/a$i;->b:Lcom/salesforce/marketingcloud/config/a$i;

    .line 32
    .line 33
    const/4 v6, 0x2

    .line 34
    const/4 v7, 0x0

    .line 35
    const-string v3, "~!ConfigComponent"

    .line 36
    .line 37
    const/4 v4, 0x0

    .line 38
    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/g;->b(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_1
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->f:Lcom/salesforce/marketingcloud/k$e;

    .line 43
    .line 44
    if-ne p1, v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/config/a;->d(Lorg/json/JSONObject;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    :cond_2
    :goto_0
    return-void

    .line 50
    :catchall_0
    move-exception v0

    .line 51
    move-object p0, v0

    .line 52
    sget-object p1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 53
    .line 54
    sget-object p2, Lcom/salesforce/marketingcloud/config/a$j;->b:Lcom/salesforce/marketingcloud/config/a$j;

    .line 55
    .line 56
    const-string v0, "~!ConfigComponent"

    .line 57
    .line 58
    invoke-virtual {p1, v0, p0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public tearDown(Z)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/config/a;->U:Lcom/salesforce/marketingcloud/k;

    .line 2
    .line 3
    sget-object p1, Lcom/salesforce/marketingcloud/config/a;->o:Ljava/util/EnumSet;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/k;->a(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/k$f;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/config/a;->T:Lcom/salesforce/marketingcloud/config/a;

    .line 10
    .line 11
    return-void
.end method

.class public final Lcom/salesforce/marketingcloud/i;
.super Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/i$a;
    }
.end annotation


# static fields
.field public static final b:Lcom/salesforce/marketingcloud/i$a;

.field private static c:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/registration/RegistrationManager;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/i$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/i$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/i;->b:Lcom/salesforce/marketingcloud/i$a;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/registration/RegistrationManager;)V
    .locals 2

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->PUSH:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;Ljava/lang/String;)V

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/i;->a:Lcom/salesforce/marketingcloud/registration/RegistrationManager;

    if-eqz p2, :cond_0

    .line 4
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->getContactKey()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->setProfileId(Ljava/lang/String;)V

    .line 5
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->getDeviceId()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->setInstallationId(Ljava/lang/String;)V

    .line 6
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 7
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->getDeviceId()Ljava/lang/String;

    move-result-object v0

    const-string v1, "deviceId"

    invoke-virtual {p1, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->getAttributes()Ljava/util/Map;

    move-result-object v0

    const-string v1, "attributes"

    invoke-virtual {p1, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->getTags()Ljava/util/Set;

    move-result-object p2

    const-string v0, "tags"

    invoke-virtual {p1, v0, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->setCustomProperties(Ljava/util/Map;)V

    :cond_0
    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/registration/RegistrationManager;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/i;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/registration/RegistrationManager;)V

    return-void
.end method

.method public static final synthetic a()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;
    .locals 1

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/i;->c:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    return-object v0
.end method

.method public static final a(Ljava/lang/String;Lcom/salesforce/marketingcloud/registration/RegistrationManager;)Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/i;->b:Lcom/salesforce/marketingcloud/i$a;

    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/i$a;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/registration/RegistrationManager;)Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    move-result-object p0

    return-object p0
.end method

.method public static final synthetic a(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;)V
    .locals 0

    .line 3
    sput-object p0, Lcom/salesforce/marketingcloud/i;->c:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    return-void
.end method


# virtual methods
.method public customPropertiesToJson(Ljava/util/Map;)Lorg/json/JSONObject;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ljava/lang/Object;",
            ">;)",
            "Lorg/json/JSONObject;"
        }
    .end annotation

    .line 1
    const-string v0, "attributes"

    .line 2
    .line 3
    const-string v1, "deviceId"

    .line 4
    .line 5
    const-string v2, "customProperties"

    .line 6
    .line 7
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    new-instance v2, Lorg/json/JSONObject;

    .line 11
    .line 12
    invoke-direct {v2}, Lorg/json/JSONObject;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-interface {p1, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-virtual {v2, v1, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 20
    .line 21
    .line 22
    new-instance v1, Lorg/json/JSONObject;

    .line 23
    .line 24
    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const-string v3, "null cannot be cast to non-null type kotlin.collections.MutableMap<kotlin.Any?, kotlin.Any?>"

    .line 29
    .line 30
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {p1}, Lkotlin/jvm/internal/j0;->c(Ljava/lang/Object;)Ljava/util/Map;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-direct {v1, p1}, Lorg/json/JSONObject;-><init>(Ljava/util/Map;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v2, v0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 41
    .line 42
    .line 43
    const-string p1, "tags"

    .line 44
    .line 45
    new-instance v0, Lorg/json/JSONArray;

    .line 46
    .line 47
    iget-object p0, p0, Lcom/salesforce/marketingcloud/i;->a:Lcom/salesforce/marketingcloud/registration/RegistrationManager;

    .line 48
    .line 49
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->getTags()Ljava/util/Set;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-direct {v0, p0}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v2, p1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 57
    .line 58
    .line 59
    return-object v2

    .line 60
    :catch_0
    move-exception p0

    .line 61
    new-instance p1, Lorg/json/JSONObject;

    .line 62
    .line 63
    invoke-direct {p1}, Lorg/json/JSONObject;-><init>()V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    const-string v0, "error"

    .line 71
    .line 72
    invoke-virtual {p1, v0, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 73
    .line 74
    .line 75
    return-object p1
.end method

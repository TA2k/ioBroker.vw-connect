.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u000b\n\u0002\u0010$\n\u0002\u0008\u0002\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u0015\u0010\u000e\u001a\u00020\u00062\u0006\u0010\u000f\u001a\u00020\u0004H\u0000\u00a2\u0006\u0002\u0008\u0010J\u0019\u0010\u0011\u001a\u000e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u00010\u0012H\u0000\u00a2\u0006\u0002\u0008\u0013R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R\u0016\u0010\u0005\u001a\u0004\u0018\u00010\u0006X\u0082\u000e\u00a2\u0006\u0008\n\u0000\u0012\u0004\u0008\u0007\u0010\u0002R$\u0010\t\u001a\u00020\u00062\u0006\u0010\u0008\u001a\u00020\u00068F@FX\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\n\u0010\u000b\"\u0004\u0008\u000c\u0010\r\u00a8\u0006\u0014"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;",
        "",
        "()V",
        "TAG",
        "",
        "_instance",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;",
        "get_instance$annotations",
        "value",
        "instance",
        "getInstance",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;",
        "setInstance",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V",
        "create",
        "registrationId",
        "create$sfmcsdk_release",
        "toEvent",
        "",
        "toEvent$sfmcsdk_release",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;-><init>()V

    return-void
.end method

.method private static synthetic get_instance$annotations()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final create$sfmcsdk_release(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;
    .locals 1

    .line 1
    const-string p0, "registrationId"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->access$get_instance$cp()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;-><init>(Ljava/lang/String;Lkotlin/jvm/internal/g;)V

    .line 16
    .line 17
    .line 18
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;

    .line 19
    .line 20
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;->setInstance(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    return-object p0
.end method

.method public final getInstance()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;
    .locals 1

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->access$get_instance$cp()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 9
    .line 10
    const-string v0, "You must initialize the SDK before attempting to use Identity."

    .line 11
    .line 12
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    throw p0
.end method

.method public final setInstance(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V
    .locals 2

    .line 1
    const-string p0, "value"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 7
    .line 8
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion$instance$1;

    .line 9
    .line 10
    invoke-direct {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion$instance$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V

    .line 11
    .line 12
    .line 13
    const-string v1, "~$Identity"

    .line 14
    .line 15
    invoke-virtual {p0, v1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V

    .line 16
    .line 17
    .line 18
    invoke-static {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->access$set_instance$cp(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final toEvent$sfmcsdk_release()Ljava/util/Map;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->access$get_instance$cp()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    const-string v1, "platform"

    .line 13
    .line 14
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->getPlatform()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-interface {p0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    const-string v1, "registrationId"

    .line 22
    .line 23
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->getRegistrationId()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-interface {p0, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    new-instance v1, Lorg/json/JSONObject;

    .line 31
    .line 32
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 33
    .line 34
    .line 35
    invoke-static {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->access$get_moduleIdentities$p(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)Ljava/util/Map;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    if-eqz v2, :cond_0

    .line 52
    .line 53
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    check-cast v2, Ljava/util/Map$Entry;

    .line 58
    .line 59
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    check-cast v3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 64
    .line 65
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    sget-object v4, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 70
    .line 71
    invoke-virtual {v3, v4}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    const-string v4, "this as java.lang.String).toLowerCase(Locale.ROOT)"

    .line 76
    .line 77
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    check-cast v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    .line 85
    .line 86
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->toJson()Lorg/json/JSONObject;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    invoke-virtual {v1, v3, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_0
    const-string v0, "moduleIdentities"

    .line 95
    .line 96
    invoke-interface {p0, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    :cond_1
    return-object p0
.end method

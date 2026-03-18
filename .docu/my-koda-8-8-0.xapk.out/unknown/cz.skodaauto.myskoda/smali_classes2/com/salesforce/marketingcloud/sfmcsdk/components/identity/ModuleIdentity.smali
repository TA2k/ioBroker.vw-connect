.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0004\n\u0002\u0010%\n\u0002\u0008\u000f\n\u0002\u0018\u0002\n\u0002\u0010$\n\u0002\u0008\u0003\u0008&\u0018\u00002\u00020\u0001B\u0015\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0002\u0010\u0006J\u001e\u0010\u0019\u001a\u00020\u001a2\u0014\u0010\u000b\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u001bH&J\u0006\u0010\u001c\u001a\u00020\u001aJ\u0008\u0010\u001d\u001a\u00020\u0005H\u0016R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008R@\u0010\u000b\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00010\n2\u0014\u0010\t\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00010\n@FX\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u000c\u0010\r\"\u0004\u0008\u000e\u0010\u000fR(\u0010\u0010\u001a\u0004\u0018\u00010\u00052\u0008\u0010\t\u001a\u0004\u0018\u00010\u0005@FX\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0011\u0010\u0008\"\u0004\u0008\u0012\u0010\u0013R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015R(\u0010\u0016\u001a\u0004\u0018\u00010\u00052\u0008\u0010\t\u001a\u0004\u0018\u00010\u0005@FX\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0017\u0010\u0008\"\u0004\u0008\u0018\u0010\u0013\u00a8\u0006\u001e"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;",
        "",
        "moduleName",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
        "applicationId",
        "",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;Ljava/lang/String;)V",
        "getApplicationId",
        "()Ljava/lang/String;",
        "value",
        "",
        "customProperties",
        "getCustomProperties",
        "()Ljava/util/Map;",
        "setCustomProperties",
        "(Ljava/util/Map;)V",
        "installationId",
        "getInstallationId",
        "setInstallationId",
        "(Ljava/lang/String;)V",
        "getModuleName",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
        "profileId",
        "getProfileId",
        "setProfileId",
        "customPropertiesToJson",
        "Lorg/json/JSONObject;",
        "",
        "toJson",
        "toString",
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


# instance fields
.field private final applicationId:Ljava/lang/String;

.field private customProperties:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field

.field private installationId:Ljava/lang/String;

.field private final moduleName:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

.field private profileId:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "moduleName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "applicationId"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->moduleName:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->applicationId:Ljava/lang/String;

    .line 17
    .line 18
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 19
    .line 20
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->customProperties:Ljava/util/Map;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public abstract customPropertiesToJson(Ljava/util/Map;)Lorg/json/JSONObject;
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
.end method

.method public final getApplicationId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->applicationId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCustomProperties()Ljava/util/Map;
    .locals 0
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->customProperties:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getInstallationId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->installationId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getModuleName()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->moduleName:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getProfileId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->profileId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setCustomProperties(Ljava/util/Map;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->customProperties:Ljava/util/Map;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->customProperties:Ljava/util/Map;

    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public final setInstallationId(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->installationId:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->installationId:Ljava/lang/String;

    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public final setProfileId(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->profileId:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->profileId:Ljava/lang/String;

    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public final toJson()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "profileId"

    .line 7
    .line 8
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->profileId:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    const-string v1, "applicationId"

    .line 14
    .line 15
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->applicationId:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    const-string v1, "installationId"

    .line 21
    .line 22
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->installationId:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->customProperties:Ljava/util/Map;

    .line 28
    .line 29
    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->customPropertiesToJson(Ljava/util/Map;)Lorg/json/JSONObject;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v1, "customProperties"

    .line 34
    .line 35
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 36
    .line 37
    .line 38
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->toJson()Lorg/json/JSONObject;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "toString(...)"

    .line 10
    .line 11
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

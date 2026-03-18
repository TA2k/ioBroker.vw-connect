.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000Z\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0004\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010$\n\u0002\u0008\n\n\u0002\u0010 \n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0008\n\u0002\u0010%\n\u0002\u0008\t\u0018\u0000 ?2\u00020\u0001:\u0001?B\u0011\u0008\u0002\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J-\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0006\u001a\u00020\u00022\u0014\u0008\u0002\u0010\t\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00080\u0007\"\u00020\u0008H\u0007\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ!\u0010\u000b\u001a\u00020\n2\u0012\u0010\u000e\u001a\u000e\u0012\u0004\u0012\u00020\u0008\u0012\u0004\u0012\u00020\u00020\r\u00a2\u0006\u0004\u0008\u000b\u0010\u000fJ7\u0010\u0012\u001a\u00020\n2\u0006\u0010\u0010\u001a\u00020\u00022\u0008\u0010\u0011\u001a\u0004\u0018\u00010\u00022\u0014\u0008\u0002\u0010\t\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00080\u0007\"\u00020\u0008H\u0007\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J;\u0010\u0015\u001a\u00020\n2\u0014\u0010\u0014\u001a\u0010\u0012\u0004\u0012\u00020\u0002\u0012\u0006\u0012\u0004\u0018\u00010\u00020\r2\u0014\u0008\u0002\u0010\t\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00080\u0007\"\u00020\u0008H\u0007\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J-\u0010\u0017\u001a\u00020\n2\u0006\u0010\u0010\u001a\u00020\u00022\u0014\u0008\u0002\u0010\t\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00080\u0007\"\u00020\u0008H\u0007\u00a2\u0006\u0004\u0008\u0017\u0010\u000cJ3\u0010\u001a\u001a\u00020\n2\u000c\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u00182\u0014\u0008\u0002\u0010\t\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00080\u0007\"\u00020\u0008H\u0007\u00a2\u0006\u0004\u0008\u001a\u0010\u001bJG\u0010\u001e\u001a\u00020\n2\u0006\u0010\u001c\u001a\u00020\u00022\u0014\u0010\u0014\u001a\u0010\u0012\u0004\u0012\u00020\u0002\u0012\u0006\u0012\u0004\u0018\u00010\u00020\r2\u0006\u0010\u001d\u001a\u00020\u00082\u0012\u0010\t\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00080\u0007\"\u00020\u0008\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ1\u0010\u001e\u001a\u00020\n2\u0006\u0010!\u001a\u00020 2\u0006\u0010\u001d\u001a\u00020\u00082\u0012\u0010\t\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00080\u0007\"\u00020\u0008\u00a2\u0006\u0004\u0008\u001e\u0010\"J!\u0010\u001e\u001a\u00020\n2\u0012\u0010#\u001a\u000e\u0012\u0004\u0012\u00020\u0008\u0012\u0004\u0012\u00020 0\r\u00a2\u0006\u0004\u0008\u001e\u0010\u000fJ\u0017\u0010(\u001a\u00020\n2\u0006\u0010%\u001a\u00020$H\u0000\u00a2\u0006\u0004\u0008&\u0010\'J\r\u0010*\u001a\u00020)\u00a2\u0006\u0004\u0008*\u0010+J\u000f\u0010,\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008,\u0010-J\u0019\u0010/\u001a\u00020.2\u0008\u0010\u0011\u001a\u0004\u0018\u00010\u0001H\u0002\u00a2\u0006\u0004\u0008/\u00100J\u0019\u00101\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0010\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u00081\u00102R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u00103\u001a\u0004\u00084\u0010-R\u001a\u00105\u001a\u00020\u00028\u0006X\u0086D\u00a2\u0006\u000c\n\u0004\u00085\u00103\u001a\u0004\u00086\u0010-R \u00108\u001a\u000e\u0012\u0004\u0012\u00020\u0008\u0012\u0004\u0012\u00020$078\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00088\u00109R\u001a\u0010:\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u00188\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008:\u0010;R\u001d\u0010>\u001a\u000e\u0012\u0004\u0012\u00020\u0008\u0012\u0004\u0012\u00020$0\r8F\u00a2\u0006\u0006\u001a\u0004\u0008<\u0010=\u00a8\u0006@"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;",
        "",
        "",
        "registrationId",
        "<init>",
        "(Ljava/lang/String;)V",
        "id",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
        "modules",
        "Llx0/b0;",
        "setProfileId",
        "(Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V",
        "",
        "ids",
        "(Ljava/util/Map;)V",
        "key",
        "value",
        "setProfileAttribute",
        "(Ljava/lang/String;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V",
        "attributes",
        "setProfileAttributes",
        "(Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V",
        "clearProfileAttribute",
        "",
        "keys",
        "clearProfileAttributes",
        "(Ljava/util/List;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V",
        "profileId",
        "module",
        "setProfile",
        "(Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;",
        "profile",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V",
        "identities",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;",
        "moduleIdentity",
        "setModuleIdentity$sfmcsdk_release",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;)V",
        "setModuleIdentity",
        "Lorg/json/JSONObject;",
        "toJson",
        "()Lorg/json/JSONObject;",
        "toString",
        "()Ljava/lang/String;",
        "",
        "isValidEventAttributeValue",
        "(Ljava/lang/Object;)Z",
        "validatedEventAttributeKey",
        "(Ljava/lang/String;)Ljava/lang/String;",
        "Ljava/lang/String;",
        "getRegistrationId",
        "platform",
        "getPlatform",
        "",
        "_moduleIdentities",
        "Ljava/util/Map;",
        "reservedKeys",
        "Ljava/util/List;",
        "getModuleIdentities",
        "()Ljava/util/Map;",
        "moduleIdentities",
        "Companion",
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


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;

.field private static final TAG:Ljava/lang/String; = "~$Identity"

.field private static _instance:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;


# instance fields
.field private final _moduleIdentities:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;",
            ">;"
        }
    .end annotation
.end field

.field private final platform:Ljava/lang/String;

.field private final registrationId:Ljava/lang/String;

.field private final reservedKeys:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;)V
    .locals 9

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->registrationId:Ljava/lang/String;

    .line 4
    const-string p1, "Android"

    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->platform:Ljava/lang/String;

    .line 5
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    .line 6
    const-string v7, "latitude"

    .line 7
    const-string v8, "longitude"

    const-string v0, "deviceid"

    const-string v1, "userid"

    const-string v2, "eventid"

    const-string v3, "sessionid"

    const-string v4, "datetime"

    const-string v5, "eventtype"

    const-string v6, "category"

    filled-new-array/range {v0 .. v8}, [Ljava/lang/String;

    move-result-object p1

    .line 8
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->reservedKeys:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;-><init>(Ljava/lang/String;)V

    return-void
.end method

.method public static final synthetic access$get_instance$cp()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_instance:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$get_moduleIdentities$p(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$set_instance$cp(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V
    .locals 0

    .line 1
    sput-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_instance:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 2
    .line 3
    return-void
.end method

.method public static synthetic clearProfileAttribute$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->values()[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    :cond_0
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->clearProfileAttribute(Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public static synthetic clearProfileAttributes$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/util/List;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->values()[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    :cond_0
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->clearProfileAttributes(Ljava/util/List;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method private final isValidEventAttributeValue(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of p0, p1, Ljava/lang/Number;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    move p0, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    instance-of p0, p1, Ljava/lang/Boolean;

    .line 9
    .line 10
    :goto_0
    if-eqz p0, :cond_1

    .line 11
    .line 12
    move p0, v0

    .line 13
    goto :goto_1

    .line 14
    :cond_1
    instance-of p0, p1, Ljava/lang/String;

    .line 15
    .line 16
    :goto_1
    if-eqz p0, :cond_2

    .line 17
    .line 18
    move p0, v0

    .line 19
    goto :goto_2

    .line 20
    :cond_2
    instance-of p0, p1, Ljava/lang/Character;

    .line 21
    .line 22
    :goto_2
    if-eqz p0, :cond_3

    .line 23
    .line 24
    goto :goto_3

    .line 25
    :cond_3
    if-nez p1, :cond_4

    .line 26
    .line 27
    goto :goto_3

    .line 28
    :cond_4
    const/4 v0, 0x0

    .line 29
    :goto_3
    return v0
.end method

.method public static synthetic setProfileAttribute$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/lang/String;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p4, p4, 0x4

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->values()[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 6
    .line 7
    .line 8
    move-result-object p3

    .line 9
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttribute(Ljava/lang/String;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public static synthetic setProfileAttributes$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->values()[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    :cond_0
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttributes(Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public static synthetic setProfileId$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->values()[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    :cond_0
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileId(Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method private final validatedEventAttributeKey(Ljava/lang/String;)Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->reservedKeys:Ljava/util/List;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ljava/lang/Iterable;

    .line 5
    .line 6
    const/4 v5, 0x0

    .line 7
    const/16 v6, 0x3e

    .line 8
    .line 9
    const-string v2, ","

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v4, 0x0

    .line 13
    invoke-static/range {v1 .. v6}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {p1}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const-string v4, "~$Identity"

    .line 30
    .line 31
    if-eqz v2, :cond_0

    .line 32
    .line 33
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 34
    .line 35
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$validatedEventAttributeKey$1;

    .line 36
    .line 37
    invoke-direct {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$validatedEventAttributeKey$1;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, v4, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Lay0/a;)V

    .line 41
    .line 42
    .line 43
    return-object v3

    .line 44
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->reservedKeys:Ljava/util/List;

    .line 45
    .line 46
    sget-object v2, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 47
    .line 48
    const-string v5, "US"

    .line 49
    .line 50
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1, v2}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    const-string v5, "this as java.lang.String).toLowerCase(locale)"

    .line 58
    .line 59
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-interface {p0, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-eqz p0, :cond_1

    .line 67
    .line 68
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 69
    .line 70
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$validatedEventAttributeKey$2;

    .line 71
    .line 72
    invoke-direct {v1, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$validatedEventAttributeKey$2;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0, v4, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Lay0/a;)V

    .line 76
    .line 77
    .line 78
    return-object v3

    .line 79
    :cond_1
    invoke-virtual {p1, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-nez p0, :cond_2

    .line 84
    .line 85
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 86
    .line 87
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$validatedEventAttributeKey$3;

    .line 88
    .line 89
    invoke-direct {v0, p1, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$validatedEventAttributeKey$3;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {p0, v4, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Lay0/a;)V

    .line 93
    .line 94
    .line 95
    :cond_2
    return-object v1
.end method


# virtual methods
.method public final clearProfileAttribute(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "key"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    const/4 v1, 0x2

    invoke-static {p0, p1, v0, v1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->clearProfileAttribute$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V

    return-void
.end method

.method public final varargs clearProfileAttribute(Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modules"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Llx0/l;

    const-string v1, ""

    invoke-direct {v0, p1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 3
    invoke-static {v0}, Lmx0/x;->l(Llx0/l;)Ljava/util/Map;

    move-result-object p1

    array-length v0, p2

    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttributes(Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    return-void
.end method

.method public final clearProfileAttributes(Ljava/util/List;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "keys"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    const/4 v1, 0x2

    invoke-static {p0, p1, v0, v1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->clearProfileAttributes$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/util/List;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V

    return-void
.end method

.method public final varargs clearProfileAttributes(Ljava/util/List;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;[",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
            ")V"
        }
    .end annotation

    const-string v0, "keys"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modules"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    check-cast p1, Ljava/lang/Iterable;

    const/16 v0, 0xa

    .line 3
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-static {v0}, Lmx0/x;->k(I)I

    move-result v0

    const/16 v1, 0x10

    if-ge v0, v1, :cond_0

    move v0, v1

    .line 4
    :cond_0
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1, v0}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 5
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    .line 6
    check-cast v0, Ljava/lang/String;

    .line 7
    const-string v2, ""

    .line 8
    invoke-interface {v1, v0, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    .line 9
    :cond_1
    array-length p1, p2

    invoke-static {p2, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    invoke-virtual {p0, v1, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttributes(Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    return-void
.end method

.method public final getModuleIdentities()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPlatform()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->platform:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRegistrationId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->registrationId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setModuleIdentity$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;)V
    .locals 2

    .line 1
    const-string v0, "moduleIdentity"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    .line 10
    .line 11
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->getModuleName()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-interface {p0, v1, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    .line 17
    .line 18
    monitor-exit v0

    .line 19
    return-void

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    monitor-exit v0

    .line 22
    throw p0
.end method

.method public final varargs setProfile(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V
    .locals 6

    const-string v0, "profile"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "module"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modules"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 3
    invoke-interface {v0, p2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    array-length v1, p3

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    aget-object v3, p3, v2

    .line 5
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v5

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_0

    .line 6
    invoke-interface {v0, v3, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 7
    :cond_1
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfile(Ljava/util/Map;)V

    return-void
.end method

.method public final varargs setProfile(Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
            "[",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
            ")V"
        }
    .end annotation

    const-string v0, "profileId"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "attributes"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "module"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modules"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;

    invoke-direct {v0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    array-length p1, p4

    invoke-static {p4, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    invoke-virtual {p0, v0, p3, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfile(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    return-void
.end method

.method public final setProfile(Ljava/util/Map;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;",
            ">;)V"
        }
    .end annotation

    const-string v0, "identities"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    monitor-enter v0

    .line 9
    :try_start_0
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map$Entry;

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    invoke-interface {v2, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    if-eqz v2, :cond_0

    .line 11
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;->getProfileId()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->setProfileId(Ljava/lang/String;)V

    .line 12
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->getCustomProperties()Ljava/util/Map;

    move-result-object v2

    const-string v3, "attributes"

    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Profile;->getAttributes()Ljava/util/Map;

    move-result-object v1

    invoke-static {v1}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    move-result-object v1

    invoke-interface {v2, v3, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 13
    :cond_1
    monitor-exit v0

    .line 14
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->identityEvent$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    if-eqz p0, :cond_2

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->track()V

    :cond_2
    return-void

    .line 15
    :goto_1
    monitor-exit v0

    throw p0
.end method

.method public final setProfileAttribute(Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    .line 1
    const-string v0, "key"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x4

    const/4 v6, 0x0

    const/4 v4, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttribute$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/lang/String;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V

    return-void
.end method

.method public final varargs setProfileAttribute(Ljava/lang/String;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modules"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Llx0/l;

    invoke-direct {v0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 3
    invoke-static {v0}, Lmx0/x;->l(Llx0/l;)Ljava/util/Map;

    move-result-object p1

    array-length p2, p3

    invoke-static {p3, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttributes(Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    return-void
.end method

.method public final setProfileAttributes(Ljava/util/Map;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "attributes"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    const/4 v1, 0x2

    invoke-static {p0, p1, v0, v1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttributes$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V

    return-void
.end method

.method public final varargs setProfileAttributes(Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;[",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
            ")V"
        }
    .end annotation

    const-string v0, "attributes"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modules"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    monitor-enter v0

    .line 3
    :try_start_0
    array-length v1, p2

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    aget-object v3, p2, v2

    .line 4
    iget-object v4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    invoke-interface {v4, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    if-eqz v3, :cond_0

    .line 5
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->getCustomProperties()Ljava/util/Map;

    move-result-object v3

    const-string v4, "attributes"

    invoke-interface {v3, v4, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p0

    goto :goto_2

    :cond_0
    :goto_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 6
    :cond_1
    monitor-exit v0

    .line 7
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->identityEvent$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    if-eqz p0, :cond_2

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->track()V

    :cond_2
    return-void

    .line 8
    :goto_2
    monitor-exit v0

    throw p0
.end method

.method public final setProfileId(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    const/4 v1, 0x2

    invoke-static {p0, p1, v0, v1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileId$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;ILjava/lang/Object;)V

    return-void
.end method

.method public final varargs setProfileId(Ljava/lang/String;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V
    .locals 4

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modules"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 3
    array-length v1, p2

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    aget-object v3, p2, v2

    .line 4
    invoke-interface {v0, v3, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 5
    :cond_0
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileId(Ljava/util/Map;)V

    return-void
.end method

.method public final setProfileId(Ljava/util/Map;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    const-string v0, "ids"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    monitor-enter v0

    .line 7
    :try_start_0
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    .line 8
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map$Entry;

    .line 9
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-static {v2}, Lcom/salesforce/marketingcloud/sfmcsdk/util/SFMCExtension;->getValidContactKey(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_0

    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->getModuleIdentities()Ljava/util/Map;

    move-result-object v3

    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v3, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->setProfileId(Ljava/lang/String;)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 11
    :cond_2
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->identityEvent$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    move-result-object p0

    if-eqz p0, :cond_3

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;->track()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    :cond_3
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0

    throw p0
.end method

.method public final toJson()Lorg/json/JSONObject;
    .locals 5

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "platform"

    .line 7
    .line 8
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->platform:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    const-string v1, "registrationId"

    .line 14
    .line 15
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->registrationId:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    new-instance v1, Lorg/json/JSONObject;

    .line 21
    .line 22
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->_moduleIdentities:Ljava/util/Map;

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_0

    .line 40
    .line 41
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Ljava/util/Map$Entry;

    .line 46
    .line 47
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    check-cast v3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 52
    .line 53
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    sget-object v4, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 58
    .line 59
    invoke-virtual {v3, v4}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    const-string v4, "this as java.lang.String).toLowerCase(Locale.ROOT)"

    .line 64
    .line 65
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    check-cast v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    .line 73
    .line 74
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;->toJson()Lorg/json/JSONObject;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    invoke-virtual {v1, v3, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_0
    const-string p0, "moduleIdentities"

    .line 83
    .line 84
    invoke-virtual {v0, p0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 85
    .line 86
    .line 87
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->toJson()Lorg/json/JSONObject;

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

.class public final Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0011\n\u0002\u0008\u0003\u0008\u00c0\u0002\u0018\u00002\u00020\u0001J\u001e\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0082 \u00a2\u0006\u0004\u0008\u0005\u0010\u0006\u00a8\u0006\u0007"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;",
        "",
        "",
        "environment",
        "",
        "getConfigurationSecrets",
        "(Ljava/lang/String;)[Ljava/lang/String;",
        "salesforce_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final a:Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;

.field public static b:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;->a:Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;

    .line 7
    .line 8
    return-void
.end method

.method private final native getConfigurationSecrets(Ljava/lang/String;)[Ljava/lang/String;
.end method


# virtual methods
.method public final a(Lcm0/b;)Lxp0/a;
    .locals 4

    .line 1
    const-string v0, "environment"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-boolean v0, Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;->b:Z

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const-string v0, "salesforce_notifications_configurations"

    .line 12
    .line 13
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    sput-boolean v1, Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;->b:Z

    .line 17
    .line 18
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const-string v0, "toLowerCase(...)"

    .line 29
    .line 30
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-direct {p0, p1}, Lcz/skodaauto/myskoda/library/salesforce/system/SalesforceConfigurationResource;->getConfigurationSecrets(Ljava/lang/String;)[Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    new-instance p1, Lxp0/a;

    .line 38
    .line 39
    const/4 v0, 0x0

    .line 40
    aget-object v0, p0, v0

    .line 41
    .line 42
    aget-object v1, p0, v1

    .line 43
    .line 44
    const/4 v2, 0x2

    .line 45
    aget-object v2, p0, v2

    .line 46
    .line 47
    const/4 v3, 0x3

    .line 48
    aget-object p0, p0, v3

    .line 49
    .line 50
    invoke-direct {p1, v0, v1, v2, p0}, Lxp0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    return-object p1
.end method

.class public final Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm0/d;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0011\n\u0002\u0008\u0003\u0008\u0000\u0018\u00002\u00020\u0001J\u001e\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0082 \u00a2\u0006\u0004\u0008\u0005\u0010\u0006\u00a8\u0006\u0007"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;",
        "Ldm0/d;",
        "",
        "environment",
        "",
        "getConfiguration",
        "(Ljava/lang/String;)[Ljava/lang/String;",
        "networking_release"
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
.field public static final b:Lcm0/a;


# instance fields
.field public a:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcm0/a;

    .line 2
    .line 3
    const-string v1, "https://simplyclever.com"

    .line 4
    .line 5
    const-string v2, "0123456789abcdef"

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lcm0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;->b:Lcm0/a;

    .line 11
    .line 12
    return-void
.end method

.method private final native getConfiguration(Ljava/lang/String;)[Ljava/lang/String;
.end method


# virtual methods
.method public final a(Lcm0/b;)Lcm0/a;
    .locals 3

    .line 1
    const-string v0, "environment"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;->a:Z

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x1

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    :try_start_0
    const-string v0, "cert_store_configuration"

    .line 13
    .line 14
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iput-boolean v2, p0, Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;->a:Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catch_0
    move-exception p1

    .line 21
    new-instance v0, Lac0/b;

    .line 22
    .line 23
    const/16 v2, 0x9

    .line 24
    .line 25
    invoke-direct {v0, v2, p1}, Lac0/b;-><init>(ILjava/lang/Exception;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v1, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 29
    .line 30
    .line 31
    sget-object p0, Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;->b:Lcm0/a;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_0
    :goto_0
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 39
    .line 40
    invoke-virtual {p1, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    const-string v0, "toLowerCase(...)"

    .line 45
    .line 46
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-direct {p0, p1}, Lcz/skodaauto/myskoda/library/networking/system/JniCertStoreConfigurationResource;->getConfiguration(Ljava/lang/String;)[Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    const/4 p1, 0x0

    .line 54
    aget-object v0, p0, p1

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-lez v0, :cond_1

    .line 61
    .line 62
    aget-object v0, p0, v2

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-lez v0, :cond_1

    .line 69
    .line 70
    new-instance v0, Lcm0/a;

    .line 71
    .line 72
    aget-object p1, p0, p1

    .line 73
    .line 74
    aget-object p0, p0, v2

    .line 75
    .line 76
    invoke-direct {v0, p1, p0}, Lcm0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return-object v0

    .line 80
    :cond_1
    return-object v1
.end method

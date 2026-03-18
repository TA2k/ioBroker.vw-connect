.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000h\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u0011\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0008\u0011\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0018\u0000 <2\u00020\u0001:\u0001<B-\u0008\u0000\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\n\u0008\u0002\u0010\t\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u001d\u0010\u0011\u001a\u00020\u00102\u0006\u0010\r\u001a\u00020\u000c2\u0006\u0010\u000f\u001a\u00020\u000e\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J\u0015\u0010\u0014\u001a\u00020\u00132\u0006\u0010\r\u001a\u00020\u000c\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u0017\u0010\u0017\u001a\u00020\u00132\u0006\u0010\r\u001a\u00020\u000cH\u0001\u00a2\u0006\u0004\u0008\u0016\u0010\u0015J\u0017\u0010\u001d\u001a\u00020\u001a2\u0006\u0010\u0019\u001a\u00020\u0018H\u0000\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ!\u0010 \u001a\u00020\u001a2\u0012\u0010\u001f\u001a\n\u0012\u0006\u0008\u0001\u0012\u00020\u00180\u001e\"\u00020\u0018\u00a2\u0006\u0004\u0008 \u0010!J\u0017\u0010%\u001a\u00020\"2\u0006\u0010\u0019\u001a\u00020\u0018H\u0001\u00a2\u0006\u0004\u0008#\u0010$J\u0017\u0010\'\u001a\u00020\"2\u0006\u0010\u0019\u001a\u00020\u0018H\u0001\u00a2\u0006\u0004\u0008&\u0010$J!\u0010+\u001a\u00020\u00102\u0006\u0010\r\u001a\u00020\u000c2\u0008\u0008\u0002\u0010(\u001a\u00020\"H\u0001\u00a2\u0006\u0004\u0008)\u0010*J\u001f\u0010/\u001a\u00020\u00102\u0006\u0010\r\u001a\u00020\u000c2\u0006\u0010,\u001a\u00020\u0013H\u0001\u00a2\u0006\u0004\u0008-\u0010.R\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u00100R\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u00101R\u0014\u0010\u0007\u001a\u00020\u00068\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0007\u00102R\u0016\u0010\t\u001a\u0004\u0018\u00010\u00088\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\t\u00103R,\u00106\u001a\u000e\u0012\u0004\u0012\u00020\u0018\u0012\u0004\u0012\u000205048\u0000X\u0081\u0004\u00a2\u0006\u0012\n\u0004\u00086\u00107\u0012\u0004\u0008:\u0010;\u001a\u0004\u00088\u00109\u00a8\u0006="
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;",
        "",
        "Landroid/content/Context;",
        "context",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;",
        "executors",
        "Landroid/content/SharedPreferences;",
        "networkPreferences",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;",
        "authenticator",
        "<init>",
        "(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;Landroid/content/SharedPreferences;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;",
        "request",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;",
        "callback",
        "Llx0/b0;",
        "executeAsync",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;",
        "executeSync",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;",
        "makeRequest$sfmcsdk_release",
        "makeRequest",
        "",
        "requestName",
        "",
        "isBlockedByRetryAfter$sfmcsdk_release",
        "(Ljava/lang/String;)Z",
        "isBlockedByRetryAfter",
        "",
        "requestNames",
        "canMakeRequest",
        "([Ljava/lang/String;)Z",
        "",
        "serverRetryAfterTime$sfmcsdk_release",
        "(Ljava/lang/String;)J",
        "serverRetryAfterTime",
        "deviceRetryAfterTime$sfmcsdk_release",
        "deviceRetryAfterTime",
        "timestamp",
        "recordDeviceRetryAfter$sfmcsdk_release",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;J)V",
        "recordDeviceRetryAfter",
        "response",
        "recordRetryAfter$sfmcsdk_release",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;)V",
        "recordRetryAfter",
        "Landroid/content/Context;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;",
        "Landroid/content/SharedPreferences;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;",
        "",
        "Ljava/util/concurrent/atomic/AtomicBoolean;",
        "requestsInFlight",
        "Ljava/util/Map;",
        "getRequestsInFlight$sfmcsdk_release",
        "()Ljava/util/Map;",
        "getRequestsInFlight$sfmcsdk_release$annotations",
        "()V",
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
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;

.field public static final MAX_SERVER_RETRY:J = 0x5265c00L

.field public static final TAG:Ljava/lang/String; = "~$NetworkManager"


# instance fields
.field private final authenticator:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;

.field private final context:Landroid/content/Context;

.field private final executors:Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;

.field private final networkPreferences:Landroid/content/SharedPreferences;

.field private final requestsInFlight:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/concurrent/atomic/AtomicBoolean;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;Landroid/content/SharedPreferences;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;)V
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "executors"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "networkPreferences"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->context:Landroid/content/Context;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->executors:Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->networkPreferences:Landroid/content/SharedPreferences;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->authenticator:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;

    .line 6
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    return-void
.end method

.method public synthetic constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;Landroid/content/SharedPreferences;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    const/4 p4, 0x0

    .line 7
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;Landroid/content/SharedPreferences;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;)V

    return-void
.end method

.method public static synthetic getRequestsInFlight$sfmcsdk_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic recordDeviceRetryAfter$sfmcsdk_release$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;JILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p4, p4, 0x2

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 6
    .line 7
    .line 8
    move-result-wide p2

    .line 9
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->recordDeviceRetryAfter$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;J)V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final varargs canMakeRequest([Ljava/lang/String;)Z
    .locals 4

    .line 1
    const-string v0, "requestNames"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->context:Landroid/content/Context;

    .line 7
    .line 8
    invoke-static {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/util/NetworkUtils;->hasConnectivity(Landroid/content/Context;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    return v1

    .line 16
    :cond_0
    array-length v0, p1

    .line 17
    move v2, v1

    .line 18
    :goto_0
    if-ge v2, v0, :cond_2

    .line 19
    .line 20
    aget-object v3, p1, v2

    .line 21
    .line 22
    invoke-virtual {p0, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->isBlockedByRetryAfter$sfmcsdk_release(Ljava/lang/String;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_1

    .line 27
    .line 28
    return v1

    .line 29
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    const/4 p0, 0x1

    .line 33
    return p0
.end method

.method public final deviceRetryAfterTime$sfmcsdk_release(Ljava/lang/String;)J
    .locals 2

    .line 1
    const-string v0, "requestName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->networkPreferences:Landroid/content/SharedPreferences;

    .line 7
    .line 8
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;->getDeviceRetryKey$sfmcsdk_release(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-wide/16 v0, 0x0

    .line 15
    .line 16
    invoke-interface {p0, p1, v0, v1}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    return-wide p0
.end method

.method public final executeAsync(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;)V
    .locals 2

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "callback"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->executors:Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;

    .line 12
    .line 13
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;->getNetworkIO()Ljava/util/concurrent/ExecutorService;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;

    .line 18
    .line 19
    invoke-direct {v1, p2, p1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeAsync$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Callback;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;)V

    .line 20
    .line 21
    .line 22
    const-string p0, "network_manager_execute"

    .line 23
    .line 24
    invoke-static {v0, p0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutorsKt;->namedRunnable(Ljava/util/concurrent/ExecutorService;Ljava/lang/String;Lay0/a;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final executeSync(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;
    .locals 12

    .line 1
    const-string v1, "~$NetworkManager"

    .line 2
    .line 3
    const-string v0, "Too many requests. "

    .line 4
    .line 5
    const-string v2, "request"

    .line 6
    .line 7
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance v2, Lkotlin/jvm/internal/f0;

    .line 11
    .line 12
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    :try_start_0
    iget-object v4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 19
    .line 20
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-interface {v4, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Ljava/util/concurrent/atomic/AtomicBoolean;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_2

    .line 29
    .line 30
    const/16 v4, 0x1ad

    .line 31
    .line 32
    const/4 v5, 0x1

    .line 33
    if-eqz p1, :cond_1

    .line 34
    .line 35
    :try_start_1
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 36
    .line 37
    .line 38
    move-result v6

    .line 39
    if-nez v6, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_2

    .line 47
    .line 48
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;

    .line 49
    .line 50
    iget-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 53
    .line 54
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    new-instance v5, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v0, " request already in-flight"

    .line 67
    .line 68
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-virtual {p1, v0, v4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;->error$sfmcsdk_release(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 76
    .line 77
    .line 78
    move-result-object p0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 79
    return-object p0

    .line 80
    :catch_0
    move-exception v0

    .line 81
    move-object p1, v0

    .line 82
    move-object v6, p0

    .line 83
    goto/16 :goto_2

    .line 84
    .line 85
    :cond_1
    :goto_0
    :try_start_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 86
    .line 87
    iget-object v6, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 90
    .line 91
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    new-instance v7, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 96
    .line 97
    invoke-direct {v7, v5}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 98
    .line 99
    .line 100
    invoke-interface {p1, v6, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    :cond_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 104
    .line 105
    iget-object v6, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 108
    .line 109
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    invoke-interface {p1, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    check-cast p1, Ljava/util/concurrent/atomic/AtomicBoolean;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 118
    .line 119
    if-eqz p1, :cond_3

    .line 120
    .line 121
    :try_start_3
    invoke-virtual {p1, v5}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    .line 122
    .line 123
    .line 124
    :cond_3
    :try_start_4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->context:Landroid/content/Context;

    .line 125
    .line 126
    invoke-static {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/util/NetworkUtils;->hasConnectivity(Landroid/content/Context;)Z

    .line 127
    .line 128
    .line 129
    move-result p1
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_2

    .line 130
    if-nez p1, :cond_5

    .line 131
    .line 132
    :try_start_5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 133
    .line 134
    iget-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 137
    .line 138
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    check-cast p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 147
    .line 148
    if-eqz p1, :cond_4

    .line 149
    .line 150
    invoke-virtual {p1, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 151
    .line 152
    .line 153
    :cond_4
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;

    .line 154
    .line 155
    const-string v0, "Device has no network connectivity"

    .line 156
    .line 157
    const/16 v4, 0x257

    .line 158
    .line 159
    invoke-virtual {p1, v0, v4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;->error$sfmcsdk_release(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 160
    .line 161
    .line 162
    move-result-object p0
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0

    .line 163
    return-object p0

    .line 164
    :cond_5
    :try_start_6
    iget-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 167
    .line 168
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->isBlockedByRetryAfter$sfmcsdk_release(Ljava/lang/String;)Z

    .line 173
    .line 174
    .line 175
    move-result p1
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_2

    .line 176
    if-eqz p1, :cond_7

    .line 177
    .line 178
    :try_start_7
    iget-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 179
    .line 180
    iget-object v5, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 183
    .line 184
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v5

    .line 188
    invoke-interface {p1, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    check-cast p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 193
    .line 194
    if-eqz p1, :cond_6

    .line 195
    .line 196
    invoke-virtual {p1, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 197
    .line 198
    .line 199
    :cond_6
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;

    .line 200
    .line 201
    iget-object v5, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 204
    .line 205
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v5

    .line 209
    new-instance v6, Ljava/lang/StringBuilder;

    .line 210
    .line 211
    invoke-direct {v6, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    const-string v0, " request aborted."

    .line 218
    .line 219
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    invoke-virtual {p1, v0, v4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;->error$sfmcsdk_release(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 227
    .line 228
    .line 229
    move-result-object p0
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_0

    .line 230
    return-object p0

    .line 231
    :cond_7
    :try_start_8
    iget-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->context:Landroid/content/Context;

    .line 232
    .line 233
    invoke-static {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/util/NetworkUtils;->installProvidersIfNeeded(Landroid/content/Context;)V

    .line 234
    .line 235
    .line 236
    iget-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 237
    .line 238
    move-object v7, p1

    .line 239
    check-cast v7, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_2

    .line 240
    .line 241
    const/4 v10, 0x2

    .line 242
    const/4 v11, 0x0

    .line 243
    const-wide/16 v8, 0x0

    .line 244
    .line 245
    move-object v6, p0

    .line 246
    :try_start_9
    invoke-static/range {v6 .. v11}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->recordDeviceRetryAfter$sfmcsdk_release$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;JILjava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    iget-object p0, v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->authenticator:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;

    .line 250
    .line 251
    if-eqz p0, :cond_a

    .line 252
    .line 253
    const/4 p1, 0x0

    .line 254
    invoke-static {p0, v3, v5, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;->getAuthTokenHeader$sfmcsdk_release$default(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;ZILjava/lang/Object;)Llx0/l;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    if-nez p0, :cond_9

    .line 259
    .line 260
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;

    .line 261
    .line 262
    const-string p1, "Expectation Failed"

    .line 263
    .line 264
    const/16 v0, 0x1a1

    .line 265
    .line 266
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;->error$sfmcsdk_release(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 267
    .line 268
    .line 269
    move-result-object p0

    .line 270
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 271
    .line 272
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$authHeader$1$1;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$authHeader$1$1;

    .line 273
    .line 274
    invoke-virtual {p1, v1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Lay0/a;)V

    .line 275
    .line 276
    .line 277
    iget-object p1, v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->authenticator:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;

    .line 278
    .line 279
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;->deleteCachedToken()V

    .line 280
    .line 281
    .line 282
    iget-object p1, v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 283
    .line 284
    iget-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 287
    .line 288
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object p1

    .line 296
    check-cast p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 297
    .line 298
    if-eqz p1, :cond_8

    .line 299
    .line 300
    invoke-virtual {p1, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 301
    .line 302
    .line 303
    return-object p0

    .line 304
    :catch_1
    move-exception v0

    .line 305
    :goto_1
    move-object p1, v0

    .line 306
    goto/16 :goto_2

    .line 307
    .line 308
    :cond_8
    return-object p0

    .line 309
    :cond_9
    iget-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 312
    .line 313
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->toBuilder$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 314
    .line 315
    .line 316
    move-result-object p1

    .line 317
    iget-object v0, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 318
    .line 319
    check-cast v0, Ljava/lang/String;

    .line 320
    .line 321
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 322
    .line 323
    check-cast p0, Ljava/lang/String;

    .line 324
    .line 325
    invoke-virtual {p1, v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->addOrReplaceHeader(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 326
    .line 327
    .line 328
    move-result-object p0

    .line 329
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->build()Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 330
    .line 331
    .line 332
    move-result-object p0

    .line 333
    iput-object p0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 334
    .line 335
    :cond_a
    new-instance p0, Lkotlin/jvm/internal/f0;

    .line 336
    .line 337
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 338
    .line 339
    .line 340
    iget-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 341
    .line 342
    check-cast p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 343
    .line 344
    invoke-virtual {v6, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->makeRequest$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 345
    .line 346
    .line 347
    move-result-object p1

    .line 348
    iput-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 349
    .line 350
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->getCode()I

    .line 351
    .line 352
    .line 353
    move-result p1

    .line 354
    const/16 v0, 0x191

    .line 355
    .line 356
    if-ne p1, v0, :cond_c

    .line 357
    .line 358
    iget-object p1, v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->authenticator:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;

    .line 359
    .line 360
    if-eqz p1, :cond_c

    .line 361
    .line 362
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;->deleteCachedToken()V

    .line 363
    .line 364
    .line 365
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;->refreshAuthTokenHeader()Llx0/l;

    .line 366
    .line 367
    .line 368
    move-result-object p1

    .line 369
    if-eqz p1, :cond_c

    .line 370
    .line 371
    iget-object v4, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast v4, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 374
    .line 375
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->toBuilder$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 376
    .line 377
    .line 378
    move-result-object v4

    .line 379
    iget-object v5, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 380
    .line 381
    check-cast v5, Ljava/lang/String;

    .line 382
    .line 383
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 384
    .line 385
    check-cast p1, Ljava/lang/String;

    .line 386
    .line 387
    invoke-virtual {v4, v5, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->addOrReplaceHeader(Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;

    .line 388
    .line 389
    .line 390
    move-result-object p1

    .line 391
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request$Builder;->build()Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 392
    .line 393
    .line 394
    move-result-object p1

    .line 395
    iput-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 396
    .line 397
    invoke-virtual {v6, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->makeRequest$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 398
    .line 399
    .line 400
    move-result-object p1

    .line 401
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->getCode()I

    .line 402
    .line 403
    .line 404
    move-result v4

    .line 405
    if-ne v4, v0, :cond_b

    .line 406
    .line 407
    iget-object v0, v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->authenticator:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;

    .line 408
    .line 409
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Authenticator;->deleteCachedToken()V

    .line 410
    .line 411
    .line 412
    :cond_b
    iput-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 413
    .line 414
    :cond_c
    iget-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 415
    .line 416
    check-cast p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 417
    .line 418
    iget-object v0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 419
    .line 420
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 421
    .line 422
    invoke-virtual {v6, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->recordRetryAfter$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;)V

    .line 423
    .line 424
    .line 425
    iget-object p1, v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 426
    .line 427
    iget-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 428
    .line 429
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 430
    .line 431
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 432
    .line 433
    .line 434
    move-result-object v0

    .line 435
    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object p1

    .line 439
    check-cast p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 440
    .line 441
    if-eqz p1, :cond_d

    .line 442
    .line 443
    invoke-virtual {p1, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 444
    .line 445
    .line 446
    :cond_d
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 447
    .line 448
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;

    .line 449
    .line 450
    invoke-direct {v0, v2, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$2;-><init>(Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;)V

    .line 451
    .line 452
    .line 453
    invoke-virtual {p1, v1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V

    .line 454
    .line 455
    .line 456
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 457
    .line 458
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_1

    .line 459
    .line 460
    return-object p0

    .line 461
    :catch_2
    move-exception v0

    .line 462
    move-object v6, p0

    .line 463
    goto/16 :goto_1

    .line 464
    .line 465
    :goto_2
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 466
    .line 467
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$3;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$executeSync$3;

    .line 468
    .line 469
    invoke-virtual {p0, v1, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 470
    .line 471
    .line 472
    iget-object p0, v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 473
    .line 474
    iget-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 475
    .line 476
    check-cast p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 477
    .line 478
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 479
    .line 480
    .line 481
    move-result-object p1

    .line 482
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 483
    .line 484
    .line 485
    move-result-object p0

    .line 486
    check-cast p0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 487
    .line 488
    if-eqz p0, :cond_e

    .line 489
    .line 490
    invoke-virtual {p0, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 491
    .line 492
    .line 493
    :cond_e
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;

    .line 494
    .line 495
    iget-object p1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 496
    .line 497
    check-cast p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 498
    .line 499
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 500
    .line 501
    .line 502
    move-result-object p1

    .line 503
    iget-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 504
    .line 505
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;

    .line 506
    .line 507
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getUrl()Ljava/lang/String;

    .line 508
    .line 509
    .line 510
    move-result-object v0

    .line 511
    const-string v1, " request to "

    .line 512
    .line 513
    const-string v2, " could not be completed."

    .line 514
    .line 515
    const-string v3, "An unknown error occurred. The "

    .line 516
    .line 517
    invoke-static {v3, p1, v1, v0, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 518
    .line 519
    .line 520
    move-result-object p1

    .line 521
    const/16 v0, -0x3e7

    .line 522
    .line 523
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;->error$sfmcsdk_release(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 524
    .line 525
    .line 526
    move-result-object p0

    .line 527
    return-object p0
.end method

.method public final getRequestsInFlight$sfmcsdk_release()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/concurrent/atomic/AtomicBoolean;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isBlockedByRetryAfter$sfmcsdk_release(Ljava/lang/String;)Z
    .locals 6

    .line 1
    const-string v0, "requestName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->serverRetryAfterTime$sfmcsdk_release(Ljava/lang/String;)J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->deviceRetryAfterTime$sfmcsdk_release(Ljava/lang/String;)J

    .line 15
    .line 16
    .line 17
    move-result-wide v4

    .line 18
    cmp-long p0, v0, v2

    .line 19
    .line 20
    if-lez p0, :cond_0

    .line 21
    .line 22
    cmp-long p0, v0, v4

    .line 23
    .line 24
    if-lez p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    return p0

    .line 28
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 29
    .line 30
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$isBlockedByRetryAfter$1$1;

    .line 31
    .line 32
    invoke-direct {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$isBlockedByRetryAfter$1$1;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const-string p1, "~$NetworkManager"

    .line 36
    .line 37
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Lay0/a;)V

    .line 38
    .line 39
    .line 40
    const/4 p0, 0x1

    .line 41
    return p0
.end method

.method public final makeRequest$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;
    .locals 12

    .line 1
    const-string v0, "~$NetworkManager"

    .line 2
    .line 3
    const-string v1, "request"

    .line 4
    .line 5
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 9
    .line 10
    .line 11
    move-result-wide v1

    .line 12
    new-instance v3, Lkotlin/jvm/internal/f0;

    .line 13
    .line 14
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    :try_start_0
    new-instance v5, Ljava/net/URL;

    .line 19
    .line 20
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getUrl()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v6

    .line 24
    invoke-direct {v5, v6}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v5}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    invoke-static {v5}, Lcom/google/firebase/perf/network/FirebasePerfUrlConnection;->instrument(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    check-cast v5, Ljava/net/URLConnection;

    .line 36
    .line 37
    const-string v6, "null cannot be cast to non-null type java.net.HttpURLConnection"

    .line 38
    .line 39
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    check-cast v5, Ljava/net/HttpURLConnection;

    .line 43
    .line 44
    iput-object v5, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getMethod()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v6

    .line 50
    invoke-virtual {v5, v6}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    iget-object v5, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v5, Ljava/net/HttpURLConnection;

    .line 56
    .line 57
    const/4 v6, 0x1

    .line 58
    invoke-virtual {v5, v6}, Ljava/net/URLConnection;->setDoInput(Z)V

    .line 59
    .line 60
    .line 61
    iget-object v5, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v5, Ljava/net/HttpURLConnection;

    .line 64
    .line 65
    invoke-virtual {v5, v4}, Ljava/net/URLConnection;->setUseCaches(Z)V

    .line 66
    .line 67
    .line 68
    iget-object v5, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v5, Ljava/net/HttpURLConnection;

    .line 71
    .line 72
    invoke-virtual {v5, v4}, Ljava/net/URLConnection;->setAllowUserInteraction(Z)V

    .line 73
    .line 74
    .line 75
    iget-object v5, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v5, Ljava/net/HttpURLConnection;

    .line 78
    .line 79
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getConnectionTimeout()I

    .line 80
    .line 81
    .line 82
    move-result v7

    .line 83
    invoke-virtual {v5, v7}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getHeaders()Ljava/util/List;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 91
    .line 92
    .line 93
    move-result v5

    .line 94
    add-int/lit8 v5, v5, -0x1

    .line 95
    .line 96
    const/4 v7, 0x2

    .line 97
    invoke-static {v4, v5, v7}, Llp/o0;->b(III)I

    .line 98
    .line 99
    .line 100
    move-result v5

    .line 101
    if-ltz v5, :cond_0

    .line 102
    .line 103
    move v7, v4

    .line 104
    :goto_0
    iget-object v8, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v8, Ljava/net/HttpURLConnection;

    .line 107
    .line 108
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getHeaders()Ljava/util/List;

    .line 109
    .line 110
    .line 111
    move-result-object v9

    .line 112
    invoke-interface {v9, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v9

    .line 116
    check-cast v9, Ljava/lang/String;

    .line 117
    .line 118
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getHeaders()Ljava/util/List;

    .line 119
    .line 120
    .line 121
    move-result-object v10

    .line 122
    add-int/lit8 v11, v7, 0x1

    .line 123
    .line 124
    invoke-interface {v10, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v10

    .line 128
    check-cast v10, Ljava/lang/String;

    .line 129
    .line 130
    invoke-virtual {v8, v9, v10}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    if-eq v7, v5, :cond_0

    .line 134
    .line 135
    add-int/lit8 v7, v7, 0x2

    .line 136
    .line 137
    goto :goto_0

    .line 138
    :catchall_0
    move-exception v0

    .line 139
    goto/16 :goto_6

    .line 140
    .line 141
    :catch_0
    move-exception v1

    .line 142
    goto/16 :goto_4

    .line 143
    .line 144
    :cond_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getRequestBody()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v5

    .line 148
    if-eqz v5, :cond_1

    .line 149
    .line 150
    iget-object v7, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v7, Ljava/net/HttpURLConnection;

    .line 153
    .line 154
    invoke-virtual {v7, v6}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 155
    .line 156
    .line 157
    sget-object v6, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 158
    .line 159
    new-instance v7, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$1$1;

    .line 160
    .line 161
    invoke-direct {v7, p1, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$1$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lkotlin/jvm/internal/f0;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v6, v0, v7}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V

    .line 165
    .line 166
    .line 167
    iget-object v6, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v6, Ljava/net/HttpURLConnection;

    .line 170
    .line 171
    invoke-virtual {v6}, Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;

    .line 172
    .line 173
    .line 174
    move-result-object v6
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 175
    :try_start_1
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/RequestKt;->getUTF_8()Ljava/nio/charset/Charset;

    .line 176
    .line 177
    .line 178
    move-result-object v7

    .line 179
    invoke-virtual {v5, v7}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 180
    .line 181
    .line 182
    move-result-object v5

    .line 183
    const-string v7, "this as java.lang.String).getBytes(charset)"

    .line 184
    .line 185
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v6, v5}, Ljava/io/OutputStream;->write([B)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 189
    .line 190
    .line 191
    const/4 v5, 0x0

    .line 192
    :try_start_2
    invoke-static {v6, v5}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 193
    .line 194
    .line 195
    goto :goto_1

    .line 196
    :catchall_1
    move-exception v1

    .line 197
    :try_start_3
    throw v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 198
    :catchall_2
    move-exception v2

    .line 199
    :try_start_4
    invoke-static {v6, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 200
    .line 201
    .line 202
    throw v2

    .line 203
    :cond_1
    :goto_1
    new-instance v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;

    .line 204
    .line 205
    invoke-direct {v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;-><init>()V

    .line 206
    .line 207
    .line 208
    iget-object v6, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast v6, Ljava/net/HttpURLConnection;

    .line 211
    .line 212
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 213
    .line 214
    .line 215
    move-result v6

    .line 216
    invoke-virtual {v5, v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->code(I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;

    .line 217
    .line 218
    .line 219
    iget-object v6, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v6, Ljava/net/HttpURLConnection;

    .line 222
    .line 223
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getResponseMessage()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v6

    .line 227
    const-string v7, "getResponseMessage(...)"

    .line 228
    .line 229
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v5, v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->message(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;

    .line 233
    .line 234
    .line 235
    iget-object v6, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v6, Ljava/net/HttpURLConnection;

    .line 238
    .line 239
    invoke-virtual {v6}, Ljava/net/URLConnection;->getHeaderFields()Ljava/util/Map;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    const-string v7, "getHeaderFields(...)"

    .line 244
    .line 245
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v5, v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->headers(Ljava/util/Map;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 249
    .line 250
    .line 251
    :try_start_5
    iget-object v6, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast v6, Ljava/net/HttpURLConnection;

    .line 254
    .line 255
    invoke-virtual {v6}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 256
    .line 257
    .line 258
    move-result-object v6

    .line 259
    invoke-static {v6}, Lcom/salesforce/marketingcloud/sfmcsdk/util/FileUtilsKt;->readAll(Ljava/io/InputStream;)Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v6

    .line 263
    if-eqz v6, :cond_2

    .line 264
    .line 265
    invoke-virtual {v5, v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->body(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_1
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 266
    .line 267
    .line 268
    goto :goto_2

    .line 269
    :catch_1
    :try_start_6
    iget-object v6, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 270
    .line 271
    check-cast v6, Ljava/net/HttpURLConnection;

    .line 272
    .line 273
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 274
    .line 275
    .line 276
    move-result-object v6

    .line 277
    invoke-static {v6}, Lcom/salesforce/marketingcloud/sfmcsdk/util/FileUtilsKt;->readAll(Ljava/io/InputStream;)Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object v6

    .line 281
    if-eqz v6, :cond_2

    .line 282
    .line 283
    invoke-virtual {v5, v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->body(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;

    .line 284
    .line 285
    .line 286
    :cond_2
    :goto_2
    invoke-virtual {v5, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->startTimeMillis(J)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;

    .line 287
    .line 288
    .line 289
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 290
    .line 291
    .line 292
    move-result-wide v1

    .line 293
    invoke-virtual {v5, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->endTimeMillis(J)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;

    .line 294
    .line 295
    .line 296
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Builder;->build()Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 297
    .line 298
    .line 299
    move-result-object v1

    .line 300
    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 301
    .line 302
    new-instance v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;

    .line 303
    .line 304
    invoke-direct {v5, v1, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$3$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;)V

    .line 305
    .line 306
    .line 307
    invoke-virtual {v2, v0, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 308
    .line 309
    .line 310
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 311
    .line 312
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 313
    .line 314
    .line 315
    move-result-object p1

    .line 316
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object p0

    .line 320
    check-cast p0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 321
    .line 322
    if-eqz p0, :cond_3

    .line 323
    .line 324
    invoke-virtual {p0, v4}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 325
    .line 326
    .line 327
    :cond_3
    iget-object p0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 328
    .line 329
    check-cast p0, Ljava/net/HttpURLConnection;

    .line 330
    .line 331
    if-eqz p0, :cond_5

    .line 332
    .line 333
    :goto_3
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 334
    .line 335
    .line 336
    goto :goto_5

    .line 337
    :goto_4
    :try_start_7
    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 338
    .line 339
    sget-object v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$4;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$makeRequest$4;

    .line 340
    .line 341
    invoke-virtual {v2, v0, v1, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 342
    .line 343
    .line 344
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;

    .line 345
    .line 346
    const-string v1, "ERROR"

    .line 347
    .line 348
    const/16 v2, -0x64

    .line 349
    .line 350
    invoke-virtual {v0, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response$Companion;->error$sfmcsdk_release(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;

    .line 351
    .line 352
    .line 353
    move-result-object v1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 354
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 355
    .line 356
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object p1

    .line 360
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 361
    .line 362
    .line 363
    move-result-object p0

    .line 364
    check-cast p0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 365
    .line 366
    if-eqz p0, :cond_4

    .line 367
    .line 368
    invoke-virtual {p0, v4}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 369
    .line 370
    .line 371
    :cond_4
    iget-object p0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast p0, Ljava/net/HttpURLConnection;

    .line 374
    .line 375
    if-eqz p0, :cond_5

    .line 376
    .line 377
    goto :goto_3

    .line 378
    :cond_5
    :goto_5
    return-object v1

    .line 379
    :goto_6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->requestsInFlight:Ljava/util/Map;

    .line 380
    .line 381
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 382
    .line 383
    .line 384
    move-result-object p1

    .line 385
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object p0

    .line 389
    check-cast p0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 390
    .line 391
    if-eqz p0, :cond_6

    .line 392
    .line 393
    invoke-virtual {p0, v4}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 394
    .line 395
    .line 396
    :cond_6
    iget-object p0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 397
    .line 398
    check-cast p0, Ljava/net/HttpURLConnection;

    .line 399
    .line 400
    if-eqz p0, :cond_7

    .line 401
    .line 402
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 403
    .line 404
    .line 405
    :cond_7
    throw v0
.end method

.method public final recordDeviceRetryAfter$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;J)V
    .locals 4

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getRateLimit()J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    const-wide/16 v2, 0x0

    .line 11
    .line 12
    cmp-long v0, v0, v2

    .line 13
    .line 14
    if-lez v0, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->networkPreferences:Landroid/content/SharedPreferences;

    .line 17
    .line 18
    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;

    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;->getDeviceRetryKey$sfmcsdk_release(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getRateLimit()J

    .line 33
    .line 34
    .line 35
    move-result-wide v1

    .line 36
    add-long/2addr v1, p2

    .line 37
    invoke-interface {p0, v0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    .line 38
    .line 39
    .line 40
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 41
    .line 42
    .line 43
    :cond_0
    return-void
.end method

.method public final recordRetryAfter$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;)V
    .locals 6

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "response"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->networkPreferences:Landroid/content/SharedPreferences;

    .line 12
    .line 13
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->getEndTimeMillis()J

    .line 18
    .line 19
    .line 20
    move-result-wide v1

    .line 21
    invoke-virtual {p0, p1, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->recordDeviceRetryAfter$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;J)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->getHeaders()Ljava/util/Map;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const-string v1, "Retry-After"

    .line 29
    .line 30
    invoke-interface {p0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Ljava/util/List;

    .line 35
    .line 36
    if-eqz p0, :cond_1

    .line 37
    .line 38
    move-object v1, p0

    .line 39
    check-cast v1, Ljava/util/Collection;

    .line 40
    .line 41
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-nez v1, :cond_1

    .line 46
    .line 47
    const/4 v1, 0x0

    .line 48
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    check-cast p0, Ljava/lang/String;

    .line 53
    .line 54
    :try_start_0
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 55
    .line 56
    .line 57
    move-result-wide v1

    .line 58
    const-wide/16 v3, 0x3e8

    .line 59
    .line 60
    mul-long/2addr v1, v3

    .line 61
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;

    .line 62
    .line 63
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Request;->getName()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;->getServerRetryKey$sfmcsdk_release(Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/Response;->getEndTimeMillis()J

    .line 72
    .line 73
    .line 74
    move-result-wide p1

    .line 75
    const-wide/32 v3, 0x5265c00

    .line 76
    .line 77
    .line 78
    cmp-long v5, v1, v3

    .line 79
    .line 80
    if-lez v5, :cond_0

    .line 81
    .line 82
    move-wide v1, v3

    .line 83
    :cond_0
    add-long/2addr p1, v1

    .line 84
    invoke-interface {v0, p0, p1, p2}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    .line 85
    .line 86
    .line 87
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 88
    .line 89
    .line 90
    return-void

    .line 91
    :catch_0
    move-exception p0

    .line 92
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 93
    .line 94
    const-string p2, "~$NetworkManager"

    .line 95
    .line 96
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$recordRetryAfter$1;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$recordRetryAfter$1;

    .line 97
    .line 98
    invoke-virtual {p1, p2, p0, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 99
    .line 100
    .line 101
    :cond_1
    return-void
.end method

.method public final serverRetryAfterTime$sfmcsdk_release(Ljava/lang/String;)J
    .locals 2

    .line 1
    const-string v0, "requestName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->networkPreferences:Landroid/content/SharedPreferences;

    .line 7
    .line 8
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/http/NetworkManager$Companion;->getServerRetryKey$sfmcsdk_release(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-wide/16 v0, 0x0

    .line 15
    .line 16
    invoke-interface {p0, p1, v0, v1}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    return-wide p0
.end method

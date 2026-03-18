.class Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/i;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;
    }
.end annotation


# static fields
.field private static cloneMethod:Ljava/lang/reflect/Method;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private static final contextsByRequest:Lio/opentelemetry/instrumentation/api/util/VirtualField;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/util/VirtualField<",
            "Ld01/k0;",
            "Lio/opentelemetry/context/Context;",
            ">;"
        }
    .end annotation
.end field

.field private static timeoutMethod:Ljava/lang/reflect/Method;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# instance fields
.field private final okHttpClient:Ld01/h0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-class v0, Ld01/j;

    .line 2
    .line 3
    const-class v1, Ld01/k0;

    .line 4
    .line 5
    const-class v2, Lio/opentelemetry/context/Context;

    .line 6
    .line 7
    invoke-static {v1, v2}, Lio/opentelemetry/instrumentation/api/util/VirtualField;->find(Ljava/lang/Class;Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/util/VirtualField;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    sput-object v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->contextsByRequest:Lio/opentelemetry/instrumentation/api/util/VirtualField;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    :try_start_0
    const-string v2, "timeout"

    .line 15
    .line 16
    invoke-virtual {v0, v2, v1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    sput-object v2, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->timeoutMethod:Ljava/lang/reflect/Method;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :catch_0
    sput-object v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->timeoutMethod:Ljava/lang/reflect/Method;

    .line 24
    .line 25
    :goto_0
    :try_start_1
    const-string v2, "clone"

    .line 26
    .line 27
    invoke-virtual {v0, v2, v1}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->cloneMethod:Ljava/lang/reflect/Method;
    :try_end_1
    .catch Ljava/lang/NoSuchMethodException; {:try_start_1 .. :try_end_1} :catch_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :catch_1
    sput-object v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->cloneMethod:Ljava/lang/reflect/Method;

    .line 35
    .line 36
    :goto_1
    return-void
.end method

.method public constructor <init>(Ld01/h0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->okHttpClient:Ld01/h0;

    .line 5
    .line 6
    return-void
.end method

.method public static synthetic access$000()Ljava/lang/reflect/Method;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->cloneMethod:Ljava/lang/reflect/Method;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$100()Ljava/lang/reflect/Method;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->timeoutMethod:Ljava/lang/reflect/Method;

    .line 2
    .line 3
    return-object v0
.end method

.method public static getCallingContextForRequest(Ld01/k0;)Lio/opentelemetry/context/Context;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->contextsByRequest:Lio/opentelemetry/instrumentation/api/util/VirtualField;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lio/opentelemetry/instrumentation/api/util/VirtualField;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/context/Context;

    .line 8
    .line 9
    return-object p0
.end method


# virtual methods
.method public newCall(Ld01/k0;)Ld01/j;
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Ld01/k0;->b()Ld01/j0;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    new-instance v1, Ld01/k0;

    .line 10
    .line 11
    invoke-direct {v1, p1}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 12
    .line 13
    .line 14
    sget-object p1, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->contextsByRequest:Lio/opentelemetry/instrumentation/api/util/VirtualField;

    .line 15
    .line 16
    invoke-virtual {p1, v1, v0}, Lio/opentelemetry/instrumentation/api/util/VirtualField;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    new-instance p1, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;

    .line 20
    .line 21
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->okHttpClient:Ld01/h0;

    .line 22
    .line 23
    invoke-virtual {p0, v1}, Ld01/h0;->newCall(Ld01/k0;)Ld01/j;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-direct {p1, p0, v0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;-><init>(Ld01/j;Lio/opentelemetry/context/Context;)V

    .line 28
    .line 29
    .line 30
    return-object p1
.end method

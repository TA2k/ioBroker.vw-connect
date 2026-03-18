.class public final enum Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;",
        ">;",
        "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
        "Ld01/b0;",
        "Ld01/t0;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

.field public static final enum INSTANCE:Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->INSTANCE:Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->INSTANCE:Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->$values()[Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->$VALUES:[Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 16
    .line 17
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->$VALUES:[Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public getHttpRequestHeader(Ld01/b0;Ljava/lang/String;)Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ld01/b0;",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 2
    check-cast p1, Li01/f;

    .line 3
    iget-object p0, p1, Li01/f;->e:Ld01/k0;

    .line 4
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    const-string p1, "name"

    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    iget-object p0, p0, Ld01/k0;->c:Ld01/y;

    invoke-virtual {p0, p2}, Ld01/y;->m(Ljava/lang/String;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getHttpRequestHeader(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;
    .locals 0

    .line 1
    check-cast p1, Ld01/b0;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getHttpRequestHeader(Ld01/b0;Ljava/lang/String;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public getHttpRequestMethod(Ld01/b0;)Ljava/lang/String;
    .locals 0

    .line 2
    check-cast p1, Li01/f;

    .line 3
    iget-object p0, p1, Li01/f;->e:Ld01/k0;

    .line 4
    iget-object p0, p0, Ld01/k0;->b:Ljava/lang/String;

    return-object p0
.end method

.method public bridge synthetic getHttpRequestMethod(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    check-cast p1, Ld01/b0;

    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getHttpRequestMethod(Ld01/b0;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public getHttpResponseHeader(Ld01/b0;Ld01/t0;Ljava/lang/String;)Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ld01/b0;",
            "Ld01/t0;",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3
    const-string p0, "name"

    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    iget-object p0, p2, Ld01/t0;->i:Ld01/y;

    invoke-virtual {p0, p3}, Ld01/y;->m(Ljava/lang/String;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getHttpResponseHeader(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;
    .locals 0

    .line 1
    check-cast p1, Ld01/b0;

    check-cast p2, Ld01/t0;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getHttpResponseHeader(Ld01/b0;Ld01/t0;Ljava/lang/String;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public getHttpResponseStatusCode(Ld01/b0;Ld01/t0;Ljava/lang/Throwable;)Ljava/lang/Integer;
    .locals 0
    .param p3    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 2
    iget p0, p2, Ld01/t0;->g:I

    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getHttpResponseStatusCode(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)Ljava/lang/Integer;
    .locals 0
    .param p3    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    check-cast p1, Ld01/b0;

    check-cast p2, Ld01/t0;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getHttpResponseStatusCode(Ld01/b0;Ld01/t0;Ljava/lang/Throwable;)Ljava/lang/Integer;

    move-result-object p0

    return-object p0
.end method

.method public getNetworkPeerInetSocketAddress(Ld01/b0;Ld01/t0;)Ljava/net/InetSocketAddress;
    .locals 0
    .param p2    # Ld01/t0;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 2
    check-cast p1, Li01/f;

    .line 3
    iget-object p0, p1, Li01/f;->d:Lh01/g;

    const/4 p1, 0x0

    if-eqz p0, :cond_0

    .line 4
    invoke-virtual {p0}, Lh01/g;->c()Lh01/p;

    move-result-object p0

    goto :goto_0

    :cond_0
    move-object p0, p1

    :goto_0
    if-nez p0, :cond_1

    goto :goto_1

    .line 5
    :cond_1
    iget-object p0, p0, Lh01/p;->e:Ljava/net/Socket;

    .line 6
    invoke-virtual {p0}, Ljava/net/Socket;->getRemoteSocketAddress()Ljava/net/SocketAddress;

    move-result-object p0

    .line 7
    instance-of p2, p0, Ljava/net/InetSocketAddress;

    if-eqz p2, :cond_2

    .line 8
    check-cast p0, Ljava/net/InetSocketAddress;

    return-object p0

    :cond_2
    :goto_1
    return-object p1
.end method

.method public bridge synthetic getNetworkPeerInetSocketAddress(Ljava/lang/Object;Ljava/lang/Object;)Ljava/net/InetSocketAddress;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    check-cast p1, Ld01/b0;

    check-cast p2, Ld01/t0;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getNetworkPeerInetSocketAddress(Ld01/b0;Ld01/t0;)Ljava/net/InetSocketAddress;

    move-result-object p0

    return-object p0
.end method

.method public getNetworkProtocolName(Ld01/b0;Ld01/t0;)Ljava/lang/String;
    .locals 2
    .param p2    # Ld01/t0;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    const/4 p0, 0x0

    if-nez p2, :cond_0

    return-object p0

    .line 2
    :cond_0
    iget-object p1, p2, Ld01/t0;->e:Ld01/i0;

    .line 3
    sget-object p2, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter$1;->$SwitchMap$okhttp3$Protocol:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget p2, p2, v0

    const/4 v0, 0x1

    const-string v1, "http"

    if-eq p2, v0, :cond_3

    const/4 v0, 0x2

    if-eq p2, v0, :cond_3

    const/4 v0, 0x3

    if-eq p2, v0, :cond_3

    const/4 v0, 0x4

    if-eq p2, v0, :cond_2

    .line 4
    const-string p2, "H2_PRIOR_KNOWLEDGE"

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    return-object v1

    :cond_1
    return-object p0

    .line 5
    :cond_2
    const-string p0, "spdy"

    return-object p0

    :cond_3
    return-object v1
.end method

.method public bridge synthetic getNetworkProtocolName(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    check-cast p1, Ld01/b0;

    check-cast p2, Ld01/t0;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getNetworkProtocolName(Ld01/b0;Ld01/t0;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public getNetworkProtocolVersion(Ld01/b0;Ld01/t0;)Ljava/lang/String;
    .locals 2
    .param p2    # Ld01/t0;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    const/4 p0, 0x0

    if-nez p2, :cond_0

    return-object p0

    .line 2
    :cond_0
    iget-object p1, p2, Ld01/t0;->e:Ld01/i0;

    .line 3
    sget-object p2, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter$1;->$SwitchMap$okhttp3$Protocol:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget p2, p2, v0

    const/4 v0, 0x1

    if-eq p2, v0, :cond_5

    const/4 v0, 0x2

    if-eq p2, v0, :cond_4

    const/4 v0, 0x3

    const-string v1, "2"

    if-eq p2, v0, :cond_3

    const/4 v0, 0x4

    if-eq p2, v0, :cond_2

    .line 4
    const-string p2, "H2_PRIOR_KNOWLEDGE"

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    return-object v1

    :cond_1
    return-object p0

    .line 5
    :cond_2
    const-string p0, "3.1"

    return-object p0

    :cond_3
    return-object v1

    .line 6
    :cond_4
    const-string p0, "1.1"

    return-object p0

    .line 7
    :cond_5
    const-string p0, "1.0"

    return-object p0
.end method

.method public bridge synthetic getNetworkProtocolVersion(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    check-cast p1, Ld01/b0;

    check-cast p2, Ld01/t0;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getNetworkProtocolVersion(Ld01/b0;Ld01/t0;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public getServerAddress(Ld01/b0;)Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 2
    check-cast p1, Li01/f;

    .line 3
    iget-object p0, p1, Li01/f;->e:Ld01/k0;

    .line 4
    iget-object p0, p0, Ld01/k0;->a:Ld01/a0;

    .line 5
    iget-object p0, p0, Ld01/a0;->d:Ljava/lang/String;

    return-object p0
.end method

.method public bridge synthetic getServerAddress(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    check-cast p1, Ld01/b0;

    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getServerAddress(Ld01/b0;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public getServerPort(Ld01/b0;)Ljava/lang/Integer;
    .locals 0

    .line 2
    check-cast p1, Li01/f;

    .line 3
    iget-object p0, p1, Li01/f;->e:Ld01/k0;

    .line 4
    iget-object p0, p0, Ld01/k0;->a:Ld01/a0;

    .line 5
    iget p0, p0, Ld01/a0;->e:I

    .line 6
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getServerPort(Ljava/lang/Object;)Ljava/lang/Integer;
    .locals 0

    .line 1
    check-cast p1, Ld01/b0;

    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getServerPort(Ld01/b0;)Ljava/lang/Integer;

    move-result-object p0

    return-object p0
.end method

.method public getUrlFull(Ld01/b0;)Ljava/lang/String;
    .locals 0

    .line 2
    check-cast p1, Li01/f;

    .line 3
    iget-object p0, p1, Li01/f;->e:Ld01/k0;

    .line 4
    iget-object p0, p0, Ld01/k0;->a:Ld01/a0;

    .line 5
    iget-object p0, p0, Ld01/a0;->i:Ljava/lang/String;

    return-object p0
.end method

.method public bridge synthetic getUrlFull(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    check-cast p1, Ld01/b0;

    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/OkHttpAttributesGetter;->getUrlFull(Ld01/b0;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.class public final Lio/opentelemetry/extension/kotlin/ContextExtensionsKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u001a\u0011\u0010\u0002\u001a\u00020\u0001*\u00020\u0000\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u001a\u0011\u0010\u0002\u001a\u00020\u0001*\u00020\u0004\u00a2\u0006\u0004\u0008\u0002\u0010\u0005\u001a\u0011\u0010\u0006\u001a\u00020\u0000*\u00020\u0001\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Lio/opentelemetry/context/Context;",
        "Lpx0/g;",
        "asContextElement",
        "(Lio/opentelemetry/context/Context;)Lpx0/g;",
        "Lio/opentelemetry/context/ImplicitContextKeyed;",
        "(Lio/opentelemetry/context/ImplicitContextKeyed;)Lpx0/g;",
        "getOpenTelemetryContext",
        "(Lpx0/g;)Lio/opentelemetry/context/Context;",
        "opentelemetry-extension-kotlin"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final asContextElement(Lio/opentelemetry/context/Context;)Lpx0/g;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;

    invoke-direct {v0, p0}, Lio/opentelemetry/extension/kotlin/KotlinContextElement;-><init>(Lio/opentelemetry/context/Context;)V

    return-object v0
.end method

.method public static final asContextElement(Lio/opentelemetry/context/ImplicitContextKeyed;)Lpx0/g;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;

    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    move-result-object v1

    invoke-interface {v1, p0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ImplicitContextKeyed;)Lio/opentelemetry/context/Context;

    move-result-object p0

    invoke-direct {v0, p0}, Lio/opentelemetry/extension/kotlin/KotlinContextElement;-><init>(Lio/opentelemetry/context/Context;)V

    return-object v0
.end method

.method public static final getOpenTelemetryContext(Lpx0/g;)Lio/opentelemetry/context/Context;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->KEY:Lpx0/f;

    .line 7
    .line 8
    const-string v1, "KEY"

    .line 9
    .line 10
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->getContext()Lio/opentelemetry/context/Context;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v0, "getContext(...)"

    .line 26
    .line 27
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_0
    invoke-static {}, Lio/opentelemetry/context/Context;->root()Lio/opentelemetry/context/Context;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    const-string v0, "root(...)"

    .line 36
    .line 37
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    return-object p0
.end method

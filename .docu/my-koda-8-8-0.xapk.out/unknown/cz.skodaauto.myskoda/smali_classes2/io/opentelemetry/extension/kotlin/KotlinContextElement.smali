.class Lio/opentelemetry/extension/kotlin/KotlinContextElement;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/a2;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lvy0/a2;"
    }
.end annotation


# static fields
.field static final KEY:Lpx0/f;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lpx0/f;"
        }
    .end annotation
.end field


# instance fields
.field private final otelContext:Lio/opentelemetry/context/Context;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/extension/kotlin/KotlinContextElement$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/extension/kotlin/KotlinContextElement$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->KEY:Lpx0/f;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->otelContext:Lio/opentelemetry/context/Context;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<R:",
            "Ljava/lang/Object;",
            ">(TR;",
            "Lay0/n;",
            ")TR;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1, p2}, Ljp/de;->a(Lpx0/e;Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public get(Lpx0/f;)Lpx0/e;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E::",
            "Lpx0/e;",
            ">(",
            "Lpx0/f;",
            ")TE;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1}, Ljp/de;->b(Lpx0/e;Lpx0/f;)Lpx0/e;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getContext()Lio/opentelemetry/context/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->otelContext:Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public getKey()Lpx0/f;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lpx0/f;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->KEY:Lpx0/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public minusKey(Lpx0/f;)Lpx0/g;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lpx0/f;",
            ")",
            "Lpx0/g;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1}, Ljp/de;->c(Lpx0/e;Lpx0/f;)Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public plus(Lpx0/g;)Lpx0/g;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljp/ce;->a(Lpx0/g;Lpx0/g;)Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public restoreThreadContext(Lpx0/g;Lio/opentelemetry/context/Scope;)V
    .locals 0

    .line 2
    invoke-interface {p2}, Lio/opentelemetry/context/Scope;->close()V

    return-void
.end method

.method public bridge synthetic restoreThreadContext(Lpx0/g;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/context/Scope;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->restoreThreadContext(Lpx0/g;Lio/opentelemetry/context/Scope;)V

    return-void
.end method

.method public updateThreadContext(Lpx0/g;)Lio/opentelemetry/context/Scope;
    .locals 0

    .line 2
    iget-object p0, p0, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->otelContext:Lio/opentelemetry/context/Context;

    invoke-interface {p0}, Lio/opentelemetry/context/Context;->makeCurrent()Lio/opentelemetry/context/Scope;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic updateThreadContext(Lpx0/g;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/extension/kotlin/KotlinContextElement;->updateThreadContext(Lpx0/g;)Lio/opentelemetry/context/Scope;

    move-result-object p0

    return-object p0
.end method

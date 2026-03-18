.class public final Le01/c;
.super Ld01/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public final e:Ld01/d0;

.field public final f:J


# direct methods
.method public constructor <init>(Ld01/d0;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le01/c;->e:Ld01/d0;

    .line 5
    .line 6
    iput-wide p2, p0, Le01/c;->f:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 0

    .line 1
    const-string p0, "sink"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string p1, "Unreadable ResponseBody! These Response objects have bodies that are stripped:\n * Response.cacheResponse\n * Response.networkResponse\n * Response.priorResponse\n * EventSourceListener\n * WebSocketListener\n(It is safe to call contentType() and contentLength() on these response bodies.)"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final b()J
    .locals 2

    .line 1
    iget-wide v0, p0, Le01/c;->f:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final close()V
    .locals 0

    .line 1
    return-void
.end method

.method public final d()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Le01/c;->e:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final p0()Lu01/h;
    .locals 0

    .line 1
    invoke-static {p0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    sget-object p0, Lu01/j0;->d:Lu01/i0;

    .line 2
    .line 3
    return-object p0
.end method

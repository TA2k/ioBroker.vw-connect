.class final Lcom/squareup/moshi/JsonValueSource;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lu01/i;->g:Lu01/i;

    .line 2
    .line 3
    const-string v0, "[]{}\"\'/#"

    .line 4
    .line 5
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 6
    .line 7
    .line 8
    const-string v0, "\'\\"

    .line 9
    .line 10
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 11
    .line 12
    .line 13
    const-string v0, "\"\\"

    .line 14
    .line 15
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 16
    .line 17
    .line 18
    const-string v0, "\r\n"

    .line 19
    .line 20
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 21
    .line 22
    .line 23
    const-string v0, "*"

    .line 24
    .line 25
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 26
    .line 27
    .line 28
    sget-object v0, Lu01/i;->g:Lu01/i;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string p1, "closed"

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final close()V
    .locals 0

    .line 1
    return-void
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    throw p0
.end method

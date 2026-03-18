.class public final Lio/ktor/utils/io/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/ktor/utils/io/t;


# instance fields
.field public final b:Lnz0/a;

.field private volatile closed:Lio/ktor/utils/io/j0;


# direct methods
.method public constructor <init>(Lnz0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/ktor/utils/io/q0;->b:Lnz0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c(Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/ktor/utils/io/q0;->closed:Lio/ktor/utils/io/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance v0, Lio/ktor/utils/io/j0;

    .line 7
    .line 8
    new-instance v1, Ljava/io/IOException;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    if-nez v2, :cond_1

    .line 15
    .line 16
    const-string v2, "Channel was cancelled"

    .line 17
    .line 18
    :cond_1
    invoke-direct {v1, v2, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {v0, v1}, Lio/ktor/utils/io/j0;-><init>(Ljava/lang/Throwable;)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lio/ktor/utils/io/q0;->closed:Lio/ktor/utils/io/j0;

    .line 25
    .line 26
    return-void
.end method

.method public final d()Ljava/lang/Throwable;
    .locals 1

    .line 1
    iget-object p0, p0, Lio/ktor/utils/io/q0;->closed:Lio/ktor/utils/io/j0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lio/ktor/utils/io/i0;->d:Lio/ktor/utils/io/i0;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lio/ktor/utils/io/j0;->a(Lay0/k;)Ljava/lang/Throwable;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final e()Lnz0/a;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lio/ktor/utils/io/q0;->d()Ljava/lang/Throwable;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lio/ktor/utils/io/q0;->b:Lnz0/a;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    throw v0
.end method

.method public final f(ILrx0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/ktor/utils/io/q0;->d()Ljava/lang/Throwable;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lio/ktor/utils/io/q0;->b:Lnz0/a;

    .line 8
    .line 9
    int-to-long p1, p1

    .line 10
    invoke-virtual {p0, p1, p2}, Lnz0/a;->c(J)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    throw p2
.end method

.method public final g()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/ktor/utils/io/q0;->b:Lnz0/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnz0/a;->Z()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

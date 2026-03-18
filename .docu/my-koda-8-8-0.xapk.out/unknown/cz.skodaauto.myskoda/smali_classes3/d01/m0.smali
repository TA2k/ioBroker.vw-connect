.class public final Ld01/m0;
.super Ld01/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Ld01/d0;

.field public final synthetic b:Lu01/k;

.field public final synthetic c:Lu01/y;


# direct methods
.method public constructor <init>(Lu01/y;Lu01/k;Ld01/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Ld01/m0;->a:Ld01/d0;

    .line 5
    .line 6
    iput-object p2, p0, Ld01/m0;->b:Lu01/k;

    .line 7
    .line 8
    iput-object p1, p0, Ld01/m0;->c:Lu01/y;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final contentLength()J
    .locals 2

    .line 1
    iget-object v0, p0, Ld01/m0;->b:Lu01/k;

    .line 2
    .line 3
    iget-object p0, p0, Ld01/m0;->c:Lu01/y;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lu01/k;->l(Lu01/y;)Li5/f;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    iget-object p0, p0, Li5/f;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Ljava/lang/Long;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 16
    .line 17
    .line 18
    move-result-wide v0

    .line 19
    return-wide v0

    .line 20
    :cond_0
    const-wide/16 v0, -0x1

    .line 21
    .line 22
    return-wide v0
.end method

.method public final contentType()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/m0;->a:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final writeTo(Lu01/g;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ld01/m0;->b:Lu01/k;

    .line 2
    .line 3
    iget-object p0, p0, Ld01/m0;->c:Lu01/y;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lu01/k;->H(Lu01/y;)Lu01/h0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :try_start_0
    invoke-interface {p1, p0}, Lu01/g;->P(Lu01/h0;)J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :catchall_0
    move-exception p1

    .line 17
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 18
    :catchall_1
    move-exception v0

    .line 19
    invoke-static {p0, p1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 20
    .line 21
    .line 22
    throw v0
.end method

.class public final Ld01/l0;
.super Ld01/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Ld01/d0;

.field public final synthetic b:Ljava/io/File;


# direct methods
.method public constructor <init>(Ld01/d0;Ljava/io/File;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ld01/l0;->a:Ld01/d0;

    .line 5
    .line 6
    iput-object p2, p0, Ld01/l0;->b:Ljava/io/File;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final contentLength()J
    .locals 2

    .line 1
    iget-object p0, p0, Ld01/l0;->b:Ljava/io/File;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/File;->length()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public final contentType()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/l0;->a:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final writeTo(Lu01/g;)V
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    iget-object p0, p0, Ld01/l0;->b:Ljava/io/File;

    .line 4
    .line 5
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lu01/s;

    .line 9
    .line 10
    new-instance v1, Ljava/io/FileInputStream;

    .line 11
    .line 12
    invoke-direct {v1, p0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Lu01/j0;->d:Lu01/i0;

    .line 16
    .line 17
    invoke-direct {v0, v1, p0}, Lu01/s;-><init>(Ljava/io/InputStream;Lu01/j0;)V

    .line 18
    .line 19
    .line 20
    :try_start_0
    invoke-interface {p1, v0}, Lu01/g;->P(Lu01/h0;)J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Lu01/s;->close()V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    :try_start_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 29
    :catchall_1
    move-exception p1

    .line 30
    invoke-static {v0, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 31
    .line 32
    .line 33
    throw p1
.end method

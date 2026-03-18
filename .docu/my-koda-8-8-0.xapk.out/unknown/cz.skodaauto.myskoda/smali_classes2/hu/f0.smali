.class public final Lhu/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/u0;


# instance fields
.field public final a:Lhu/p0;


# direct methods
.method public constructor <init>(Lhu/p0;)V
    .locals 1

    .line 1
    const-string v0, "sessionGenerator"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lhu/f0;->a:Lhu/p0;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lhu/e0;

    .line 2
    .line 3
    iget-object p0, p0, Lhu/f0;->a:Lhu/p0;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p0, v1}, Lhu/p0;->a(Lhu/j0;)Lhu/j0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-direct {v0, p0, v1, v1}, Lhu/e0;-><init>(Lhu/j0;Lhu/z0;Ljava/util/Map;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final b(Ljava/io/FileInputStream;)Ljava/lang/Object;
    .locals 1

    .line 1
    :try_start_0
    sget-object p0, Lvz0/d;->d:Lvz0/c;

    .line 2
    .line 3
    invoke-static {p1}, Llp/ud;->c(Ljava/io/InputStream;)[B

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p1}, Lly0/w;->l([B)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    sget-object v0, Lhu/e0;->Companion:Lhu/d0;

    .line 15
    .line 16
    invoke-virtual {v0}, Lhu/d0;->serializer()Lqz0/a;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Lqz0/a;

    .line 21
    .line 22
    invoke-virtual {p0, p1, v0}, Lvz0/d;->b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lhu/e0;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    .line 28
    return-object p0

    .line 29
    :catch_0
    move-exception p0

    .line 30
    new-instance p1, Lm6/b;

    .line 31
    .line 32
    const-string v0, "Cannot parse session data"

    .line 33
    .line 34
    invoke-direct {p1, v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    throw p1
.end method

.method public final c(Ljava/lang/Object;Lm6/b1;)V
    .locals 1

    .line 1
    check-cast p1, Lhu/e0;

    .line 2
    .line 3
    sget-object p0, Lvz0/d;->d:Lvz0/c;

    .line 4
    .line 5
    sget-object v0, Lhu/e0;->Companion:Lhu/d0;

    .line 6
    .line 7
    invoke-virtual {v0}, Lhu/d0;->serializer()Lqz0/a;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lqz0/a;

    .line 12
    .line 13
    invoke-virtual {p0, v0, p1}, Lvz0/d;->d(Lqz0/a;Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-static {p0}, Lly0/w;->n(Ljava/lang/String;)[B

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p2, p0}, Lm6/b1;->write([B)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

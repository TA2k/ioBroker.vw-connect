.class public final Lku/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/u0;


# static fields
.field public static final a:Lku/h;

.field public static final b:Lku/g;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lku/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lku/h;->a:Lku/h;

    .line 7
    .line 8
    new-instance v1, Lku/g;

    .line 9
    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x0

    .line 14
    const/4 v4, 0x0

    .line 15
    invoke-direct/range {v1 .. v6}, Lku/g;-><init>(Ljava/lang/Boolean;Ljava/lang/Double;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Long;)V

    .line 16
    .line 17
    .line 18
    sput-object v1, Lku/h;->b:Lku/g;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final bridge synthetic a()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Lku/h;->b:Lku/g;

    .line 2
    .line 3
    return-object p0
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
    sget-object v0, Lku/g;->Companion:Lku/f;

    .line 15
    .line 16
    invoke-virtual {v0}, Lku/f;->serializer()Lqz0/a;

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
    check-cast p0, Lku/g;
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
    const-string v0, "Cannot parse session configs"

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
    check-cast p1, Lku/g;

    .line 2
    .line 3
    sget-object p0, Lvz0/d;->d:Lvz0/c;

    .line 4
    .line 5
    sget-object v0, Lku/g;->Companion:Lku/f;

    .line 6
    .line 7
    invoke-virtual {v0}, Lku/f;->serializer()Lqz0/a;

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

.class public final Lbd0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbd0/a;


# direct methods
.method public constructor <init>(Lbd0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbd0/c;->a:Lbd0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ldd0/a;

    .line 4
    .line 5
    new-instance v2, Ljava/net/URL;

    .line 6
    .line 7
    iget-object v1, v0, Ldd0/a;->a:Ljava/lang/String;

    .line 8
    .line 9
    invoke-direct {v2, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-boolean v3, v0, Ldd0/a;->b:Z

    .line 13
    .line 14
    iget-boolean v4, v0, Ldd0/a;->c:Z

    .line 15
    .line 16
    iget-boolean v5, v0, Ldd0/a;->d:Z

    .line 17
    .line 18
    iget-boolean v6, v0, Ldd0/a;->e:Z

    .line 19
    .line 20
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 21
    .line 22
    move-object v1, p0

    .line 23
    check-cast v1, Lzc0/b;

    .line 24
    .line 25
    invoke-virtual/range {v1 .. v6}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

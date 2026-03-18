.class public final Lks0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbd0/c;


# direct methods
.method public constructor <init>(Lbd0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lks0/g;->a:Lbd0/c;

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
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lks0/g;->a:Lbd0/c;

    .line 6
    .line 7
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 8
    .line 9
    new-instance v2, Ljava/net/URL;

    .line 10
    .line 11
    invoke-direct {v2, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    move-object v1, p0

    .line 15
    check-cast v1, Lzc0/b;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x0

    .line 19
    const/4 v5, 0x0

    .line 20
    const/4 v6, 0x0

    .line 21
    invoke-virtual/range {v1 .. v6}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    new-instance v0, Lal0/i;

    .line 26
    .line 27
    const/4 v1, 0x5

    .line 28
    invoke-direct {v0, p0, v1}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 29
    .line 30
    .line 31
    return-object v0
.end method

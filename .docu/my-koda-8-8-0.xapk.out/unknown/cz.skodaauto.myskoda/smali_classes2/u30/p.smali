.class public final Lu30/p;
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
    iput-object p1, p0, Lu30/p;->a:Lbd0/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    const/16 v1, 0x1e

    .line 6
    .line 7
    and-int/lit8 v2, v1, 0x2

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x1

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    move v7, v4

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v7, v3

    .line 16
    :goto_0
    and-int/lit8 v2, v1, 0x4

    .line 17
    .line 18
    if-eqz v2, :cond_1

    .line 19
    .line 20
    move v8, v4

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    move v8, v3

    .line 23
    :goto_1
    and-int/lit8 v2, v1, 0x8

    .line 24
    .line 25
    if-eqz v2, :cond_2

    .line 26
    .line 27
    move v9, v3

    .line 28
    goto :goto_2

    .line 29
    :cond_2
    move v9, v4

    .line 30
    :goto_2
    and-int/lit8 v1, v1, 0x10

    .line 31
    .line 32
    if-eqz v1, :cond_3

    .line 33
    .line 34
    move v10, v3

    .line 35
    goto :goto_3

    .line 36
    :cond_3
    move v10, v4

    .line 37
    :goto_3
    iget-object p0, p0, Lu30/p;->a:Lbd0/c;

    .line 38
    .line 39
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 40
    .line 41
    new-instance v6, Ljava/net/URL;

    .line 42
    .line 43
    invoke-direct {v6, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    move-object v5, p0

    .line 47
    check-cast v5, Lzc0/b;

    .line 48
    .line 49
    invoke-virtual/range {v5 .. v10}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    new-instance v0, Lal0/i;

    .line 54
    .line 55
    const/16 v1, 0x9

    .line 56
    .line 57
    invoke-direct {v0, p0, v1}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 58
    .line 59
    .line 60
    return-object v0
.end method

.class public final Lf40/g3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/y0;


# direct methods
.method public constructor <init>(Lf40/y0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/g3;->a:Lf40/y0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Ljava/util/Map;

    .line 2
    .line 3
    const-string p2, "id"

    .line 4
    .line 5
    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Ljava/lang/String;

    .line 10
    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    new-instance v0, Lne0/c;

    .line 14
    .line 15
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 16
    .line 17
    const-string p0, "Invalid badge ID"

    .line 18
    .line 19
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    const/16 v5, 0x1e

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 28
    .line 29
    .line 30
    return-object v0

    .line 31
    :cond_0
    new-instance p2, Lg40/v0;

    .line 32
    .line 33
    invoke-direct {p2, p1}, Lg40/v0;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lf40/g3;->a:Lf40/y0;

    .line 37
    .line 38
    check-cast p0, Ld40/a;

    .line 39
    .line 40
    iput-object p2, p0, Ld40/a;->c:Lg40/v0;

    .line 41
    .line 42
    iget-object p0, p0, Ld40/a;->b:Lwe0/a;

    .line 43
    .line 44
    check-cast p0, Lwe0/c;

    .line 45
    .line 46
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 47
    .line 48
    .line 49
    new-instance p0, Lne0/e;

    .line 50
    .line 51
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 52
    .line 53
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-object p0
.end method

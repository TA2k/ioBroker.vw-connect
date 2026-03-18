.class public final Lro0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lro0/q;


# direct methods
.method public constructor <init>(Lro0/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lro0/a;->a:Lro0/q;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lto0/h;

    .line 2
    .line 3
    iget-object p1, p1, Lto0/h;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lro0/a;->b(Ljava/lang/String;)Lne0/n;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final b(Ljava/lang/String;)Lne0/n;
    .locals 9

    .line 1
    iget-object v0, p0, Lro0/a;->a:Lro0/q;

    .line 2
    .line 3
    check-cast v0, Lpo0/b;

    .line 4
    .line 5
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-powerpass-model-EvseId$-evseId$0"

    .line 6
    .line 7
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, v0, Lpo0/b;->a:Lro0/u;

    .line 11
    .line 12
    check-cast v0, Lpo0/e;

    .line 13
    .line 14
    iget-object v0, v0, Lpo0/e;->a:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    new-instance v2, Lh7/z;

    .line 20
    .line 21
    const/16 v3, 0x12

    .line 22
    .line 23
    invoke-direct {v2, v3, v0, p1, v1}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    new-instance v0, Lyy0/m1;

    .line 27
    .line 28
    invoke-direct {v0, v2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance v3, Lne0/c;

    .line 33
    .line 34
    new-instance v4, Llx0/g;

    .line 35
    .line 36
    invoke-direct {v4}, Llx0/g;-><init>()V

    .line 37
    .line 38
    .line 39
    const/4 v7, 0x0

    .line 40
    const/16 v8, 0x1e

    .line 41
    .line 42
    const/4 v5, 0x0

    .line 43
    const/4 v6, 0x0

    .line 44
    invoke-direct/range {v3 .. v8}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 45
    .line 46
    .line 47
    new-instance v0, Lyy0/m;

    .line 48
    .line 49
    const/4 v2, 0x0

    .line 50
    invoke-direct {v0, v3, v2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 51
    .line 52
    .line 53
    :goto_0
    new-instance v2, Lqh/a;

    .line 54
    .line 55
    const/4 v3, 0x2

    .line 56
    invoke-direct {v2, v3, p0, p1, v1}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 57
    .line 58
    .line 59
    new-instance p0, Lne0/n;

    .line 60
    .line 61
    const/4 p1, 0x5

    .line 62
    invoke-direct {p0, v0, v2, p1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 63
    .line 64
    .line 65
    return-object p0
.end method

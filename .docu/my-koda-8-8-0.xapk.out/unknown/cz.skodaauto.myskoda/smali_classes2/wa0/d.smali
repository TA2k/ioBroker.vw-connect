.class public final Lwa0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lua0/b;

.field public final c:Lua0/f;


# direct methods
.method public constructor <init>(Lkf0/o;Lua0/b;Lua0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwa0/d;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lwa0/d;->b:Lua0/b;

    .line 7
    .line 8
    iput-object p3, p0, Lwa0/d;->c:Lua0/f;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lwa0/d;->a:Lkf0/o;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lqa0/a;

    .line 8
    .line 9
    const/16 v2, 0x18

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    iget-object v4, p0, Lwa0/d;->b:Lua0/b;

    .line 13
    .line 14
    invoke-direct {v1, v3, v4, v2}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, Lvu/j;

    .line 22
    .line 23
    const/16 v2, 0x16

    .line 24
    .line 25
    invoke-direct {v1, p0, v3, v2}, Lvu/j;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v1, v0}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    new-instance v1, Lwa0/c;

    .line 33
    .line 34
    const/4 v2, 0x0

    .line 35
    invoke-direct {v1, p0, v3, v2}, Lwa0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {v1, v0}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

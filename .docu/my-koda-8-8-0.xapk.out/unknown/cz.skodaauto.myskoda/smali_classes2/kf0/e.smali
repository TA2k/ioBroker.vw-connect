.class public final Lkf0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/b0;

.field public final b:Lif0/u;

.field public final c:Lrs0/f;

.field public final d:Lif0/f0;


# direct methods
.method public constructor <init>(Lkf0/b0;Lif0/u;Lrs0/f;Lif0/f0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/e;->a:Lkf0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/e;->b:Lif0/u;

    .line 7
    .line 8
    iput-object p3, p0, Lkf0/e;->c:Lrs0/f;

    .line 9
    .line 10
    iput-object p4, p0, Lkf0/e;->d:Lif0/f0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lkf0/e;->a:Lkf0/b0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-static {v0, v1}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    new-instance v1, Lgb0/z;

    .line 15
    .line 16
    const/16 v2, 0xa

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    invoke-direct {v1, v3, p0, v2}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    new-instance v1, Lk31/l;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-direct {v1, v0, v3, p0, v2}, Lk31/l;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    new-instance v0, Lyy0/m1;

    .line 33
    .line 34
    invoke-direct {v0, v1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 35
    .line 36
    .line 37
    new-instance v1, Lk31/t;

    .line 38
    .line 39
    const/16 v2, 0xa

    .line 40
    .line 41
    invoke-direct {v1, p0, v3, v2}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    new-instance p0, Lne0/n;

    .line 45
    .line 46
    const/4 v2, 0x5

    .line 47
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 48
    .line 49
    .line 50
    return-object p0
.end method

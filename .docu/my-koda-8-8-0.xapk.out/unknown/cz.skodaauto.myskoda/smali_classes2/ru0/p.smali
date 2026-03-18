.class public final Lru0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/z;

.field public final b:Lqd0/o0;

.field public final c:Llm0/e;

.field public final d:Lqd0/x;


# direct methods
.method public constructor <init>(Lkf0/z;Lqd0/o0;Llm0/e;Lqd0/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lru0/p;->a:Lkf0/z;

    .line 5
    .line 6
    iput-object p2, p0, Lru0/p;->b:Lqd0/o0;

    .line 7
    .line 8
    iput-object p3, p0, Lru0/p;->c:Llm0/e;

    .line 9
    .line 10
    iput-object p4, p0, Lru0/p;->d:Lqd0/x;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lru0/p;->a:Lkf0/z;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lhg/q;

    .line 10
    .line 11
    const/16 v2, 0x1d

    .line 12
    .line 13
    invoke-direct {v1, v0, v2}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Le71/e;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-direct {v0, v2, p0}, Le71/e;-><init>(Lkotlin/coroutines/Continuation;Lru0/p;)V

    .line 20
    .line 21
    .line 22
    invoke-static {v1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.class public final Lqd0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lqd0/i;

.field public final c:Lod0/b0;

.field public final d:Lsf0/a;


# direct methods
.method public constructor <init>(Lkf0/o;Lod0/b0;Lqd0/i;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/s;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p3, p0, Lqd0/s;->b:Lqd0/i;

    .line 7
    .line 8
    iput-object p2, p0, Lqd0/s;->c:Lod0/b0;

    .line 9
    .line 10
    iput-object p4, p0, Lqd0/s;->d:Lsf0/a;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lrd0/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lqd0/s;->b(Lrd0/d;)Lam0/i;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lrd0/d;)Lam0/i;
    .locals 4

    .line 1
    iget-object v0, p0, Lqd0/s;->a:Lkf0/o;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lo20/c;

    .line 8
    .line 9
    const/16 v2, 0x9

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v1, v2, p0, p1, v3}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    new-instance v0, Ln00/f;

    .line 20
    .line 21
    const/16 v1, 0x12

    .line 22
    .line 23
    invoke-direct {v0, p0, v3, v1}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, p1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iget-object p0, p0, Lqd0/s;->d:Lsf0/a;

    .line 31
    .line 32
    invoke-static {p1, p0, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

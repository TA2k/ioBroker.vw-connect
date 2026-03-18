.class public final Lqd0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lod0/b0;

.field public final c:Lod0/o0;

.field public final d:Lhu0/b;


# direct methods
.method public constructor <init>(Lkf0/o;Lod0/b0;Lod0/o0;Lhu0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/n;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lqd0/n;->b:Lod0/b0;

    .line 7
    .line 8
    iput-object p3, p0, Lqd0/n;->c:Lod0/o0;

    .line 9
    .line 10
    iput-object p4, p0, Lqd0/n;->d:Lhu0/b;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lqd0/m;)Lzy0/j;
    .locals 4

    .line 1
    iget-object v0, p0, Lqd0/n;->a:Lkf0/o;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Le71/e;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/16 v3, 0x9

    .line 11
    .line 12
    invoke-direct {v1, v3, p1, v2, p0}, Le71/e;-><init>(ILjava/lang/Object;Lkotlin/coroutines/Continuation;Ltr0/d;)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lqd0/m;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lqd0/n;->a(Lqd0/m;)Lzy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

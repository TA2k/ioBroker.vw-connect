.class public final Lqd0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lod0/b0;

.field public final b:Lqd0/y;

.field public final c:Lkf0/z;

.field public final d:Lam0/c;

.field public final e:Lkc0/i;

.field public final f:Lkg0/a;


# direct methods
.method public constructor <init>(Lod0/b0;Lqd0/y;Lkf0/z;Lam0/c;Lkc0/i;Lkg0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/g;->a:Lod0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lqd0/g;->b:Lqd0/y;

    .line 7
    .line 8
    iput-object p3, p0, Lqd0/g;->c:Lkf0/z;

    .line 9
    .line 10
    iput-object p4, p0, Lqd0/g;->d:Lam0/c;

    .line 11
    .line 12
    iput-object p5, p0, Lqd0/g;->e:Lkc0/i;

    .line 13
    .line 14
    iput-object p6, p0, Lqd0/g;->f:Lkg0/a;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lqd0/g;->c:Lkf0/z;

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
    invoke-static {v0}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Lm70/u0;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const/4 v3, 0x0

    .line 17
    invoke-direct {v1, v3, p0, v2}, Lm70/u0;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    new-instance v0, Lal0/m0;

    .line 25
    .line 26
    const/4 v1, 0x2

    .line 27
    const/16 v2, 0x16

    .line 28
    .line 29
    invoke-direct {v0, v1, v3, v2}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    new-instance v1, Lne0/n;

    .line 33
    .line 34
    invoke-direct {v1, v0, p0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 35
    .line 36
    .line 37
    return-object v1
.end method

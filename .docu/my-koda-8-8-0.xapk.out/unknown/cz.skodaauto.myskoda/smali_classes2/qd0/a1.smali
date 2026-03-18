.class public final Lqd0/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lod0/b0;

.field public final c:Lsf0/a;

.field public final d:Lkf0/j0;

.field public final e:Ljr0/f;


# direct methods
.method public constructor <init>(Lkf0/m;Lod0/b0;Lsf0/a;Lkf0/j0;Ljr0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/a1;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Lqd0/a1;->b:Lod0/b0;

    .line 7
    .line 8
    iput-object p3, p0, Lqd0/a1;->c:Lsf0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lqd0/a1;->d:Lkf0/j0;

    .line 11
    .line 12
    iput-object p5, p0, Lqd0/a1;->e:Ljr0/f;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lqd0/a1;->a:Lkf0/m;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lna/e;

    .line 8
    .line 9
    const/16 v2, 0x17

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v1, p0, v3, v2}, Lna/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Llp/sf;->c(Lyy0/m1;Lay0/n;)Lyy0/m1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v1, Lqa0/a;

    .line 20
    .line 21
    const/16 v2, 0x8

    .line 22
    .line 23
    invoke-direct {v1, v3, p0, v2}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iget-object p0, p0, Lqd0/a1;->c:Lsf0/a;

    .line 31
    .line 32
    invoke-static {v0, p0, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.class public final Lq10/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lko0/f;

.field public final c:Lo10/m;

.field public final d:Lsf0/a;


# direct methods
.method public constructor <init>(Lkf0/m;Lko0/f;Lo10/m;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq10/w;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Lq10/w;->b:Lko0/f;

    .line 7
    .line 8
    iput-object p3, p0, Lq10/w;->c:Lo10/m;

    .line 9
    .line 10
    iput-object p4, p0, Lq10/w;->d:Lsf0/a;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lr10/b;)Lyy0/m1;
    .locals 4

    .line 1
    iget-object v0, p0, Lq10/w;->a:Lkf0/m;

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
    const/4 v2, 0x2

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v1, v2, p0, p1, v3}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iget-object v0, p0, Lq10/w;->d:Lsf0/a;

    .line 19
    .line 20
    invoke-static {p1, v0, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    new-instance v0, Lna/e;

    .line 25
    .line 26
    const/16 v1, 0x13

    .line 27
    .line 28
    invoke-direct {v0, p0, v3, v1}, Lna/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v0, p1}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lr10/b;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lq10/w;->a(Lr10/b;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

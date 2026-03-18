.class public final Lq10/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lo10/m;

.field public final c:Lq10/f;


# direct methods
.method public constructor <init>(Lkf0/m;Lo10/m;Lq10/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq10/c;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Lq10/c;->b:Lo10/m;

    .line 7
    .line 8
    iput-object p3, p0, Lq10/c;->c:Lq10/f;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lq10/b;)Lzy0/j;
    .locals 4

    .line 1
    iget-object v0, p0, Lq10/c;->a:Lkf0/m;

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
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x1

    .line 11
    invoke-direct {v1, v3, p0, p1, v2}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lq10/b;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lq10/c;->a(Lq10/b;)Lzy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

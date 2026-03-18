.class public final Lk70/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lk70/v;

.field public final b:Lk70/e;


# direct methods
.method public constructor <init>(Lk70/v;Lk70/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/b0;->a:Lk70/v;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/b0;->b:Lk70/e;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ll70/h;)Lyy0/i;
    .locals 6

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk70/b0;->a:Lk70/v;

    .line 7
    .line 8
    check-cast v0, Li70/b;

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Li70/b;->b(Ll70/h;)Li70/a;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-object v1, v1, Li70/a;->f:Lyy0/c2;

    .line 15
    .line 16
    new-instance v2, Lyy0/l1;

    .line 17
    .line 18
    invoke-direct {v2, v1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, p1}, Li70/b;->b(Ll70/h;)Li70/a;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget-object v0, v0, Li70/a;->d:Lez0/c;

    .line 26
    .line 27
    new-instance v1, Li2/t;

    .line 28
    .line 29
    const/16 v3, 0x17

    .line 30
    .line 31
    invoke-direct {v1, v3, p0, p1}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    new-instance v3, Lc1/b;

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    const/4 v5, 0x3

    .line 38
    invoke-direct {v3, v5, p0, p1, v4}, Lc1/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 39
    .line 40
    .line 41
    invoke-static {v2, v0, v1, v3}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ll70/h;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lk70/b0;->a(Ll70/h;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

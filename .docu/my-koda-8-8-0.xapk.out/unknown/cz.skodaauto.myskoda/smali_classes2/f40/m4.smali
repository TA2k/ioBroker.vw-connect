.class public final Lf40/m4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ld40/n;

.field public final b:Lwr0/h;

.field public final c:Lrs0/g;

.field public final d:Lf40/v;

.field public final e:Lf40/r;


# direct methods
.method public constructor <init>(Ld40/n;Lwr0/h;Lrs0/g;Lf40/v;Lf40/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/m4;->a:Ld40/n;

    .line 5
    .line 6
    iput-object p2, p0, Lf40/m4;->b:Lwr0/h;

    .line 7
    .line 8
    iput-object p3, p0, Lf40/m4;->c:Lrs0/g;

    .line 9
    .line 10
    iput-object p4, p0, Lf40/m4;->d:Lf40/v;

    .line 11
    .line 12
    iput-object p5, p0, Lf40/m4;->e:Lf40/r;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 6

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lf40/m4;->b:Lwr0/h;

    .line 7
    .line 8
    invoke-virtual {v0}, Lwr0/h;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lyy0/i;

    .line 13
    .line 14
    iget-object v1, p0, Lf40/m4;->c:Lrs0/g;

    .line 15
    .line 16
    invoke-virtual {v1}, Lrs0/g;->invoke()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lyy0/i;

    .line 21
    .line 22
    new-instance v2, Lal0/y0;

    .line 23
    .line 24
    const/4 v3, 0x3

    .line 25
    const/4 v4, 0x3

    .line 26
    const/4 v5, 0x0

    .line 27
    invoke-direct {v2, v3, v5, v4}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    new-instance v3, Lbn0/f;

    .line 31
    .line 32
    const/4 v4, 0x5

    .line 33
    invoke-direct {v3, v0, v1, v2, v4}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 34
    .line 35
    .line 36
    new-instance v0, Lac/k;

    .line 37
    .line 38
    const/16 v1, 0x9

    .line 39
    .line 40
    invoke-direct {v0, v1, p0, p1, v5}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v3, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lf40/m4;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

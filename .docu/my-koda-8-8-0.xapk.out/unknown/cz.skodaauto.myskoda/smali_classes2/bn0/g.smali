.class public final Lbn0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/b0;

.field public final b:Lwr0/h;

.field public final c:Lcc0/g;

.field public final d:Lcc0/e;

.field public final e:Lbn0/b;


# direct methods
.method public constructor <init>(Lkf0/b0;Lwr0/h;Lcc0/g;Lcc0/e;Lbn0/b;Lbn0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbn0/g;->a:Lkf0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lbn0/g;->b:Lwr0/h;

    .line 7
    .line 8
    iput-object p3, p0, Lbn0/g;->c:Lcc0/g;

    .line 9
    .line 10
    iput-object p4, p0, Lbn0/g;->d:Lcc0/e;

    .line 11
    .line 12
    iput-object p5, p0, Lbn0/g;->e:Lbn0/b;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lbn0/c;)Lzy0/j;
    .locals 6

    .line 1
    iget-object v0, p0, Lbn0/g;->a:Lkf0/b0;

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
    iget-object v1, p0, Lbn0/g;->b:Lwr0/h;

    .line 10
    .line 11
    invoke-virtual {v1}, Lwr0/h;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lyy0/i;

    .line 16
    .line 17
    new-instance v2, Lbn0/d;

    .line 18
    .line 19
    const/4 v3, 0x3

    .line 20
    const/4 v4, 0x0

    .line 21
    const/4 v5, 0x0

    .line 22
    invoke-direct {v2, v3, v5, v4}, Lbn0/d;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lbn0/f;

    .line 26
    .line 27
    const/4 v4, 0x5

    .line 28
    invoke-direct {v3, v0, v1, v2, v4}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    new-instance v0, Lac/k;

    .line 32
    .line 33
    const/4 v1, 0x4

    .line 34
    invoke-direct {v0, v1, p1, p0, v5}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    invoke-static {v3, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lbn0/c;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.class public final Llt0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ljt0/d;

.field public final b:Llt0/d;


# direct methods
.method public constructor <init>(Ljt0/d;Llt0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llt0/a;->a:Ljt0/d;

    .line 5
    .line 6
    iput-object p2, p0, Llt0/a;->b:Llt0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 5

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Llt0/a;->a:Ljt0/d;

    .line 7
    .line 8
    iget-object v1, v0, Ljt0/d;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v2, La2/c;

    .line 11
    .line 12
    const/16 v3, 0x16

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    invoke-direct {v2, v3, v0, p1, v4}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    new-instance p1, Lim0/b;

    .line 19
    .line 20
    const/16 v0, 0x1c

    .line 21
    .line 22
    invoke-direct {p1, v0}, Lim0/b;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1, v2, p1, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    new-instance v0, Llb0/q0;

    .line 30
    .line 31
    const/4 v1, 0x2

    .line 32
    invoke-direct {v0, p0, v4, v1}, Llb0/q0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    new-instance p0, Lne0/n;

    .line 36
    .line 37
    const/4 v1, 0x5

    .line 38
    invoke-direct {p0, p1, v0, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 39
    .line 40
    .line 41
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
    invoke-virtual {p0, v0}, Llt0/a;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

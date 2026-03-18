.class public final Lzy/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lpp0/l0;

.field public final c:Lxy/g;


# direct methods
.method public constructor <init>(Lkf0/o;Lpp0/l0;Lxy/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzy/p;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lzy/p;->b:Lpp0/l0;

    .line 7
    .line 8
    iput-object p3, p0, Lzy/p;->c:Lxy/g;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Laz/i;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lzy/p;->b(Laz/i;)Lzy0/j;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Laz/i;)Lzy0/j;
    .locals 5

    .line 1
    iget-object v0, p0, Lzy/p;->a:Lkf0/o;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lzy/p;->b:Lpp0/l0;

    .line 8
    .line 9
    invoke-virtual {v1}, Lpp0/l0;->invoke()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lyy0/i;

    .line 14
    .line 15
    new-instance v2, Lfw0/x;

    .line 16
    .line 17
    const/4 v3, 0x2

    .line 18
    const/4 v4, 0x0

    .line 19
    invoke-direct {v2, v3, p0, p1, v4}, Lfw0/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 20
    .line 21
    .line 22
    new-instance p0, Lbn0/f;

    .line 23
    .line 24
    const/4 p1, 0x5

    .line 25
    invoke-direct {p0, v0, v1, v2, p1}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    new-instance p1, Lbq0/a;

    .line 29
    .line 30
    const/4 v0, 0x3

    .line 31
    const/4 v1, 0x2

    .line 32
    invoke-direct {p1, v0, v4, v1}, Lbq0/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    invoke-static {p0, p1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

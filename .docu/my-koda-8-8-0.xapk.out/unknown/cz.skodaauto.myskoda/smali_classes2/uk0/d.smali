.class public final Luk0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Llk0/a;

.field public final b:Llk0/f;

.field public final c:Luk0/b0;

.field public final d:Llk0/k;


# direct methods
.method public constructor <init>(Llk0/a;Llk0/f;Luk0/b0;Llk0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/d;->a:Llk0/a;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/d;->b:Llk0/f;

    .line 7
    .line 8
    iput-object p3, p0, Luk0/d;->c:Luk0/b0;

    .line 9
    .line 10
    iput-object p4, p0, Luk0/d;->d:Llk0/k;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Luk0/d;->c:Luk0/b0;

    .line 2
    .line 3
    invoke-virtual {v0}, Luk0/b0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lrz/k;

    .line 10
    .line 11
    const/16 v2, 0x15

    .line 12
    .line 13
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v1}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-instance v1, Luk0/a;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct {v1, v2, p0}, Luk0/a;-><init>(Lkotlin/coroutines/Continuation;Luk0/d;)V

    .line 28
    .line 29
    .line 30
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.class public final Lkf0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lif0/u;

.field public final c:Lsf0/a;


# direct methods
.method public constructor <init>(Lkf0/m;Lif0/u;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/g0;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/g0;->b:Lif0/u;

    .line 7
    .line 8
    iput-object p3, p0, Lkf0/g0;->c:Lsf0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llf0/b;

    .line 2
    .line 3
    iget-object p2, p0, Lkf0/g0;->a:Lkf0/m;

    .line 4
    .line 5
    invoke-static {p2}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    new-instance v0, Lac/k;

    .line 10
    .line 11
    const/16 v1, 0x14

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-direct {v0, v1, p0, p1, v2}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p2, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iget-object p0, p0, Lkf0/g0;->c:Lsf0/a;

    .line 22
    .line 23
    invoke-static {p1, p0, v2}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

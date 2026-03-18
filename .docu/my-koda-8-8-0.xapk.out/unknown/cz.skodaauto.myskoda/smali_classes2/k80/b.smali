.class public final Lk80/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lj80/b;


# direct methods
.method public constructor <init>(Lj80/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk80/b;->a:Lj80/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lss0/j0;

    .line 2
    .line 3
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lk80/b;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Lk80/b;->a:Lj80/b;

    .line 2
    .line 3
    const-string p2, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 4
    .line 5
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p2, p0, Lj80/b;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v0, Lj80/a;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-direct {v0, p0, p1, v2, v1}, Lj80/a;-><init>(Lj80/b;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    new-instance p0, Lim0/b;

    .line 18
    .line 19
    const/16 p1, 0xd

    .line 20
    .line 21
    invoke-direct {p0, p1}, Lim0/b;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p2, v0, p0, v2}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

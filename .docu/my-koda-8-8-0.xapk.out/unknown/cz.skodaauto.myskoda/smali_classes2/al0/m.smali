.class public final Lal0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/y;

.field public final b:Lal0/p;

.field public final c:Lyy0/i;


# direct methods
.method public constructor <init>(Lwj0/k;Lal0/y;Lal0/p;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lal0/m;->a:Lal0/y;

    .line 5
    .line 6
    iput-object p3, p0, Lal0/m;->b:Lal0/p;

    .line 7
    .line 8
    invoke-virtual {p1}, Lwj0/k;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    check-cast p1, Lyy0/i;

    .line 13
    .line 14
    new-instance p2, La50/h;

    .line 15
    .line 16
    const/4 p3, 0x1

    .line 17
    invoke-direct {p2, p1, p3}, La50/h;-><init>(Lyy0/i;I)V

    .line 18
    .line 19
    .line 20
    new-instance p1, La00/a;

    .line 21
    .line 22
    const/16 p3, 0x12

    .line 23
    .line 24
    invoke-direct {p1, p3}, La00/a;-><init>(I)V

    .line 25
    .line 26
    .line 27
    new-instance p3, Lv2/k;

    .line 28
    .line 29
    const/16 v0, 0x12

    .line 30
    .line 31
    invoke-direct {p3, v0, p1}, Lv2/k;-><init>(ILay0/k;)V

    .line 32
    .line 33
    .line 34
    new-instance p1, Le71/e;

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    invoke-direct {p1, p3, p2, v0}, Le71/e;-><init>(Lay0/k;Lyy0/i;Lkotlin/coroutines/Continuation;)V

    .line 38
    .line 39
    .line 40
    new-instance p2, Lyy0/m1;

    .line 41
    .line 42
    invoke-direct {p2, p1}, Lyy0/m1;-><init>(Lay0/o;)V

    .line 43
    .line 44
    .line 45
    invoke-static {p2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    iput-object p1, p0, Lal0/m;->c:Lyy0/i;

    .line 50
    .line 51
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lal0/m;->a:Lal0/y;

    .line 2
    .line 3
    invoke-virtual {v0}, Lal0/y;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, La90/c;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x2

    .line 13
    invoke-direct {v1, v2, p0, v3}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

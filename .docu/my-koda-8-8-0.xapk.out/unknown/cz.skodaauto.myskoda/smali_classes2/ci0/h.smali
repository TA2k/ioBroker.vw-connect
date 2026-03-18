.class public final Lci0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lif0/f0;

.field public final b:Len0/s;

.field public final c:Lci0/d;

.field public final d:Lgb0/p;


# direct methods
.method public constructor <init>(Lif0/f0;Len0/s;Lci0/d;Lgb0/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lci0/h;->a:Lif0/f0;

    .line 5
    .line 6
    iput-object p2, p0, Lci0/h;->b:Len0/s;

    .line 7
    .line 8
    iput-object p3, p0, Lci0/h;->c:Lci0/d;

    .line 9
    .line 10
    iput-object p4, p0, Lci0/h;->d:Lgb0/p;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lci0/h;->a:Lif0/f0;

    .line 4
    .line 5
    iget-object p1, p1, Lif0/f0;->j:Lac/l;

    .line 6
    .line 7
    new-instance p2, La50/h;

    .line 8
    .line 9
    const/16 v0, 0x9

    .line 10
    .line 11
    invoke-direct {p2, p1, v0}, La50/h;-><init>(Lyy0/i;I)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lci0/h;->b:Len0/s;

    .line 15
    .line 16
    iget-object p1, p1, Len0/s;->i:Lac/l;

    .line 17
    .line 18
    new-instance v0, La50/h;

    .line 19
    .line 20
    const/16 v1, 0xa

    .line 21
    .line 22
    invoke-direct {v0, p1, v1}, La50/h;-><init>(Lyy0/i;I)V

    .line 23
    .line 24
    .line 25
    new-instance p1, Lal0/y0;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    const/4 v2, 0x2

    .line 29
    const/4 v3, 0x0

    .line 30
    invoke-direct {p1, v1, v3, v2}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    new-instance v1, Lbn0/f;

    .line 34
    .line 35
    const/4 v2, 0x5

    .line 36
    invoke-direct {v1, p2, v0, p1, v2}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 37
    .line 38
    .line 39
    new-instance p1, Lhg/q;

    .line 40
    .line 41
    const/16 p2, 0x10

    .line 42
    .line 43
    invoke-direct {p1, v1, p2}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 44
    .line 45
    .line 46
    iget-object p2, p0, Lci0/h;->d:Lgb0/p;

    .line 47
    .line 48
    iget-object p2, p2, Lgb0/p;->c:Lez0/c;

    .line 49
    .line 50
    new-instance v0, La71/u;

    .line 51
    .line 52
    const/16 v1, 0x1c

    .line 53
    .line 54
    invoke-direct {v0, p0, v1}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 55
    .line 56
    .line 57
    new-instance v1, La90/s;

    .line 58
    .line 59
    const/4 v2, 0x4

    .line 60
    invoke-direct {v1, p0, v3, v2}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 61
    .line 62
    .line 63
    invoke-static {p1, p2, v0, v1}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0
.end method

.class public final Lci0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lai0/a;

.field public final b:Lif0/f0;

.field public final c:Len0/s;


# direct methods
.method public constructor <init>(Lai0/a;Lif0/f0;Len0/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lci0/d;->a:Lai0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lci0/d;->b:Lif0/f0;

    .line 7
    .line 8
    iput-object p3, p0, Lci0/d;->c:Len0/s;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lci0/d;->a:Lai0/a;

    .line 4
    .line 5
    iget-object p2, p1, Lai0/a;->a:Lxl0/f;

    .line 6
    .line 7
    new-instance v0, La90/s;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {v0, p1, v2, v1}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    new-instance p1, La00/a;

    .line 15
    .line 16
    const/16 v1, 0xf

    .line 17
    .line 18
    invoke-direct {p1, v1}, La00/a;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p2, v0, p1, v2}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance p2, Lci0/c;

    .line 26
    .line 27
    invoke-direct {p2, p0, v2}, Lci0/c;-><init>(Lci0/d;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    new-instance p0, Lne0/n;

    .line 31
    .line 32
    const/4 v0, 0x5

    .line 33
    invoke-direct {p0, p1, p2, v0}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 34
    .line 35
    .line 36
    return-object p0
.end method
